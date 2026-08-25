package monitoring

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/keaunbound"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Config drift watchers.
//
// Why this file exists: on 2026-08-10 a NIC rename left a WAN link pointing
// at an interface that no longer existed and the firewall's masquerade rule
// stranded on the old name. Every existing health check stayed green —
// `systemctl is-active nftables` was perfectly happy serving a stale rule —
// so the operator only found it by SSHing in. These checks close that blind
// spot: they compare what LinkGuard APPLIED against what the system
// actually LOOKS LIKE, which no other check in this package does.
//
// All three are read-only and cheap enough for the 30s collector tick.

// defaultResolvConfPath is the file checkDNSResolver reads; overridden in tests.
const defaultResolvConfPath = "/etc/resolv.conf"

// BootPersistSource é o que checkBootPersist precisa saber sobre o arquivo de
// boot do firewall. Interface, e não *nftables.Service direto, para o teste
// poder montar as combinações (nunca tentou / falhou / gravou e o arquivo
// sumiu) sem um nft de verdade — e para deixar explícito que o vigia só LÊ.
//
// Implementado por *nftables.Service (PersistState/PersistPath).
type BootPersistSource interface {
	PersistState() nftables.PersistState
	PersistPath() string
}

// SetBootPersistSource liga o vigia ao serviço de nftables. Sem ela o item
// "Regras no próximo boot" simplesmente não existe — um Collector sem fonte
// não tem como saber nada sobre o arquivo de boot, e inventar um "ok" seria o
// dado falso que este projeto não aceita. Ligar isto é obrigação do main
// (guardado por TestMainWiresTheBootPersistSource).
func (c *Collector) SetBootPersistSource(src BootPersistSource) { c.bootPersist = src }

// checkBootPersist responde a pergunta que o §10 da validação em VM deixou sem
// resposta na tela: "o que está valendo agora volta depois de um reboot?".
//
// É item de saúde, e não só alerta, porque é uma CONDIÇÃO contínua e não um
// evento: enquanto o arquivo de boot não refletir o firewall vivo o operador
// tem que ver, e quando voltar a ser gravado tem que sumir sozinho. Um alerta
// isolado seria criado uma vez e o operador o resolveria sem a condição ter
// mudado.
//
// COMO O ITEM APAGA, MEDIDO (validação em VM de 2026-08-13, cenário 5): o
// operador devolve a permissão de escrita e REINICIA O SERVIÇO
// (`systemctl restart linkguard-fw`). Aplicar outra regra não apaga o item — a
// unidade tem `ProtectSystem=strict` com `ReadWritePaths=-/etc/nftables.conf`, e
// um caminho ausente no start do serviço não entra gravável no namespace, de
// modo que o processo já rodando continua enxergando o arquivo como somente
// leitura por mais mutações que venham. Só um start novo remonta o namespace.
// Por isso o rótulo do item carrega essa instrução na tela (web/src/components/
// SystemHealth.tsx): a primeira coisa que o operador tentaria é justamente a que
// não funciona, e o silêncio o levaria a concluir que o produto está quebrado.
//
// As duas perguntas que ele faz, ambas baratas e ambas honestas:
//
//  1. a última tentativa REAL de gravar falhou? (nftables.PersistState — sem
//     nenhum comando novo: é a memória do que já aconteceu);
//  2. o arquivo simplesmente não está lá? (um os.Stat por ciclo).
//
// O que ele deliberadamente NÃO faz é comparar o ruleset vivo com o conteúdo
// do arquivo a cada ciclo: isso custaria um `nft list table` por tique para
// responder a uma pergunta que a memória do Persist já responde. Também não
// olha a IDADE do arquivo — uma máquina saudável que não muda regra há meses
// tem um arquivo antigo e correto, e transformar isso em item vermelho seria
// exatamente o falso positivo que treina o operador a ignorar a tela.
//
// Três silêncios de propósito, cada um por não haver veredito a dar:
//
//   - sem fonte ligada (binário sem nft, testes): nada a dizer;
//   - Persist nunca chegou a tentar gravar (dry-run, ou o boot ainda não
//     reconciliou): "ainda não sei" nunca vira "está tudo bem";
//   - o os.Stat falhou por algo que não é "não existe" (permissão no diretório,
//     IO): não conseguir olhar não é o mesmo que o arquivo estar errado. Mesma
//     escolha de todo early-return deste arquivo.
func (c *Collector) checkBootPersist() {
	if c.bootPersist == nil {
		return
	}
	st := c.bootPersist.PersistState()
	if !st.Attempted {
		return
	}
	path := c.bootPersist.PersistPath()

	var reason string
	if !st.OK {
		reason = fmt.Sprintf("a última gravação de %s falhou: %s", path, st.Err)
	} else if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return // não consegui olhar; sem veredito neste ciclo
		}
		reason = fmt.Sprintf("%s foi gravado com sucesso, mas não está mais lá", path)
	}

	tr := c.observe("firewall:bootpersist", reason == "", c.nowFn())
	c.ensureMeta("firewall:bootpersist", "firewall-boot-persist", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.FirewallBootPersistFailed(reason)
	case transUp:
		_ = c.alertSvc.FirewallBootPersistOK()
	}
}

// enabledWANInterfaces returns the interfaces of every enabled WAN link —
// the source of truth both checkWANInterfaces and checkFirewallNAT compare
// reality against.
func (c *Collector) enabledWANInterfaces() []string {
	ls, err := c.db.GetLinks()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			out = append(out, l.Interface)
		}
	}
	return out
}

// interfaceExists reports whether the kernel currently has this interface.
// Uses /sys/class/net directly (no exec) — a rename shows up immediately.
func interfaceExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// checkWANInterfaces verifies every enabled WAN link points at an interface
// the kernel actually has. This is the watcher that would have caught the
// 2026-08-10 incident the moment the box came up.
func (c *Collector) checkWANInterfaces() {
	ls, err := c.db.GetLinks()
	if err != nil {
		return // cannot evaluate this tick; don't invent a verdict
	}
	exists := c.ifaceExists
	if exists == nil {
		exists = interfaceExists
	}

	var missing []string
	for _, l := range ls {
		if !l.Enabled || l.Interface == "" {
			continue
		}
		if !exists(l.Interface) {
			missing = append(missing, fmt.Sprintf("%s -> %s", l.Name, l.Interface))
		}
	}

	tr := c.observe("wan:interface", len(missing) == 0, c.nowFn())
	c.ensureMeta("wan:interface", "wan-interface", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.WANInterfaceMissing(strings.Join(missing, ", "))
	case transUp:
		_ = c.alertSvc.WANInterfaceOK()
	}
}

// masqueradeRuleRe finds the line carrying the masquerade verdict inside
// `nft list chain` output (the ruleset ReconcileMasquerade writes always
// keeps `oifname { ... } masquerade` together on one line — see
// internal/nftables/reconcile.go).
var masqueradeRuleRe = regexp.MustCompile(`(?m)^.*\bmasquerade\b.*$`)

// quotedInterfaceRe pulls interface names out of an nft `{ "a", "b" }` set
// (also matches the unbracketed single-interface form nft can print).
var quotedInterfaceRe = regexp.MustCompile(`"([^"]+)"`)

// parseMasqueradeInterfaces extracts the interface names referenced by the
// masquerade rule in `nft list chain` output. found is false when the chain
// has no masquerade rule at all (NAT is off), as distinct from an empty
// interface set.
func parseMasqueradeInterfaces(chainText string) (ifaces []string, found bool) {
	line := masqueradeRuleRe.FindString(chainText)
	if line == "" {
		return nil, false
	}
	for _, m := range quotedInterfaceRe.FindAllStringSubmatch(line, -1) {
		ifaces = append(ifaces, m[1])
	}
	return ifaces, true
}

// checkFirewallNAT verifies the LIVE masquerade rule references EXACTLY the
// configured WAN interfaces, and that every interface it references exists
// in the kernel. `systemctl is-active nftables` cannot see any of this: the
// service is happily active while the rule inside it is stale.
//
// Replays the 2026-08-10 incident directly: the DB still said enp4s0,
// reconciliation faithfully wrote `oifname { "enp4s0" }`, NAT was down — and
// a check that only tests "every configured WAN appears somewhere in the
// rule" sees "enp4s0" present and reports green on a tile literally named
// "Regra de NAT", during the exact scenario it exists to catch. Comparing
// both directions (configured ⊆ rule AND rule ⊆ configured) also catches a
// stale extra interface left behind by a partial reconcile, and checking
// existence catches the rule referencing an interface the kernel no longer
// has at all.
func (c *Collector) checkFirewallNAT() {
	wans := c.enabledWANInterfaces()
	if len(wans) == 0 {
		return // nothing configured to verify against
	}
	out, err := c.exec.ExecuteRead(context.Background(), "nft", "list", "chain",
		nftables.Family, nftables.Table, "postrouting")
	if err != nil {
		return // table/chain unreadable this tick — no verdict rather than a false one
	}

	exists := c.ifaceExists
	if exists == nil {
		exists = interfaceExists
	}

	ruleIfaces, found := parseMasqueradeInterfaces(out)
	if !found {
		// No masquerade rule at all is a problem state (NAT is off), not an
		// unknown — we DID read the chain successfully.
		tr := c.observe("firewall:nat", false, c.nowFn())
		c.ensureMeta("firewall:nat", "firewall-nat", "resource")
		if tr == transDown {
			_ = c.alertSvc.FirewallNATDrift("nenhuma regra de masquerade encontrada na chain postrouting (NAT desligado)")
		}
		return
	}

	configured := make(map[string]bool, len(wans))
	for _, w := range wans {
		configured[w] = true
	}
	inRule := make(map[string]bool, len(ruleIfaces))
	for _, i := range ruleIfaces {
		inRule[i] = true
	}

	var missing, stale, absentFromKernel []string
	for _, w := range wans {
		if !inRule[w] {
			missing = append(missing, w)
		}
	}
	for _, i := range ruleIfaces {
		if !configured[i] {
			stale = append(stale, i)
		}
		if !exists(i) {
			absentFromKernel = append(absentFromKernel, i)
		}
	}

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "WAN configurada mas ausente da regra: "+strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		parts = append(parts, "interface na regra que não é uma WAN configurada: "+strings.Join(stale, ", "))
	}
	if len(absentFromKernel) > 0 {
		parts = append(parts, "interface na regra que não existe no kernel: "+strings.Join(absentFromKernel, ", "))
	}

	tr := c.observe("firewall:nat", len(parts) == 0, c.nowFn())
	c.ensureMeta("firewall:nat", "firewall-nat", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.FirewallNATDrift(strings.Join(parts, "; "))
	case transUp:
		_ = c.alertSvc.FirewallNATOK()
	}
}

// dnsProbeUnavailableError marks a failure to even attempt the probe (e.g.
// the UDP socket could not be created) as distinct from a verdict about the
// resolver's health. checkDNSResolver treats this the same as its other
// early-returns in this file: no verdict this tick, rather than inventing
// one. A timeout or an explicit REFUSED/SERVFAIL IS a verdict (the resolver
// is unhealthy) and must not be wrapped in this type.
type dnsProbeUnavailableError struct{ err error }

func (e *dnsProbeUnavailableError) Error() string { return e.err.Error() }
func (e *dnsProbeUnavailableError) Unwrap() error { return e.err }

// dnsProbeTimeout bounds each probe attempt so a single stuck tick can't
// stall the collector loop.
const dnsProbeTimeout = 2 * time.Second

// probeLocalResolver sends a real "localhost." (type A) query to
// 127.0.0.1:53 over UDP and returns nil if the resolver answers NOERROR or
// NXDOMAIN — i.e. it is actually answering queries — or a descriptive error
// otherwise (REFUSED, SERVFAIL, a malformed reply, or a timeout).
//
// "localhost." is a deliberate choice: unbound answers it from its built-in
// local zone, with no recursion and no DNSSEC, so this probe stays
// meaningful even with every WAN down (that outage is the link monitor's
// job, not this check's) while still exercising unbound's access-control
// path — exactly what silently REFUSED the box's own queries on
// 2026-08-11.
//
// This talks DNS directly over a UDP socket instead of net.Resolver /
// LookupHost: Go's resolver can satisfy "localhost" from /etc/hosts without
// ever touching port 53, which would make the probe prove nothing about
// unbound at all.
func probeLocalResolver() error {
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", dnsProbeTimeout)
	if err != nil {
		return &dnsProbeUnavailableError{err}
	}
	defer conn.Close()

	query := buildDNSQuery(0xC0DE, "localhost.", 1) // qtype 1 = A
	if err := conn.SetDeadline(time.Now().Add(dnsProbeTimeout)); err != nil {
		return &dnsProbeUnavailableError{err}
	}
	if _, err := conn.Write(query); err != nil {
		return &dnsProbeUnavailableError{err}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return errors.New("timeout")
		}
		return &dnsProbeUnavailableError{err}
	}

	rcode, ok := dnsResponseRcode(buf[:n], query)
	if !ok {
		return errors.New("resposta DNS malformada")
	}
	switch rcode {
	case 0, 3: // NOERROR, NXDOMAIN: the resolver is answering.
		return nil
	default:
		return errors.New(dnsRcodeName(rcode))
	}
}

// buildDNSQuery builds a minimal DNS query message: a 12-byte header (one
// question, recursion desired) followed by QNAME/QTYPE/QCLASS.
func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT=1

	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root label

	qtypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBytes, qtype)
	msg = append(msg, qtypeBytes...)
	msg = append(msg, 0, 1) // QCLASS=IN
	return msg
}

// dnsResponseRcode extracts the response code from a DNS reply after
// verifying it is actually a response to our query (matching transaction ID,
// QR bit set) — anything else is a malformed/unrelated reply, not a verdict.
func dnsResponseRcode(resp, query []byte) (rcode int, ok bool) {
	if len(resp) < 12 || len(query) < 12 {
		return 0, false
	}
	if resp[0] != query[0] || resp[1] != query[1] { // transaction ID
		return 0, false
	}
	if resp[2]&0x80 == 0 { // QR bit: must be a response, not a query
		return 0, false
	}
	return int(resp[3] & 0x0F), true
}

// dnsRcodeName renders a DNS response code the way an operator recognizes it.
func dnsRcodeName(rcode int) string {
	switch rcode {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("rcode=%d", rcode)
	}
}

// lerResolvConf lê o resolv.conf e separa o que ele aponta: o resolver local
// (127.0.0.1/::1) e os externos. Extraída porque DUAS checagens precisam da
// mesma leitura — checkDNSResolver, que pergunta o que está escrito ali, e
// checkCaminhoNSS, que pergunta se alguém lê aquele arquivo. Duas cópias da
// mesma varredura acabariam divergindo, e a divergência apareceria como dois
// vereditos contraditórios sobre a mesma máquina.
func (c *Collector) lerResolvConf() (local bool, external []string, err error) {
	path := c.resolvConfPath
	if path == "" {
		path = defaultResolvConfPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, nil, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		addr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		if addr == "127.0.0.1" || addr == "::1" {
			local = true
		} else if addr != "" {
			external = append(external, addr)
		}
	}
	return local, external, nil
}

// checkDNSResolver verifies the box actually resolves through its own
// unbound rather than the ISP's servers. Two independent halves, both
// required for a healthy verdict:
//
//  1. resolv.conf points at the local resolver (the config drift originally
//     found in production, caused by dhclient rewriting resolv.conf on
//     lease renewal).
//  2. the local resolver actually answers queries (added after the
//     2026-08-11 incident: resolv.conf pointed at 127.0.0.1 the whole time
//     while a blanket masquerade rule rewrote the source address of the
//     box's own loopback DNS queries, so unbound correctly REFUSED them —
//     the config-only check stayed green through the entire outage).
func (c *Collector) checkDNSResolver() {
	local, external, err := c.lerResolvConf()
	if err != nil {
		return // unreadable this tick; no verdict
	}
	configOK := local && len(external) == 0

	probe := c.dnsProbe
	if probe == nil {
		probe = probeLocalResolver
	}
	probeErr := probe()
	var unavailable *dnsProbeUnavailableError
	if errors.As(probeErr, &unavailable) {
		// The probe itself could not even run this tick (e.g. socket
		// creation failed) — that is not a verdict about the resolver, so
		// don't invent one. Consistent with every other early-return in
		// this file.
		return
	}

	var reasons []string
	if !configOK {
		if len(external) > 0 {
			reasons = append(reasons, "resolv.conf aponta para "+strings.Join(external, ", "))
		} else {
			reasons = append(reasons, "resolv.conf não aponta para o resolvedor local (127.0.0.1)")
		}
	}
	if probeErr != nil {
		reasons = append(reasons, fmt.Sprintf("o resolvedor local não respondeu (%s)", probeErr))
	}

	tr := c.observe("dns:resolver", configOK && probeErr == nil, c.nowFn())
	c.ensureMeta("dns:resolver", "dns-resolver", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.DNSResolverDrift(strings.Join(reasons, "; "))
	case transUp:
		_ = c.alertSvc.DNSResolverOK()
	}
}

// checkCaminhoNSS responde a pergunta que o resolv.conf sozinho não responde: a
// resolução de nome desta máquina CHEGA até o resolv.conf? (issue #195)
//
// Ela só chega se a busca do NSS alcançar o módulo `dns`. Numa instalação nova
// de Debian 13 o systemd-resolved vem ativo e o nsswitch.conf vem com
// `hosts: files myhostname resolve [!UNAVAIL=return] dns` — a linha encerra a
// busca no `resolve` e o resolv.conf fica correto e irrelevante. Foi medido na
// VM de validação: o getent não incrementava o contador do unbound, e é por
// isso que a bateria T da suíte teve de passar a consultar 127.0.0.1:53 direto.
//
// POR QUE AQUI, E NÃO NO EnsureResolvConf DO BOOT (onde nasceu). Lá a checagem
// roda uma vez por processo, e um veredito que só se atualiza no reboot é a
// própria doença que a issue quer curar: o admin arruma a linha `hosts:` e o
// painel fica vermelho até o serviço reiniciar. Aqui ela é uma CONDIÇÃO
// contínua, medida a cada tique, com observe()/transDown/transUp como todo o
// resto deste arquivo — sobe sozinha e desce sozinha. De quebra, o
// ResolveStaleOnStartup passa a funcionar como projetado para este alerta: a
// premissa dele é que "o que continuar errado é reerguido no primeiro tique ou
// dois", e uma checagem de boot não cumpria isso.
//
// O que este código faz é MEDIR E DIZER. Ele não conserta: mexer no
// nsswitch.conf ou desligar o systemd-resolved é escrever em arquivo de sistema
// fora do escopo declarado do produto, e errar ali quebra a resolução de nome
// da caixa inteira. O conserto, quando existir, é botão com
// confirmar-ou-reverter — não efeito colateral de um vigia.
func (c *Collector) checkCaminhoNSS() {
	// Portão: só há o que afirmar sobre "o caminho até o resolver local" se o
	// resolv.conf estiver mesmo apontando para ele. Sem isso quem responde é o
	// checkDNSResolver logo acima (dns_resolver_drift), e abrir aqui também
	// seria dois vermelhos para uma causa só — com a agravante de a mensagem
	// deste afirmar que o resolv.conf aponta para o unbound, o que seria falso.
	// Não saber é o terceiro estado de sempre: nem abre, nem fecha.
	local, _, err := c.lerResolvConf()
	if err != nil || !local {
		return
	}

	path := c.nsswitchPath
	if path == "" {
		path = keaunbound.NsswitchPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return // unreadable this tick; no verdict
	}

	// O systemd-resolved é consultado por PREDICADO, e preguiçosamente: numa
	// linha `hosts: files dns` (a produção de hoje) nenhum módulo com ação de
	// corte aparece antes do dns, e nenhum systemctl é executado no tique.
	resolvedAtivo, perguntou := false, false
	caminho := keaunbound.AnalisarCaminhoNSS(string(raw), func(nome string) bool {
		if nome != keaunbound.ModuloResolved {
			return false
		}
		if !perguntou {
			resolvedAtivo, perguntou = c.systemdResolvedAtivo(), true
		}
		return !resolvedAtivo
	})

	// NSSIndeterminado é o caso em que não dá para dizer, e ele não mexe em
	// alerta nenhum — mesma regra do os.ReadFile acima e de todo early-return
	// deste arquivo. Dois arranjos caem aqui:
	//
	//   - arquivo malformado (colchete sem fechar): o parser parou no meio, e
	//     concluir "não tem dns" de um prefixo da linha é afirmar sobre a parte
	//     que não foi lida;
	//   - a busca só chega ao dns porque o `resolve` está com o daemon parado.
	//
	// O segundo é uma DECISÃO, não um descuido: `systemctl is-active` responde
	// sobre o processo agora, e o processo pode subir sem ninguém tocar neste
	// produto (basta o boot). Fechar o alerta por isso seria anunciar um
	// conserto que ninguém fez, e o alerta voltaria no reboot seguinte — o
	// vermelho piscante que ensina o operador a ignorar vermelho. A regra deste
	// vigia é simétrica: abrir exige certeza, fechar exige certeza.
	//
	// A alternativa considerada era somar `is-enabled` ao `is-active` e tratar
	// "habilitada mas parada" como corte. Ela fecha o alerta quando o admin faz
	// `disable --now`, e foi recusada porque afirmaria defeito a partir da
	// CONFIGURAÇÃO da unidade, não do comportamento dela — a mesma inferência
	// que esta issue existe para desfazer. O preço da escolha, e ele é real: com
	// o systemd-resolved apenas parado o painel não fica verde. O conserto que
	// este vigia reconhece é o duradouro — a linha `hosts:` deixar de encerrar a
	// busca antes do dns —, e não um daemon que volta no próximo boot.
	if caminho.Estado == keaunbound.NSSIndeterminado {
		slog.Debug("caminho de resolução: sem veredito neste tique",
			"nsswitch", path, "hosts", caminho.Hosts, "motivo", caminho.Motivo)
		return
	}

	tr := c.observe("dns:caminho", caminho.Estado == keaunbound.NSSAlcancaDNS, c.nowFn())
	c.ensureMeta("dns:caminho", "dns-caminho", "resource")
	switch tr {
	case transDown:
		detalhe := caminho.Motivo
		if caminho.Achou {
			detalhe += fmt.Sprintf(" (hosts: %s)", caminho.Hosts)
		}
		if perguntou && resolvedAtivo {
			detalhe += "; o systemd-resolved está ativo"
		}
		slog.Warn("o resolv.conf aponta para o resolver local (unbound), mas a resolução de nome desta máquina NÃO passa por ele",
			"nsswitch", path, "hosts", caminho.Hosts, "cortado_por", caminho.CortadoPor, "motivo", caminho.Motivo)
		// Duas frases, e não uma com um detalhe a mais: sem módulo `dns` na
		// linha a caixa não resolve nome externo NENHUM, e dizer ali que "a
		// caixa continua resolvendo nomes" manda o operador caçar um problema
		// silencioso enquanto o barulhento está na cara. Ver os tipos em
		// internal/alerts.
		if caminho.Estado == keaunbound.NSSSemModuloDNS {
			_ = c.alertSvc.ResolucaoSemModuloDNS(detalhe)
		} else {
			_ = c.alertSvc.CaminhoDNSForaDoLocal(detalhe)
		}
	case transUp:
		c.alertSvc.CaminhoDNSNoLocal()
	}
}

// systemdResolvedAtivo diz se o daemon do módulo NSS `resolve` está de pé
// AGORA. Um erro aqui (unidade inexistente, que é o normal numa caixa sem
// systemd-resolved) é resposta — "não está de pé" —, não falha.
func (c *Collector) systemdResolvedAtivo() bool {
	out, err := c.exec.ExecuteRead(context.Background(), "systemctl", "is-active", "systemd-resolved")
	return err == nil && strings.TrimSpace(out) == "active"
}
