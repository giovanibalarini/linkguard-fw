package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

// Registro de conversa por host (#115, primeira fase): "com quem esse host
// falou na última janela".
//
// O QUE ISTO RESPONDE, E O QUE NÃO RESPONDE. A contabilidade da #112
// (accounting.go) sabe QUANTO cada host da LAN trafegou; ela não sabe COM QUEM,
// porque a chave dos sets dela tem uma dimensão só — o endereço do host. Aqui a
// chave é a tupla `origem . destino . porta`, e é isso que faz a pergunta do
// título da issue ter resposta.
//
// O que esta fase NÃO sabe, e a tela é obrigada a dizer: não tem duração de
// fluxo, não tem por qual WAN o fluxo saiu, não conta ICMP nem IPv6 (a chave é
// ipv4_addr; pacote IPv6 atravessa a chain sem casar com nada), e mostra a
// medição como CHEIA quando o set bateu o teto. Duração e WAN de saída só saem
// do evento de destruição do conntrack, que é outro caminho e outro custo.
//
// ─── POR QUE UMA TABELA PRÓPRIA, E POR QUE NÃO JUNTAR COM A DO FIREWALL ───
//
// Esta é a decisão que quem vier depois vai querer "simplificar". Não junte.
//
// Service.Persist (service.go) executa um `nft list table` da tabela do
// firewall e grava o dump INTEIRO — elementos e contadores inclusive — em
// /etc/nftables.conf, que é o arquivo que o nftables.service do systemd
// recarrega no BOOT, antes de o LinkGuard subir. Duas consequências, as duas
// ruins, se o set de fluxos morasse dentro da tabela do firewall:
//
//   - o arquivo de boot cresceria com o tráfego da rede. Milhares de tuplas com
//     contador viram megabytes de script que o systemd replaya na subida. Se
//     esse replay demorar ou falhar, a caixa volta sem firewall ou com o ruleset
//     velho — e SetPersistGuard já documenta que nesse intervalo o operador fica
//     sem SSH e sem painel, sem conserto remoto (incidente de 2026-07-24, boot
//     travado 50+ min);
//   - as tuplas RESSUSCITARIAM no boot. O registro passaria a afirmar que o host
//     falou com um destino às 3h — quando aquilo foi restaurado de um arquivo
//     escrito dias atrás. É a mesma armadilha que EnsureDomainStructures esvazia
//     à mão no boot, pelo mesmo motivo.
//
// Persist NOMEIA a tabela que ele dumpa. Uma tabela irmã fica fora por
// construção — não por disciplina de quem chama, que é o tipo de garantia que
// este projeto já viu falhar. E perder o set no reboot é o comportamento CERTO
// para uma janela rolante de uma hora: o que o registro afirma é "na última
// hora", e depois de um reboot não há última hora nenhuma para afirmar.
//
// ─── POR QUE CHAIN PRÓPRIA, DEPOIS DA FILTRAGEM ───
//
// Mesmo motivo da chain de contabilidade e mesmo perigo que survival.go
// documenta: regra de contabilidade dentro das chains de filtro entra ACIMA dos
// jumps dos grupos e afrouxa o firewall de quem já o usa. Aqui a chain é base
// chain própria, policy accept, prioridade DEPOIS da filtragem — então ela
// conta o que REALMENTE passou, e um destino bloqueado por regra de filtro nunca
// aparece no set.
//
// ─── POR QUE ESCOPADO POR INTERFACE ───
//
// A regra casa `iifname !=` a lista de WANs, igual à contabilidade: sem esse
// escopo, o tráfego de ENTRADA criaria uma tupla para cada endereço da internet
// que responde, e o set encheria em minutos. Escopando pelo que não é WAN, a
// origem é sempre um endereço local.
const (
	// FlowsTable é a tabela SEPARADA da do firewall. Ver o bloco acima antes
	// de mover qualquer coisa daqui para a tabela do firewall.
	FlowsTable = "linkguard_flows"
	// FlowsChain é a base chain que alimenta o set.
	FlowsChain = "flows"
	// FlowsSet guarda a tupla origem . destino . porta com contador.
	FlowsSet = "flows"

	// flowsChainSpec põe a chain depois da filtragem e depois da contabilidade
	// da #112 (filter + 10), para as duas nunca disputarem ordem entre si.
	flowsChainSpec = "{ type filter hook forward priority filter + 15; policy accept; }"
)

// Limites da janela e do teto. Eles são o contrato entre a tela (que pede em
// minutos) e o kernel (que cobra memória por elemento).
const (
	// FlowsJanelaPadrao é a hora do "com quem esse host falou na última hora".
	FlowsJanelaPadrao = 60
	// FlowsJanelaMinima evita uma janela tão curta que a tela fique vazia entre
	// duas leituras do painel.
	FlowsJanelaMinima = 5
	// FlowsJanelaMaxima é o limite superior. Não é arbitrário: retenção de
	// quem-falou-com-quem é dado pessoal na mão do cliente, e uma janela de
	// semanas transforma um diagnóstico em arquivo de vigilância.
	FlowsJanelaMaxima = 1440

	// FlowsTetoPadrao é conservador de propósito. O tamanho do set é o teto
	// REAL de memória de kernel: cada elemento carrega chave, contador e
	// timeout, e a appliance de referência tem 2 GB.
	FlowsTetoPadrao = 8192
	// FlowsTetoMinimo mantém a medição útil mesmo no valor mais baixo.
	FlowsTetoMinimo = 1024
	// FlowsTetoMaximo é o limite superior aceito. Ver o comentário do padrão.
	FlowsTetoMaximo = 32768
)

// FlowsConfig é o que o admin escolhe: se registra, por quanto tempo e até
// quantas tuplas.
//
// DESLIGADO É O PADRÃO, e isso é decisão de produto, não preguiça. Ligar isto
// numa caixa já instalada acrescenta uma base chain no hook forward — por onde
// passa TODO o tráfego da LAN — e começa a registrar quem falou com quem sem
// ninguém ter pedido. As duas coisas têm de ser escolha explícita: a primeira
// porque toca o caminho de pacote de uma rede em produção, a segunda porque o
// registro é dado pessoal do cliente.
type FlowsConfig struct {
	Ligado        bool `json:"ligado"`
	JanelaMinutos int  `json:"janela_minutos"`
	Teto          int  `json:"teto"`
}

// NormalizeFlowsConfig põe a configuração dentro dos limites.
//
// Existe separada e pura porque é ela que impede um valor do banco de virar
// spec de set: um tamanho zero vindo de uma linha de settings escrita à mão (ou
// de um JSON de uma versão futura com campo faltando) criaria um set que não
// guarda nada, e a tela mostraria "ninguém falou com ninguém" para uma rede
// inteira em atividade. Zero e negativo caem no PADRÃO, não no mínimo: valor
// ausente é "o admin não escolheu", e o que ele não escolheu é o padrão.
func NormalizeFlowsConfig(c FlowsConfig) FlowsConfig {
	if c.JanelaMinutos <= 0 {
		c.JanelaMinutos = FlowsJanelaPadrao
	}
	if c.JanelaMinutos < FlowsJanelaMinima {
		c.JanelaMinutos = FlowsJanelaMinima
	}
	if c.JanelaMinutos > FlowsJanelaMaxima {
		c.JanelaMinutos = FlowsJanelaMaxima
	}
	if c.Teto <= 0 {
		c.Teto = FlowsTetoPadrao
	}
	if c.Teto < FlowsTetoMinimo {
		c.Teto = FlowsTetoMinimo
	}
	if c.Teto > FlowsTetoMaximo {
		c.Teto = FlowsTetoMaximo
	}
	return c
}

// flowsSetSpec monta a definição do set a partir da configuração já
// normalizada. O timeout sai em MINUTOS, que é a unidade em que o admin
// escolhe — nada de converter para uma forma que o nft depois imprima diferente
// do que foi pedido.
func flowsSetSpec(c FlowsConfig) string {
	c = NormalizeFlowsConfig(c)
	return fmt.Sprintf(
		"{ type ipv4_addr . ipv4_addr . inet_service; size %d; flags dynamic,timeout; timeout %dm; counter; }",
		c.Teto, c.JanelaMinutos)
}

// flowsChainRules é a definição canônica da chain — uma regra só, no mesmo
// espírito de acctChainRules.
//
// O "meta l4proto" é obrigatório antes de "th dport": sem ele o nft não
// sabe de qual cabeçalho tirar a porta, e a regra é recusada. É também o que
// deixa ICMP de fora — uma das quatro coisas que a tela precisa dizer que não
// sabe.
func flowsChainRules(wanIfaces []string) [][]string {
	quoted := make([]string, len(wanIfaces))
	for i, iface := range wanIfaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	set := "{ " + strings.Join(quoted, ", ") + " }"
	return [][]string{
		{"iifname", "!=", set, "meta", "l4proto", "{", "tcp,", "udp", "}",
			"update", "@" + FlowsSet, "{", "ip", "saddr", ".", "ip", "daddr", ".", "th", "dport", "}"},
	}
}

// EnsureFlows cria a tabela, o set e a chain do registro de conversa e
// reconstrói a regra a partir da definição canônica — em todo boot e a cada
// mudança de link, pelo mesmo motivo de EnsureAccounting: EnsureTable é no-op
// em máquina já provisionada, então sem isto uma instalação existente nunca
// ganharia a chain.
//
// NÃO CHAMA Persist, E ISSO É O PONTO DA FEATURE INTEIRA. Ver o bloco no topo
// do arquivo: o que este código escreve no kernel não pode acabar no
// /etc/nftables.conf. O flows_test.go prende isso com um teste que falha se
// qualquer comando emitido aqui nomear a tabela do firewall.
//
// Recriar o set com uma configuração nova NÃO acontece aqui: o "add set" é
// idempotente e ignora a spec quando o set já existe, então mudar janela ou
// teto exige derrubar a tabela antes (é o que ApplyFlowsConfig faz, em
// internal/hostflows). Sem isso a tela mostraria a janela nova enquanto o kernel
// continua com a velha — e é por isso que a leitura reporta a janela e o teto
// que o KERNEL diz ter, não os do banco.
func (s *Service) EnsureFlows(ctx context.Context, wanInterfaces []string, cfg FlowsConfig) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)
	if len(ifaces) == 0 {
		// Sem saber quais interfaces são WAN não há como distinguir host local
		// de endereço da internet, e registrar tudo encheria o set com o
		// tráfego de entrada. Mesma decisão de EnsureAccounting diante de fonte
		// vazia: não agir é mais seguro do que agir errado.
		slog.Warn("registro de conversa: nenhuma interface WAN configurada; a chain não foi reconciliada",
			"solicitado", wanInterfaces)
		return nil
	}

	if out, err := s.exec.Execute(ctx, "nft", "add", "table", Family, FlowsTable); err != nil {
		return fmt.Errorf("criar tabela %s: %w (%s)", FlowsTable, err, strings.TrimSpace(out))
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "set", Family, FlowsTable, FlowsSet, flowsSetSpec(cfg)); err != nil {
		return fmt.Errorf("criar set %s: %w (%s)", FlowsSet, err, strings.TrimSpace(out))
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, FlowsTable, FlowsChain, flowsChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", FlowsChain, err, strings.TrimSpace(out))
	}
	if err := s.rebuildChainIn(ctx, FlowsTable, FlowsChain, flowsChainRules(ifaces)); err != nil {
		return err
	}
	norm := NormalizeFlowsConfig(cfg)
	slog.Info("registro de conversa reconciliado", "wans", ifaces,
		"janela_minutos", norm.JanelaMinutos, "teto", norm.Teto)
	return nil
}

// DisableFlows derruba a tabela inteira — chain, set e tuplas.
//
// Derrubar a TABELA, e não só esvaziar o set, é o que faz o desligamento ser
// desligamento: some a base chain do hook forward, some o custo por pacote da
// rede inteira, e não sobra estrutura para alguém achar que o registro continua
// ligado. E some o dado — que é exatamente o que o admin pediu ao desligar um
// registro de quem falou com quem.
//
// Tabela ausente é SUCESSO. O caminho normal de uma caixa com a feature
// desligada é justamente esse: reconciliar no boot manda apagar o que nunca
// existiu, e transformar isso em erro encheria o journal de falha que não houve.
func (s *Service) DisableFlows(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	out, err := s.exec.Execute(ctx, "nft", "delete", "table", Family, FlowsTable)
	if err != nil && !tabelaAusente(out, err) {
		return fmt.Errorf("remover tabela %s: %w (%s)", FlowsTable, err, strings.TrimSpace(out))
	}
	return nil
}

// tabelaAusente reconhece a recusa do nft para objeto inexistente. A mensagem é
// procurada na saída E no erro porque o Executor devolve o stderr num ou noutro
// conforme o caminho.
func tabelaAusente(out string, err error) bool {
	texto := out
	if err != nil {
		texto += " " + err.Error()
	}
	texto = strings.ToLower(texto)
	return strings.Contains(texto, "no such file or directory") ||
		strings.Contains(texto, "does not exist")
}

// Flow é uma conversa observada: quem, com quem, em que porta, e quanto passou.
type Flow struct {
	Origem  string `json:"origem"`
	Destino string `json:"destino"`
	Porta   uint16 `json:"porta"`
	Pacotes uint64 `json:"pacotes"`
	Bytes   uint64 `json:"bytes"`
}

// FlowSnapshot é o set inteiro mais o que a tela precisa dizer SOBRE ele.
//
// Janela e teto vêm do KERNEL, não do banco. A diferença importa: o admin pode
// ter salvo uma janela nova sem que a tabela tenha sido recriada, e nesse
// intervalo a tela estaria afirmando "última hora" sobre um set de 15
// minutos. O que vale é o que o kernel está de fato aplicando.
type FlowSnapshot struct {
	Fluxos        []Flow `json:"fluxos"`
	JanelaMinutos int    `json:"janela_minutos"`
	Teto          int    `json:"teto"`
	// Cheio diz que o set bateu o teto. Sem isto, uma conversa ausente parece
	// "não aconteceu" quando pode ser "aconteceu e não coube" — a mesma
	// honestidade que o Estado().Cheio do mapa de domínios já entrega.
	Cheio bool `json:"cheio"`
}

// A saída de referência é a do nft 1.1.3 (Debian 13), a mesma versão da VM de
// validação e da máquina de produção. O formato é o contrato de que esta
// leitura depende.
var (
	// reFlowElement casa o elemento na forma que o nft imprime:
	// "192.168.3.50 . 142.250.219.14 . 443 counter packets 12 bytes 3456
	// expires 59m58s". Os espaços em volta dos pontos são frouxos porque o
	// nft quebra a linha entre elementos e indenta a continuação.
	//
	// A porta sai NUMÉRICA porque a tradução para nome de serviço no nft é
	// opt-in (a flag -S). Se alguém acrescentar essa flag na leitura, esta
	// regex para de casar e a tela fica vazia — não acrescente.
	reFlowElement = regexp.MustCompile(
		`(\d{1,3}(?:\.\d{1,3}){3})\s*\.\s*(\d{1,3}(?:\.\d{1,3}){3})\s*\.\s*(\d{1,5}) counter packets (\d+) bytes (\d+)`)
	// reFlowSize e reFlowTimeout leem a DECLARAÇÃO do set, e por isso são
	// ancoradas em linha inteira: a palavra timeout também aparece dentro da
	// lista de flags, e casar com aquela ocorrência devolveria janela vazia.
	reFlowSize    = regexp.MustCompile(`(?m)^\s*size (\d+)\s*$`)
	reFlowTimeout = regexp.MustCompile(`(?m)^\s*timeout (\S+)\s*$`)
)

// Flows lê o set e devolve as conversas da janela.
//
// Erro é propagado em vez de virar lista vazia, pelo mesmo motivo de
// HostCounters: lista vazia é indistinguível de "ninguém falou com ninguém",
// e mostrar silêncio no lugar de falha é exatamente o defeito que este projeto
// não pode ter. Quem chama decide como dizer "não sei" ao admin.
func (s *Service) Flows(ctx context.Context) (FlowSnapshot, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, FlowsTable, FlowsSet)
	if err != nil {
		return FlowSnapshot{}, fmt.Errorf("ler set %s: %w", FlowsSet, err)
	}
	return parseFlowSet(out), nil
}

// parseFlowSet extrai as tuplas e a declaração de um listar-set do nft.
//
// Set sem a linha de elementos devolve lista vazia — que é a resposta certa
// logo depois do boot: a chain existe e ninguém falou ainda.
func parseFlowSet(out string) FlowSnapshot {
	snap := FlowSnapshot{Fluxos: []Flow{}}

	if m := reFlowSize.FindStringSubmatch(out); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			snap.Teto = n
		}
	}
	if m := reFlowTimeout.FindStringSubmatch(out); m != nil {
		snap.JanelaMinutos = minutosDeNft(m[1])
	}

	for _, m := range reFlowElement.FindAllStringSubmatch(out, -1) {
		porta, err := strconv.ParseUint(m[3], 10, 16)
		if err != nil {
			// Fora de 0-65535 não é porta: é uma linha que casou com a regex
			// por acidente. Descartar é melhor do que gravar zero e o painel
			// mostrar uma conversa que não existiu.
			continue
		}
		pkts, _ := strconv.ParseUint(m[4], 10, 64)
		bytes, _ := strconv.ParseUint(m[5], 10, 64)
		snap.Fluxos = append(snap.Fluxos, Flow{
			Origem: m[1], Destino: m[2], Porta: uint16(porta),
			Pacotes: pkts, Bytes: bytes,
		})
	}

	// Cheio sai da contagem contra o teto DO KERNEL. Comparar com o teto do
	// banco mentiria justamente no caso que interessa: o admin baixou o teto, a
	// tabela ainda não foi recriada, e o set real já está recusando tupla nova
	// enquanto a tela diria que há folga.
	snap.Cheio = snap.Teto > 0 && len(snap.Fluxos) >= snap.Teto
	return snap
}

// minutosDeNft converte o timeout impresso pelo nft (1h, 15m, 1h30m, 1d) para
// minutos.
//
// Não usa time.ParseDuration porque o nft imprime a unidade de DIA, que aquela
// função recusa — e recusar justamente a unidade que o nosso teto máximo (1440
// min) produz deixaria a tela sem saber a janela na configuração mais longa.
// Segundos soltos sobem para um minuto cheio pelo mesmo motivo: zero na tela
// seria lido como "sem janela".
func minutosDeNft(v string) int {
	var total, num int
	temNumero := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			num = num*10 + int(r-'0')
			temNumero = true
		case r == 'd':
			total += num * 1440
			num, temNumero = 0, false
		case r == 'h':
			total += num * 60
			num, temNumero = 0, false
		case r == 'm':
			// Cuidado: ms é milissegundo, e ele nunca aparece na DECLARAÇÃO do
			// set (só no expires dos elementos). Tratar como minuto aqui é
			// correto para a linha que esta função recebe.
			total += num
			num, temNumero = 0, false
		case r == 's':
			if num > 0 {
				total++
			}
			num, temNumero = 0, false
		default:
			num, temNumero = 0, false
		}
	}
	if temNumero && total == 0 {
		// Valor sem unidade: é o que o nft imprime com -T (segundos crus).
		total = (num + 59) / 60
	}
	return total
}
