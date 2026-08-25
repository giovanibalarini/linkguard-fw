package nftables

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Alvo de regra por DOMÍNIO (#123), primeira metade: as estruturas.
//
// O QUE ESTE ARQUIVO É E O QUE ELE NÃO É. Aqui moram as três estruturas do
// kernel que passam a receber os endereços que o nosso resolver entregou para
// um nome, e o comando que as alimenta. NENHUMA LINHA DE CASAMENTO VIVE AQUI:
// enquanto nada na forward nem na mark_hosts olhar para estas estruturas, elas
// podem encher e esvaziar sem mudar um pacote sequer. É de propósito, e é a
// ordem que o plano da issue pede — este pacote já se machucou três vezes
// mexendo em chain que decide tráfego, e a parte que não decide nada é a que
// pode ser mergeada primeiro.
//
// POR QUE TRÊS ESTRUTURAS E NÃO UMA POR DOMÍNIO. Um set por domínio
// multiplicaria por N a criação, a coleta de órfãos e o risco. A identidade
// "qual domínio ensinou este endereço" serve a RELATÓRIO, e relatório não
// precisa estar no kernel: ele vive no índice em memória, do lado do feeder.
//
// POR QUE `dom_blocked6` EXISTE DESDE O PRIMEIRO DIA. Sem ele, "barrado" numa
// máquina dual-stack é falso por padrão — o nome resolve para A e AAAA, o
// cliente prefere o AAAA, e o bloqueio que a tela promete não acontece. Já o
// DIRECIONAMENTO não tem par v6, e isso não é esquecimento: não existe política
// de rota v6 neste produto, e criar a estrutura sem quem a leia seria fingir.
const (
	// DomBlockedSet guarda os endereços IPv4 aprendidos de domínios barrados.
	DomBlockedSet = "dom_blocked"
	// DomBlockedSet6 é o mesmo para IPv6.
	DomBlockedSet6 = "dom_blocked6"
	// DomWanMap leva endereço IPv4 aprendido → marca da WAN escolhida.
	DomWanMap = "dom_wan"
)

// As declarações.
//
// Sem `dynamic`: quem escreve aqui é o userspace, e não uma regra do kernel —
// é a diferença para `abusers` e para os sets de contabilidade.
//
// Sem `interval`: DNS devolve endereço, não faixa. Ligar intervalo aqui abriria
// a porta para alguém achar que dá para listar um /24.
//
// `size` explícito porque set alimentado por DNS sem teto é vazamento de
// memória com nome bonito — e estourar precisa APARECER, não sumir.
const (
	domBlockedSpec  = "{ type ipv4_addr ; flags timeout ; timeout 1h ; size 8192 ; }"
	domBlocked6Spec = "{ type ipv6_addr ; flags timeout ; timeout 1h ; size 8192 ; }"
	domWanSpec      = "{ type ipv4_addr : mark ; flags timeout ; timeout 1h ; size 8192 ; }"
)

const (
	// DomTTLPiso é o prazo mínimo de um endereço aprendido.
	//
	// TTL de CDN é de trinta segundos. Um endereço que sai trinta segundos
	// depois da última resposta faz o bloqueio PISCAR enquanto o cliente ainda
	// está usando aquele endereço, guardado no cache dele.
	DomTTLPiso = 10 * time.Minute

	// DomTTLTeto é o prazo máximo, e vale igual para as duas capacidades.
	//
	// A tentação é dar teto folgado ao direcionamento, porque "errar a rota é
	// barato". Não é: com o EnsureSteerRouting nunca retirando a `ip rule`, um
	// link caído com o map cheio manda a rede inteira para uma tabela morta. O
	// teto do dano tem de ser o mesmo dos dois lados.
	DomTTLTeto = time.Hour
)

// EnsureDomainStructures cria as três estruturas, de forma idempotente.
//
// Existe pelo mesmo motivo de EnsureBlockedMACSet: `EnsureTable` é no-op em
// caixa já provisionada, então estrutura nova NUNCA aparece por upgrade se
// alguém não a criar explicitamente. Foi assim que o set de endereços físicos
// escapou para produção sem existir na caixa do cliente.
func (s *Service) EnsureDomainStructures(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	for _, e := range []struct {
		tipo, nome, spec string
	}{
		{"set", DomBlockedSet, domBlockedSpec},
		{"set", DomBlockedSet6, domBlocked6Spec},
		{"map", DomWanMap, domWanSpec},
	} {
		args := append([]string{"add", e.tipo, Family, Table, e.nome}, strings.Fields(e.spec)...)
		if out, err := s.exec.Execute(ctx, "nft", args...); err != nil {
			return fmt.Errorf("criar %s %s: %w (%s)", e.tipo, e.nome, err, out)
		}
	}
	return nil
}

// FlushDomainStructures esvazia as três.
//
// É chamada NO BOOT, incondicionalmente. O que estas estruturas guardam é
// cache do que o resolver respondeu, e cache que sobrevive ao reboot afirma
// sobre endereços o que ninguém mais confirmou — a mesma razão pela qual o mapa
// da #116 vive só em memória.
func (s *Service) FlushDomainStructures(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	var falhas []string
	for _, e := range []struct{ tipo, nome string }{
		{"set", DomBlockedSet},
		{"set", DomBlockedSet6},
		{"map", DomWanMap},
	} {
		if out, err := s.exec.Execute(ctx, "nft", "flush", e.tipo, Family, Table, e.nome); err != nil {
			falhas = append(falhas, fmt.Sprintf("%s %s: %v (%s)", e.tipo, e.nome, err, strings.TrimSpace(out)))
		}
	}
	if len(falhas) > 0 {
		return fmt.Errorf("esvaziar as estruturas de domínio: %s", strings.Join(falhas, "; "))
	}
	return nil
}

// FlushDomWan esvazia SÓ o map de direcionamento.
//
// Separado do resto porque tem um chamador próprio: quando o link para o qual
// os domínios estão sendo direcionados sai do ar, manter o map cheio manda o
// tráfego daqueles nomes para a tabela de um link morto. Barrar não tem esse
// problema — endereço barrado com o link fora continua barrado, e isso é o
// comportamento certo.
func (s *Service) FlushDomWan(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if out, err := s.exec.Execute(ctx, "nft", "flush", "map", Family, Table, DomWanMap); err != nil {
		return fmt.Errorf("esvaziar o map %s: %w (%s)", DomWanMap, err, out)
	}
	return nil
}

// Entrada é um endereço aprendido, com o prazo que ele merece.
type Entrada struct {
	Addr netip.Addr
	// Prazo já vem grampeado entre DomTTLPiso e DomTTLTeto pelo chamador.
	Prazo time.Duration
	// Marca só é lida quando a entrada vai para o map de direcionamento.
	Marca uint32
}

// Lote é o conjunto de mudanças de UMA rodada do feeder.
//
// Renovações vão nas duas listas: o endereço aparece em Remover E em Adicionar,
// e é isso que renova o prazo. Ver AplicarLote.
type Lote struct {
	// Remover são os endereços a apagar antes de (re)adicionar.
	RemoverBloq  []netip.Addr
	RemoverBloq6 []netip.Addr
	RemoverWan   []netip.Addr

	AdicionarBloq  []Entrada
	AdicionarBloq6 []Entrada
	AdicionarWan   []Entrada
}

// Vazio diz se não há nada a fazer — o caminho mais comum, e o que não pode
// custar um fork.
func (l Lote) Vazio() bool {
	return len(l.RemoverBloq)+len(l.RemoverBloq6)+len(l.RemoverWan)+
		len(l.AdicionarBloq)+len(l.AdicionarBloq6)+len(l.AdicionarWan) == 0
}

// AplicarLote escreve o lote inteiro num único `nft -f`.
//
// POR QUE UM ARQUIVO SÓ, E NÃO UM COMANDO POR ELEMENTO. Um `nft -f` é UMA
// transação netlink: ou tudo entra, ou nada entra. Renovar com dois forks
// (`delete` e depois `add`) abre uma janela de milissegundos em que o endereço
// NÃO ESTÁ na estrutura — e no direcionamento essa janela é o pacote saindo
// pela WAN errada com o endereço de origem da outra, que o provedor descarta.
//
// POR QUE RENOVAR EXIGE `delete` ANTES DO `add`. Medido no nft da caixa:
//
//	add element ... { 1.2.3.4 timeout 1800s : 0x12c }   → aceito, sem erro
//	expires antes: 29m54s   expires depois: 29m54s      → NÃO RENOVOU
//	delete + add na mesma transação → expires 29m59s    → renovou
//
// Um `add` sobre elemento existente é aceito em silêncio e não mexe no prazo.
// Sem o `delete`, "renovação" seria um comando que não faz nada, e o endereço
// sairia no meio do uso — a falha mais cara possível, porque parece funcionar.
//
// E O QUE ACONTECE QUANDO O `delete` ERRA. Também medido: um `delete` de
// elemento AUSENTE derruba o lote INTEIRO — o `add` que ia junto não entra:
//
//	delete element ... { 9.9.9.9 }   ← ausente
//	add    element ... { 5.6.7.8 ... }
//	→ Error: Could not process rule: No such file or directory
//	→ 5.6.7.8 NÃO entrou
//
// Isso acontece de verdade: o kernel pode expirar o elemento entre o feeder
// decidir renovar e o arquivo chegar. Por isso o erro é tratado com UM reenvio
// só com os `add` — quem sumiu já não precisa ser apagado. O reenvio é único e
// contado; insistir viraria laço em cima de uma corrida que se resolve sozinha.
func (s *Service) AplicarLote(ctx context.Context, l Lote) error {
	if s.exec.IsDryRun() || l.Vazio() {
		return nil
	}
	script := montarLote(l, true)
	out, err := s.rodarScriptNft(ctx, script)
	if err == nil {
		return nil
	}
	// Segunda e última tentativa, sem os `delete`. Quem não estava lá não
	// precisa sair; o que importa é o endereço entrar.
	soAdds := montarLote(l, false)
	if soAdds == "" {
		return fmt.Errorf("aplicar o lote de domínios: %w (%s)", err, strings.TrimSpace(out))
	}
	if out2, err2 := s.rodarScriptNft(ctx, soAdds); err2 != nil {
		return fmt.Errorf("aplicar o lote de domínios (mesmo sem as remoções): %w (%s)", err2, strings.TrimSpace(out2))
	}
	return nil
}

// montarLote rende o script. Com comRemocoes=false ele omite os `delete`, que é
// o reenvio descrito em AplicarLote.
func montarLote(l Lote, comRemocoes bool) string {
	var b strings.Builder
	if comRemocoes {
		escreverRemocoes(&b, "set", DomBlockedSet, l.RemoverBloq)
		escreverRemocoes(&b, "set", DomBlockedSet6, l.RemoverBloq6)
		escreverRemocoes(&b, "map", DomWanMap, l.RemoverWan)
	}
	escreverAdicoes(&b, DomBlockedSet, l.AdicionarBloq, false)
	escreverAdicoes(&b, DomBlockedSet6, l.AdicionarBloq6, false)
	escreverAdicoes(&b, DomWanMap, l.AdicionarWan, true)
	return b.String()
}

func escreverRemocoes(b *strings.Builder, tipo, nome string, addrs []netip.Addr) {
	_ = tipo // o nft aceita `delete element` sem dizer se é set ou map
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		fmt.Fprintf(b, "delete element %s %s %s { %s }\n", Family, Table, nome, a.String())
	}
}

func escreverAdicoes(b *strings.Builder, nome string, es []Entrada, comMarca bool) {
	for _, e := range es {
		if !e.Addr.IsValid() {
			continue
		}
		prazo := grampearPrazo(e.Prazo)
		if comMarca {
			fmt.Fprintf(b, "add element %s %s %s { %s timeout %ds : 0x%x }\n",
				Family, Table, nome, e.Addr.String(), int(prazo.Seconds()), e.Marca)
			continue
		}
		fmt.Fprintf(b, "add element %s %s %s { %s timeout %ds }\n",
			Family, Table, nome, e.Addr.String(), int(prazo.Seconds()))
	}
}

// grampearPrazo aplica o piso e o teto aqui, e não só no chamador.
//
// O prazo vem do TTL de uma resposta de DNS, que é um número que um TERCEIRO
// escolheu. Confiar no chamador para grampear seria deixar a última linha de
// defesa fora do lugar onde o valor vira comando.
func grampearPrazo(d time.Duration) time.Duration {
	switch {
	case d < DomTTLPiso:
		return DomTTLPiso
	case d > DomTTLTeto:
		return DomTTLTeto
	default:
		return d
	}
}

func (s *Service) rodarScriptNft(ctx context.Context, script string) (string, error) {
	f, err := os.CreateTemp("", "linkguard-dom-*.nft")
	if err != nil {
		return "", fmt.Errorf("criar o script do lote: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		f.Close() //nolint:errcheck // já estamos devolvendo erro
		return "", fmt.Errorf("escrever o script do lote: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("fechar o script do lote: %w", err)
	}
	return s.exec.Execute(ctx, "nft", "-f", f.Name())
}

// DomKernel é o que o kernel TEM, lido de volta das três estruturas.
//
// POR QUE A LEITURA DE VOLTA EXISTE. Sem ela este arquivo é escrita-só: dá
// para encher, esvaziar e renovar, e não dá para perguntar o que está lá
// dentro. Uma tela que contasse o índice em memória do alimentador afirmaria
// coisas que o kernel pode não ter — o elemento expirou sozinho, o lote falhou,
// alguém deu flush por fora — e este produto já entregou uma vez uma tela que
// dizia o que o kernel não tinha. Quem responde "quantos endereços estão
// barrados agora" é quem barra.
type DomKernel struct {
	Bloq  []netip.Addr
	Bloq6 []netip.Addr
	Wan   []netip.Addr
}

// DomElementos lê as três estruturas.
//
// Usa ExecuteRead: é leitura, e precisa funcionar também em --dry-run. Em
// dry-run o produto não escreve, mas continua tendo de dizer a verdade sobre o
// que existe — e o que existe ali é o que sobrou de antes.
//
// Estrutura ausente NÃO é erro: é "vazia". A criação delas é do boot, e um erro
// aqui viraria faixa vermelha na tela por causa de uma caixa que ainda não
// passou pelo EnsureDomainStructures — que é exatamente o estado de todo
// upgrade entre o boot e a primeira reconciliação.
func (s *Service) DomElementos(ctx context.Context) (DomKernel, error) {
	var k DomKernel
	for _, e := range []struct {
		tipo, nome string
		destino    *[]netip.Addr
	}{
		{"set", DomBlockedSet, &k.Bloq},
		{"set", DomBlockedSet6, &k.Bloq6},
		{"map", DomWanMap, &k.Wan},
	} {
		out, err := s.exec.ExecuteRead(ctx, "nft", "list", e.tipo, Family, Table, e.nome)
		if err != nil {
			continue
		}
		*e.destino = enderecosNft(out)
	}
	return k, nil
}

// enderecosNft extrai os endereços de um `nft list set/map`.
//
// O formato é `elements = { 1.2.3.4 timeout 1h expires 59m28s, ... }`, e no map
// cada item ainda termina em ` : 0x12c`. Em todos os casos o endereço é o
// PRIMEIRO campo do item, que é o que este parser lê e o único que ele promete.
//
// Endereço que não parseia é DESCARTADO em silêncio de propósito: a alternativa
// seria devolver erro e transformar uma linha estranha na saída do nft numa
// tela quebrada. O que importa aqui é o que dá para reconhecer.
func enderecosNft(out string) []netip.Addr {
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return nil
	}
	corpo := out[i+len("elements = {"):]
	if j := strings.Index(corpo, "}"); j >= 0 {
		corpo = corpo[:j]
	}
	var res []netip.Addr
	for _, item := range strings.Split(corpo, ",") {
		campos := strings.Fields(item)
		if len(campos) == 0 {
			continue
		}
		a, err := netip.ParseAddr(campos[0])
		if err != nil {
			continue
		}
		res = append(res, a)
	}
	return res
}
