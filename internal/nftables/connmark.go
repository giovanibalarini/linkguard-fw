package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// Marcação de conexão para roteamento de retorno (issue #120).
//
// O DEFEITO. Numa caixa com mais de uma WAN, o que ENTRA por uma delas responde
// pela rota default — que em modo balanceado é multipath e escolhe o caminho
// por hash, e em modo failover é sempre o link principal. Quando a resposta sai
// pela WAN errada, ela leva o endereço de origem daquela outra WAN, e o
// provedor a descarta (uRPF). Do lado de fora parece porta fechada; do lado de
// dentro o painel diz que a regra de DNAT está aplicada, e está mesmo — a regra
// nunca foi o problema.
//
// A CORREÇÃO, EM DUAS METADES. Aqui mora a metade do nftables: lembrar em qual
// WAN cada conexão entrou (`ct mark`, que vive enquanto a conexão viver) e
// devolver essa lembrança à marca do pacote (`meta mark`) em todo pacote dela.
// A outra metade é a `ip rule fwmark → tabela do link` (internal/routes), que é
// quem transforma a marca em decisão de rota.
//
// POR QUE `ct mark` E NÃO SÓ `meta mark`. A marca do pacote morre com o pacote.
// A conexão dura, e a resposta pode sair segundos depois, num pacote que não
// tem como saber por onde a conversa começou. `ct mark` é a única memória com
// tempo de vida certo para essa pergunta.
//
// AS DUAS CHAINS, E POR QUE SÃO DUAS:
//
//   - prerouting trata o que ATRAVESSA o firewall — o caso do encaminhamento
//     de porta, em que a resposta vem de um host da LAN;
//   - output trata o que a PRÓPRIA máquina responde — o painel e o SSH
//     atendendo por uma WAN secundária. E é `type route`, não `type filter`:
//     só o tipo route faz o kernel refazer a decisão de rota depois que a marca
//     muda. Com `type filter` a marca é escrita e ignorada, que é o pior
//     resultado possível: parece configurado e não faz nada.
//
// O QUE ISTO **NÃO** TOCA. Conexão iniciada de dentro da LAN nunca entra por
// uma WAN, então nasce com `ct mark` zero e não casa com a regra de restauração
// — o direcionamento por host (@host_wan) e todo o tráfego de saída seguem
// exatamente como antes.
const (
	// ConnMarkChain lembra por onde a conexão entrou e restaura a marca no
	// tráfego que atravessa.
	ConnMarkChain = "conn_mark"
	// OutputMarkChain restaura a marca no tráfego que a própria máquina gera.
	OutputMarkChain = "output_mark"
	// ConnMarkOutChain lembra por qual WAN uma conexão NASCIDA NA LAN saiu.
	ConnMarkOutChain = "conn_mark_out"

	// Prioridade mangle + 10: depois da mark_hosts, para que a marca de
	// direcionamento por host (que só existe em conexão nova, saindo) já tenha
	// sido escrita quando a restauração roda. As duas nunca disputam o mesmo
	// pacote — ver o comentário do pacote —, mas a ordem deixa isso explícito.
	connMarkChainSpec   = "{ type filter hook prerouting priority mangle + 10; policy accept; }"
	outputMarkChainSpec = "{ type route hook output priority mangle; policy accept; }"

	// Hook FORWARD, e não postrouting, por duas razões. A interface de saída já
	// está decidida aqui, que é o que se quer lembrar; e o forward vê SÓ o que
	// atravessa — no postrouting passaria também o tráfego que a própria caixa
	// gera, e gravar marca nele seria estado sem uso, do tipo que confunde quem
	// for depurar depois.
	connMarkOutChainSpec = "{ type filter hook forward priority mangle; policy accept; }"
)

// WANMark associa a interface de uma WAN à marca que identifica o caminho de
// volta por ela. A marca é o table_id do link (100+), que é a mesma tabela de
// rota que o failover já mantém.
type WANMark struct {
	Interface string
	Mark      uint32
}

// EnsureConnMark cria as duas chains e reescreve as regras a partir da
// definição canônica, a cada boot e a cada mudança de link — mesma disciplina
// do masquerade e da contabilidade, e pelo mesmo motivo: EnsureTable é no-op em
// máquina já provisionada.
func (s *Service) EnsureConnMark(ctx context.Context, wans []WANMark) error {
	if s.exec.IsDryRun() {
		return nil
	}
	limpas := sanitizeWANMarks(wans)
	if len(limpas) == 0 {
		// Sem WAN conhecida não há o que lembrar. Escrever só a regra de
		// restauração seria pior que nada: ela restauraria marcas que ninguém
		// grava, e a chain existiria dando a impressão de que a feature está
		// ligada.
		slog.Warn("marcação de conexão: nenhuma WAN válida; as chains não foram reconciliadas",
			"solicitado", len(wans))
		return nil
	}

	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, ConnMarkChain, connMarkChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", ConnMarkChain, err, out)
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, OutputMarkChain, outputMarkChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", OutputMarkChain, err, out)
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, ConnMarkOutChain, connMarkOutChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", ConnMarkOutChain, err, out)
	}

	if err := s.rebuildChain(ctx, ConnMarkChain, connMarkChainRules(limpas)); err != nil {
		return err
	}
	if err := s.rebuildChain(ctx, OutputMarkChain, outputMarkChainRules()); err != nil {
		return err
	}
	if err := s.rebuildChain(ctx, ConnMarkOutChain, connMarkOutChainRules(limpas)); err != nil {
		return err
	}
	slog.Info("marcação de conexão reconciliada", "wans", len(limpas))

	if err := s.Persist(ctx); err != nil {
		slog.Warn("marcação de conexão reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// connMarkChainRules é a definição canônica: uma regra de memória por WAN, e
// uma de restauração no fim.
//
// `ct state new` na regra de memória não é economia: sem ele, um pacote que
// chega pela WAN errada no meio de uma conversa reescreveria a marca da
// conexão e mudaria o caminho de volta no meio do caminho.
func connMarkChainRules(wans []WANMark) [][]string {
	regras := make([][]string, 0, len(wans)+1)
	for _, w := range wans {
		regras = append(regras, []string{
			"iifname", fmt.Sprintf("%q", w.Interface),
			"ct", "state", "new", "counter",
			"ct", "mark", "set", fmt.Sprintf("0x%x", w.Mark),
		})
	}
	return append(regras, restoreReplyMarkRule(wans), restoreOutboundMarkRule(wans))
}

// restoreReplyMarkRule é a restauração da metade de ENTRADA (#120), com o
// guarda de interface que ela não precisava ter antes e passou a precisar.
//
// O DEFEITO QUE ESTE GUARDA IMPEDE, e que quase foi entregue. Antes desta
// feature, `ct mark != 0` significava uma coisa só: "a conexão entrou por uma
// WAN". A restauração podia casar `ct direction reply` sem olhar de onde o
// pacote vinha, porque a resposta de uma conexão que entrou de fora é sempre o
// host da LAN devolvendo — e ele devolve pela LAN.
//
// A memória de saída muda o significado da marca: agora conexão nascida na LAN
// também tem `ct mark`. E a "resposta" DELA é a internet respondendo, chegando
// por uma WAN. Sem o guarda, essa regra casaria esse pacote, poria a marca da
// WAN, a `ip rule fwmark` o mandaria para a tabela do link — que só tem
// `default via <gateway>` — e o SYN-ACK destinado a 192.168.3.20 sairia de
// volta para o provedor. Toda a LAN sem internet, no instante da reconciliação,
// e persistido para o próximo boot.
//
// É o defeito da #120 renascido pela porta que ninguém trancou: a proteção nova
// tinha sido posta na regra nova, e a regra velha continuou lendo `ct mark` com
// o significado antigo.
//
// `iifname != { as WANs }` diz a coisa certa para as duas metades: RESTAURAR SÓ
// O QUE VEIO DA LAN. Resposta de encaminhamento de porta vem da LAN e casa;
// resposta da internet para um host da LAN vem de uma WAN e não casa.
//
// Sem `meta mark == 0x0`, de propósito e ao contrário da restauração de saída:
// aqui a memória da conexão TEM de vencer o @host_wan. O pacote é o host da LAN
// respondendo a quem o procurou de fora, e ele precisa sair pela WAN por onde a
// conexão entrou, mesmo que o admin tenha fixado aquele aparelho em outra.
func restoreReplyMarkRule(wans []WANMark) []string {
	return append([]string{"iifname", "!=", setDeInterfaces(wans)}, restoreMarkRule()...)
}

// setDeInterfaces monta `{ "wanA", "wanB" }` como um token só, na forma que o
// resto do pacote já usa (ver acctChainRules).
func setDeInterfaces(wans []WANMark) string {
	nomes := make([]string, len(wans))
	for i, w := range wans {
		nomes[i] = fmt.Sprintf("%q", w.Interface)
	}
	return "{ " + strings.Join(nomes, ", ") + " }"
}

func outputMarkChainRules() [][]string {
	return [][]string{restoreMarkRule()}
}

// connMarkOutChainRules lembra por qual WAN saiu cada conexão NASCIDA NA LAN.
//
// O QUE ISTO RESOLVE, E POR QUE NÃO É O MESMO PROBLEMA DA #120. A #120 tratou
// do que CHEGA de fora. O que SAI da LAN nunca teve dono: a rota padrão em modo
// balanceado é multipath, o kernel escolhe o caminho por hash, e a escolha vale
// enquanto aquela rota existir. Quando um link cai e volta — ou quando o
// gateway muda numa renovação de DHCP — a rota é reescrita e o hash muda de
// resposta. As conexões ABERTAS pulam de link.
//
// E pular de link não degrada: mata. O conntrack já guardou a tradução de
// origem para o endereço da WAN antiga, então o pacote sai pela WAN nova
// levando o endereço da outra, e o provedor descarta por uRPF. A conexão morre
// calada e não se recupera nem quando o link volta.
//
// O QUE SOBREVIVE E O QUE MORRE, e é isto que torna o defeito difícil de
// enxergar: download e navegação reabrem conexão e parecem apenas "travar um
// instante". Chamada de vídeo e jogo online são fluxos longos — para eles, uma
// reescrita de rota é queda. Medido na caixa de produção: cinco quedas e sete
// retornos em trinta dias, cada um uma janela de morte para o que estava aberto.
//
// AS TRÊS CONDIÇÕES, e nenhuma é decorativa:
//
//   - `ct direction original` — conexão que veio de fora tem a marca gravada na
//     ENTRADA, e os pacotes dela que passam por aqui são a direção de RESPOSTA.
//     Sem isto, a resposta de um encaminhamento de porta seria re-marcada com a
//     WAN de saída, que é a #120 ao contrário.
//   - `ct mark == 0x0` — não sobrescrever o que a entrada já decidiu. Junto com
//     a condição acima é cinto e suspensório, de propósito: as duas metades
//     desta feature já se atropelaram uma vez.
//   - `ct state new` NÃO é usada aqui. A conexão pode virar established antes
//     de o primeiro pacote chegar ao forward em alguns caminhos; `ct mark == 0`
//     já garante gravação única, e é uma condição sobre o ESTADO GUARDADO, não
//     sobre o instante.
func connMarkOutChainRules(wans []WANMark) [][]string {
	regras := make([][]string, 0, len(wans))
	for _, w := range wans {
		regras = append(regras, []string{
			"oifname", fmt.Sprintf("%q", w.Interface),
			"ct", "direction", "original",
			"ct", "mark", "==", "0x0", "counter",
			"ct", "mark", "set", fmt.Sprintf("0x%x", w.Mark),
		})
	}
	return regras
}

// restoreOutboundMarkRule devolve ao pacote a WAN por onde a conexão dele saiu.
//
// `iifname != { as WANs }` É O QUE SEPARA ESTA REGRA DA ARMADILHA DA #120.
// A regra de restauração original vale só para `ct direction reply` justamente
// porque marcar a direção ORIGINAL de uma conexão que entrou de fora mandava o
// SYN destinado ao host da LAN de volta para o provedor. Aqui a direção original
// também é marcada — mas só quando o pacote ENTROU POR ONDE NÃO É WAN, isto é,
// quando ele veio da LAN. Conexão que entrou de fora nunca casa.
//
// `meta mark == 0x0` deixa o direcionamento por host (@host_wan) ganhar. A
// mark_hosts roda em `priority mangle` (-150) e esta chain em `mangle + 10`
// (-140): quando o admin fixou o aparelho numa WAN, a marca já está posta e
// esta regra não a toca. Fixação escolhida por gente vence memória de conexão.
func restoreOutboundMarkRule(wans []WANMark) []string {
	return []string{
		"iifname", "!=", setDeInterfaces(wans),
		"ct", "mark", "!=", "0x0", "ct", "direction", "original",
		"meta", "mark", "==", "0x0", "counter",
		"meta", "mark", "set", "ct", "mark",
	}
}

// restoreMarkRule devolve a marca guardada na conexão ao pacote. O `!= 0x0` é
// o que mantém intacto todo o tráfego que nasceu na LAN: conexão que não entrou
// por WAN nenhuma tem marca zero e não casa aqui.
//
// `ct direction reply` É O QUE IMPEDE ESTA REGRA DE QUEBRAR ENCAMINHAMENTO DE
// PORTA, e a falta dele era um defeito meu, entregue na #120.
//
// A chain de prerouting está em `priority mangle + 10` (-140), ANTES do dstnat
// (-100), e vê as DUAS direções da conexão. Sem a condição, o pacote que CHEGA
// da internet para um host da LAN — a direção original — também recebia a marca.
// Aí o DNAT reescrevia o destino para 192.168.3.50, o kernel decidia a rota já
// com a marca posta, casava a `ip rule fwmark N lookup N` (prioridade 32700,
// antes da main) e caía na tabela do link — que contém APENAS `default via
// <gateway da WAN>`. O SYN destinado ao host da LAN voltava para o provedor.
//
// O sintoma para quem opera: o painel mostra o encaminhamento aplicado, a chain
// de DNAT está lá com a tradução certa, e a câmera/NVR/servidor interno
// simplesmente não responde de fora. Exatamente o que a #120 existe para
// consertar, causado pela #120.
//
// A direção de RESPOSTA continua marcada, que é o ponto da issue: o pacote que
// o host da LAN devolve precisa sair pela mesma WAN por onde a conexão entrou.
//
// Na chain de output a condição é no-op — lá só passam pacotes gerados
// localmente, e conexão nascida aqui nunca recebeu marca (a marca só é gravada
// em `iifname "wanX" ct state new`, que é entrada). Fica na regra única para as
// duas chains dizerem a mesma coisa, em vez de duas formas que alguém precise
// comparar.
func restoreMarkRule() []string {
	return []string{"ct", "mark", "!=", "0x0", "ct", "direction", "reply",
		"counter", "meta", "mark", "set", "ct", "mark"}
}

// sanitizeWANMarks descarta entrada inválida e duplicada, preservando ordem
// estável — o nome vai para dentro de um argv do nft, e marca zero não
// identifica caminho nenhum.
func sanitizeWANMarks(in []WANMark) []WANMark {
	vistas := map[string]bool{}
	out := make([]WANMark, 0, len(in))
	for _, w := range in {
		if w.Mark == 0 || vistas[w.Interface] {
			continue
		}
		if len(sanitizeInterfaces([]string{w.Interface})) == 0 {
			continue
		}
		vistas[w.Interface] = true
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}
