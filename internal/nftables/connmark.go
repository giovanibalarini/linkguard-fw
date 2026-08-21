package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
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

	// Prioridade mangle + 10: depois da mark_hosts, para que a marca de
	// direcionamento por host (que só existe em conexão nova, saindo) já tenha
	// sido escrita quando a restauração roda. As duas nunca disputam o mesmo
	// pacote — ver o comentário do pacote —, mas a ordem deixa isso explícito.
	connMarkChainSpec   = "{ type filter hook prerouting priority mangle + 10; policy accept; }"
	outputMarkChainSpec = "{ type route hook output priority mangle; policy accept; }"
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

	if err := s.rebuildChain(ctx, ConnMarkChain, connMarkChainRules(limpas)); err != nil {
		return err
	}
	if err := s.rebuildChain(ctx, OutputMarkChain, outputMarkChainRules()); err != nil {
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
	return append(regras, restoreMarkRule())
}

func outputMarkChainRules() [][]string {
	return [][]string{restoreMarkRule()}
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
