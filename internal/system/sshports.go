package system

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

// Onde o SSH realmente escuta (#119).
//
// POR QUE ISTO EXISTE. A proteção de entrada das WANs libera as portas de
// gerência antes de descartar o resto, e é essa liberação que impede a regra de
// trancar o admin do lado de fora. A porta do painel sempre veio da config; a
// do SSH era o literal 22.
//
// Isso é o mesmo erro que o comentário de SurvivalRules já denuncia para o
// painel — "fixá-la deixaria o anti-lockout mudo justamente em quem não usa o
// padrão" — cometido na linha de baixo, para o outro serviço. Numa caixa com
// `Port 2222` no sshd_config, a regra que existe para não trancar ninguém
// descarta exatamente a porta por onde o admin entra.
//
// A FONTE É ONDE O SSHD ESTÁ ESCUTANDO AGORA, e não o sshd_config. Um arquivo
// editado e não recarregado descreve a intenção; o socket descreve o fato, e é
// o fato que decide se o pacote passa. `Port` comentado, `ListenAddress` com
// porta embutida, múltiplas portas e um sshd rodando por socket-activation dão
// todos a mesma resposta certa por este caminho, e respostas diferentes pelo
// arquivo.

var reSSHPorta = regexp.MustCompile(`:(\d+)\s*$`)

// SSHPorts devolve as portas TCP em que o sshd está escutando, em ordem.
//
// Devolve vazio quando não consegue descobrir — e quem chama decide o que
// fazer com isso. Chutar 22 aqui dentro seria transformar "não sei" em "é a
// padrão", que é precisamente a confusão que esta função existe para desfazer.
func SSHPorts(ctx context.Context, exec firewall.Executor) []int {
	out, err := exec.ExecuteRead(ctx, "ss", "-lntpH")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	vistas := map[int]bool{}
	for _, linha := range strings.Split(out, "\n") {
		if !strings.Contains(linha, "sshd") {
			continue
		}
		campos := strings.Fields(linha)
		// O endereço local é o quarto campo de `ss -lntpH`:
		//   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=820,fd=6))
		if len(campos) < 4 {
			continue
		}
		m := reSSHPorta.FindStringSubmatch(campos[3])
		if m == nil {
			continue
		}
		p, err := strconv.Atoi(m[1])
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		vistas[p] = true
	}
	portas := make([]int, 0, len(vistas))
	for p := range vistas {
		portas = append(portas, p)
	}
	sort.Ints(portas)
	return portas
}
