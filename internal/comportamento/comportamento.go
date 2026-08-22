package comportamento

import (
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/alerts"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Alerta de comportamento: desvio do que a PRÓPRIA rede costuma fazer (#117).
//
// O QUE ISTO RESOLVE. O RRD já guardava o normal de cada aparelho e o pipeline
// de alerta e notificação já existia. Ninguém cruzava as duas coisas: todo
// alerta do produto era limiar fixo — CPU acima de X, disco acima de Y — e
// limiar fixo não sabe nada sobre a rede de quem o usa. 300 Mbps é catástrofe
// numa clínica e terça-feira normal numa produtora de vídeo.
//
// O QUE ESTA ENTREGA FAZ, E O QUE ELA NÃO FAZ. A issue lista cinco detectores.
// Dois deles são possíveis com o que existe hoje, e são estes:
//
//   - aparelho NOVO na rede, nunca visto antes;
//   - aparelho consumindo muito acima do que ELE MESMO costuma consumir.
//
// Os outros três — taxa de conexões novas por segundo, saída em porta que não
// deveria sair da LAN, e link saturado junto de quem estava puxando — dependem
// de dado que o produto ainda não coleta (registro de fluxo, #115). Entregar
// meia medição com nome inteiro seria pior do que não entregar: um detector que
// não pode disparar ensina a confiar num silêncio que não significa nada.
//
// ALERTA DE COMPORTAMENTO QUE DISPARA DEMAIS É PIOR QUE NENHUM — vira ruído e
// some no meio dos outros. Por isso cada detector nasce com as três defesas que
// o failover deste produto já usa: piso absoluto (não alertar sobre ninharia),
// margem sobre o normal (não alertar sobre variação comum) e intervalo mínimo
// entre alertas do mesmo aparelho.

const (
	// JanelaBaseline é quanto passado define o "normal" de um aparelho.
	//
	// Sete dias, e não vinte e quatro horas: o consumo de terça é parecido com
	// o de outra terça, não com o do domingo. Uma janela curta transformaria
	// segunda-feira de manhã num alerta semanal.
	JanelaBaseline = 7 * 24 * time.Hour

	// MargemSobreNormal é quanto acima do próprio normal dispara.
	//
	// Três vezes o normal daquela hora. Duas seria ruído — variação de duas
	// vezes acontece por assistir um vídeo —, e cinco só pegaria o que já é
	// óbvio no gráfico.
	MargemSobreNormal = 3.0

	// PisoAbsoluto é o consumo abaixo do qual nada é alertado, em bytes por
	// segundo.
	//
	// SEM ISTO O DETECTOR SERIA INÚTIL E BARULHENTO AO MESMO TEMPO: um aparelho
	// que normalmente faz 1 KB/s e passa a fazer 4 KB/s excedeu o triplo, e não
	// aconteceu nada. É a divisão por um normal pequeno que faz detector de
	// desvio virar gerador de ruído.
	PisoAbsoluto = 2 * 1024 * 1024 // 2 MB/s

	// IntervaloEntreAlertas é o silêncio mínimo entre dois alertas do MESMO
	// aparelho — a histerese que a issue exige, no mesmo espírito do cooldown
	// do failover.
	IntervaloEntreAlertas = 6 * time.Hour

	// IdadeDeHostNovo é por quanto tempo um aparelho conta como "novo".
	IdadeDeHostNovo = 10 * time.Minute
)

// Servico cruza o histórico com o inventário e levanta alertas.
type Servico struct {
	db       *storage.DB
	alertSvc *alerts.Service
	agora    func() time.Time

	// ultimo guarda quando cada aparelho foi alertado pela última vez. Em
	// memória de propósito: depois de um reboot, alertar de novo sobre um
	// aparelho que continua fora do normal é o comportamento certo — o estado
	// que importa é o da rede, não o do processo.
	ultimo map[string]time.Time
}

// NovoServico cria o serviço.
func NovoServico(db *storage.DB, alertSvc *alerts.Service) *Servico {
	return &Servico{db: db, alertSvc: alertSvc, agora: time.Now, ultimo: map[string]time.Time{}}
}

// Verificar roda os detectores uma vez.
func (s *Servico) Verificar() {
	metas, err := s.db.ListHostMetadata()
	if err != nil {
		slog.Warn("comportamento: não consegui ler o inventário de aparelhos", "err", err)
		return
	}
	s.aparelhosNovos(metas)
	s.acimaDoNormal(metas)
}

// aparelhosNovos avisa sobre quem apareceu na rede agora.
//
// É o detector mais barato da issue e o único que não precisa de histórico
// nenhum: o inventário já grava quando cada aparelho foi visto pela primeira
// vez.
func (s *Servico) aparelhosNovos(metas []storage.HostMetadata) {
	agora := s.agora()
	for _, m := range metas {
		if m.MAC == "" || m.FirstSeen.IsZero() {
			continue
		}
		if agora.Sub(m.FirstSeen) > IdadeDeHostNovo {
			continue
		}
		if !s.podeAlertar(m.MAC, agora) {
			continue
		}
		_ = s.alertSvc.HostNovoNaRede(m.MAC, nomeDe(m))
		s.ultimo[m.MAC] = agora
	}
}

// acimaDoNormal compara o consumo de agora com o normal DAQUELE APARELHO
// naquela hora do dia.
func (s *Servico) acimaDoNormal(metas []storage.HostMetadata) {
	agora := s.agora()
	for _, m := range metas {
		if m.MAC == "" || m.Blocked {
			continue
		}
		atual, normal, ok := s.consumo(m.MAC, agora)
		if !ok {
			continue
		}
		if atual < PisoAbsoluto || normal <= 0 {
			continue
		}
		if atual < normal*MargemSobreNormal {
			continue
		}
		if !s.podeAlertar(m.MAC, agora) {
			continue
		}
		_ = s.alertSvc.HostAcimaDoNormal(m.MAC, nomeDe(m), atual, normal)
		s.ultimo[m.MAC] = agora
	}
}

// consumo devolve o consumo atual e o normal daquele aparelho naquela hora.
//
// O normal é a MEDIANA das amostras da mesma hora do dia nos últimos sete dias.
// Mediana, e não média: um único dia de backup gigante puxaria a média para
// cima e faria o detector emudecer justamente para o aparelho que já teve um
// pico.
func (s *Servico) consumo(mac string, agora time.Time) (atual, normal float64, ok bool) {
	de := agora.Add(-JanelaBaseline).Unix()
	ate := agora.Unix()
	amostras, err := s.db.GetMetricSamples("host.rx_bps", mac, 300, de, ate)
	if err != nil || len(amostras) < 12 {
		// Menos de uma hora de histórico não define normal nenhum. Alertar aqui
		// seria inventar um baseline a partir de dois pontos.
		return 0, 0, false
	}
	hora := agora.Hour()
	var mesmaHora []float64
	for _, a := range amostras {
		t := time.Unix(a.TsUnix, 0)
		if t.Hour() == hora && agora.Sub(t) > time.Hour {
			mesmaHora = append(mesmaHora, a.VAvg)
		}
	}
	if len(mesmaHora) < 6 {
		return 0, 0, false
	}
	atual = amostras[len(amostras)-1].VAvg
	sort.Float64s(mesmaHora)
	normal = mesmaHora[len(mesmaHora)/2]
	return atual, normal, true
}

// podeAlertar aplica a histerese: um aparelho não gera dois alertas seguidos.
func (s *Servico) podeAlertar(mac string, agora time.Time) bool {
	if t, ok := s.ultimo[mac]; ok && agora.Sub(t) < IntervaloEntreAlertas {
		return false
	}
	return true
}

// nomeDe devolve como o aparelho deve ser chamado na mensagem: o apelido que o
// admin deu, o nome que ele anunciou, ou o endereço físico.
func nomeDe(m storage.HostMetadata) string {
	switch {
	case m.Alias != "":
		return m.Alias
	case m.Hostname != "":
		return m.Hostname
	default:
		return m.MAC
	}
}

// FormatarTaxa devolve a taxa em unidade legível. Exportada porque a mensagem
// do alerta e a tela precisam concordar sobre como um número vira texto.
func FormatarTaxa(bps float64) string {
	switch {
	case bps >= 1024*1024:
		return fmt.Sprintf("%.1f MB/s", bps/(1024*1024))
	case bps >= 1024:
		return fmt.Sprintf("%.0f KB/s", bps/1024)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}
