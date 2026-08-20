package nftables

import (
	"fmt"
	"regexp"
	"strings"
)

// Janela de horário do grupo de regras (issue #125).
//
// POR QUE NO GRUPO E NÃO NA REGRA. A condição entra na linha do JUMP: um grupo
// inteiro passa a valer só dentro da janela, e as regras dentro dele não mudam.
// É o mesmo recorte que já existe para ligar/desligar um grupo, e evita repetir
// a condição em cada regra — onde ela sairia de sincronia na primeira edição.
//
// POR QUE NÃO PRECISA DE AGENDADOR. `meta hour` e `meta day` são avaliados no
// kernel, a cada pacote. Não há tarefa que acorda às 22h para aplicar regra e
// às 6h para tirar: a regra está sempre lá, e o kernel decide se ela casa. Isso
// elimina a classe inteira de falha de "o agendador não rodou".
//
// TRÊS COISAS QUE FORAM MEDIDAS, NÃO PRESUMIDAS (nft 1.1.3, kernel 6.12,
// Debian 13 — as versões da máquina de produção):
//
//  1. `meta hour` usa a hora LOCAL do kernel, não UTC. Numa máquina em -03,
//     uma regra para "15:00"-"15:59" casou às 15h locais e a regra para a
//     mesma hora em UTC (18h) não casou nada. Se isso mudar de versão, o
//     controle parental dispararia três horas fora — por isso a bateria K do
//     vm-validate.sh mede de novo, em vez de confiar neste comentário.
//  2. Faixa que atravessa a meia-noite funciona: "22:00"-"06:00" casou às
//     23:30 e às 03:00, e não casou às 12:00 nem às 21:00. É o caso comum do
//     controle parental, e teria sido razoável supor que não funcionasse.
//  3. `meta day` exige o dia em inglês e CAPITALIZADO ("Monday"). Com
//     minúscula o nft recusa a regra inteira — e uma regra recusada aqui
//     significaria um grupo que simplesmente não entra no firewall.
var (
	reHHMM = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

	// diasNFT traduz a chave curta que o painel guarda para o nome que o nft
	// exige. A chave é curta e estável no banco; o nome capitalizado é detalhe
	// do nft e não vaza para o resto do produto.
	diasNFT = map[string]string{
		"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday",
		"fri": "Friday", "sat": "Saturday", "sun": "Sunday",
	}

	// ordemDias mantém a saída estável e legível (segunda a domingo), em vez
	// da ordem em que o admin clicou.
	ordemDias = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
)

// Schedule é a janela em que um grupo vale.
type Schedule struct {
	Days  string // chaves curtas separadas por vírgula; vazio = todos os dias
	Start string // "HH:MM", hora local
	End   string // "HH:MM", hora local
}

// Empty diz se não há janela nenhuma — o grupo vale sempre.
func (s Schedule) Empty() bool {
	return strings.TrimSpace(s.Days) == "" && strings.TrimSpace(s.Start) == "" && strings.TrimSpace(s.End) == ""
}

// Validate recusa janela mal formada.
//
// Hora sem par é recusada em vez de completada com um padrão: "das 22:00" sem
// fim poderia razoavelmente significar "até meia-noite" ou "até o fim do dia
// seguinte", e escolher por conta própria transformaria ambiguidade do admin em
// comportamento de firewall que ele não pediu.
func (s Schedule) Validate() error {
	temInicio := strings.TrimSpace(s.Start) != ""
	temFim := strings.TrimSpace(s.End) != ""
	if temInicio != temFim {
		return fmt.Errorf("a janela precisa de hora de início E de fim")
	}
	if temInicio {
		if !reHHMM.MatchString(s.Start) || !reHHMM.MatchString(s.End) {
			return fmt.Errorf("horário inválido (use HH:MM)")
		}
		if s.Start == s.End {
			// Faixa de duração zero não é "o dia inteiro" nem "nunca": é
			// ambígua, e o nft a aceitaria casando só aquele minuto.
			return fmt.Errorf("início e fim não podem ser o mesmo horário")
		}
	}
	for _, d := range s.dias() {
		if _, ok := diasNFT[d]; !ok {
			return fmt.Errorf("dia inválido: %q", d)
		}
	}
	return nil
}

func (s Schedule) dias() []string {
	var out []string
	for _, d := range strings.Split(s.Days, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// Tokens devolve a condição no formato do nft, na ordem canônica em que o nft
// a reimprime — `meta day` antes de `meta hour`. Emitir fora dessa ordem faria
// o texto guardado divergir do texto lido de volta do kernel.
func (s Schedule) Tokens() []string {
	if s.Empty() || s.Validate() != nil {
		return nil
	}
	var t []string
	if dias := s.diasNFTOrdenados(); len(dias) > 0 && len(dias) < len(ordemDias) {
		// Todos os sete dias é o mesmo que dia nenhum: emitir o set completo
		// só acrescentaria uma condição que nunca é falsa.
		t = append(t, "meta", "day", "{ "+strings.Join(dias, ", ")+" }")
	}
	if s.Start != "" {
		t = append(t, "meta", "hour", fmt.Sprintf("%q-%q", s.Start, s.End))
	}
	return t
}

func (s Schedule) diasNFTOrdenados() []string {
	presentes := map[string]bool{}
	for _, d := range s.dias() {
		presentes[d] = true
	}
	var out []string
	for _, d := range ordemDias {
		if presentes[d] {
			out = append(out, fmt.Sprintf("%q", diasNFT[d]))
		}
	}
	return out
}

// NormalizeDays devolve as chaves de dia em ordem estável, descartando o que
// não existe. É o que o handler grava, para o banco não guardar a ordem em que
// o admin clicou nem lixo digitado.
func NormalizeDays(raw string) string {
	presentes := map[string]bool{}
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if _, ok := diasNFT[d]; ok {
			presentes[d] = true
		}
	}
	var out []string
	for _, d := range ordemDias {
		if presentes[d] {
			out = append(out, d)
		}
	}
	// A ordem já é a de ordemDias: o laço acima percorre a semana, não o que
	// o admin digitou.
	return strings.Join(out, ",")
}
