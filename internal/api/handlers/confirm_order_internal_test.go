package handlers

import "testing"

// inputOrderChanged é quem decide se uma REORDENAÇÃO abre a janela de
// confirmação, e até esta revisão ela não tinha teste nenhum: uma comparação
// invertida ali passaria a suíte inteira em verde e só apareceria com um
// operador trancado para fora de uma máquina remota — a ordem dos grupos de
// input é a ordem de avaliação da chain que decide sobre o SSH e o painel.
//
// Mora num arquivo de teste interno porque confirm_test.go é package
// handlers_test e não alcança uma função não exportada.
//
// O critério é largo de propósito ("na dúvida, abre"): basta o ÍNDICE de um
// item de input mudar. Os casos abaixo fixam as duas pontas — o que TEM que
// abrir e o que não pode abrir — e o desempate.
func TestInputOrderChanged(t *testing.T) {
	for _, c := range []struct {
		name    string
		current []string
		next    []string
		isInput map[string]bool
		want    bool
	}{
		{
			name:    "nada mudou",
			current: []string{"a", "b", "c"},
			next:    []string{"a", "b", "c"},
			isInput: map[string]bool{"b": true},
			want:    false,
		},
		{
			name:    "só os de forward trocaram de lugar",
			current: []string{"a", "b", "c"},
			next:    []string{"c", "b", "a"},
			isInput: map[string]bool{"b": true},
			want:    false,
		},
		{
			name:    "um de input mudou de índice",
			current: []string{"a", "b", "c"},
			next:    []string{"b", "a", "c"},
			isInput: map[string]bool{"b": true},
			want:    true,
		},
		{
			name: "o de input ficou no mesmo índice, mas um forward passou por baixo dele",
			// Critério largo: aqui a ordem RELATIVA entre os de input não
			// mudou (só há um), e mesmo assim não abre — porque o índice dele
			// não mudou. É o limite exato do critério, escrito para que
			// afrouxá-lo ou apertá-lo seja uma decisão visível.
			current: []string{"a", "b", "c"},
			next:    []string{"a", "b", "c"},
			isInput: map[string]bool{"a": true},
			want:    false,
		},
		{
			name:    "dois de input trocando entre si",
			current: []string{"a", "b"},
			next:    []string{"b", "a"},
			isInput: map[string]bool{"a": true, "b": true},
			want:    true,
		},
		{
			name:    "id de input que não existia na ordem de hoje",
			current: []string{"a", "b"},
			next:    []string{"a", "b", "novo"},
			isInput: map[string]bool{"novo": true},
			want:    true,
		},
		{
			name:    "nenhum item de input: reordenar não custa janela nenhuma",
			current: []string{"a", "b", "c"},
			next:    []string{"c", "b", "a"},
			isInput: map[string]bool{},
			want:    false,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := inputOrderChanged(c.current, c.next, c.isInput); got != c.want {
				t.Errorf("inputOrderChanged(%v, %v, %v) = %v, queria %v",
					c.current, c.next, c.isInput, got, c.want)
			}
		})
	}
}
