package dashboard_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	. "github.com/giovanibalarini/linkguard-fw/internal/dashboard"
)

// Toda permissão declarada pelos widgets tem que existir de fato no catálogo de
// permissões do RBAC. Uma chave inventada aqui não daria erro em lugar nenhum:
// ela simplesmente nunca casaria com nenhuma permissão do usuário, e o widget
// sumiria do painel de todo mundo, para sempre, sem nenhuma mensagem.
func TestEveryWidgetPermissionExistsInTheRBACCatalog(t *testing.T) {
	for _, w := range Catalog {
		if w.Permission == "" {
			continue // widget sem permissão (onboarding, ações rápidas)
		}
		if !auth.IsValidPermission(w.Permission) {
			t.Errorf("widget %q exige a permissão %q, que não existe no catálogo do RBAC",
				w.Name, w.Permission)
		}
	}
}

// O layout de fábrica só pode conter widget que existe. Um padrão com um nome
// errado abriria o painel já sem aquele widget — e o operador que nunca
// arrastou nada é justamente quem não tem como perceber que falta algo.
func TestDefaultLayoutOnlyReferencesKnownWidgets(t *testing.T) {
	for _, it := range Default() {
		if !IsKnown(it.Widget) {
			t.Errorf("o layout de fábrica referencia o widget desconhecido %q", it.Widget)
		}
		if it.X < 0 || it.W < 1 || it.X+it.W > GridColumns {
			t.Errorf("o item %+v sai da grade de %d colunas", it, GridColumns)
		}
	}
}

// TestSanitizeDescartaWidgetRepetido guarda o dedupe do mapa `seen`. Não havia
// nenhuma asserção em Go sobre ele: o mesmo widget duas vezes seriam duas cópias
// disputando o mesmo dado e a mesma alça de arrasto, e a segunda tem que cair
// fora. Sem este teste, um "mover de pacote" que perdesse o mapa passaria verde.
func TestSanitizeDescartaWidgetRepetido(t *testing.T) {
	entrada := []LayoutItem{
		{Widget: "system_health", X: 0, Y: 0, W: 4, H: 2},
		{Widget: "wan_links", X: 4, Y: 0, W: 4, H: 2},
		{Widget: "system_health", X: 0, Y: 2, W: 4, H: 2}, // repetido
	}
	got := Sanitize(entrada)
	if len(got) != 2 {
		t.Fatalf("esperava 2 itens após o dedupe, veio %d: %+v", len(got), got)
	}
	// A PRIMEIRA ocorrência é a que fica — a posição original do operador.
	if got[0].Widget != "system_health" || got[0].Y != 0 {
		t.Errorf("o dedupe tem que manter a PRIMEIRA ocorrência; veio %+v", got[0])
	}
	if got[1].Widget != "wan_links" {
		t.Errorf("a ordem dos demais tem que ser preservada; veio %+v", got[1])
	}
}

// TestDefaultDashboardLayoutDevolveCopiaNova guarda contra a otimização
// aparentemente inofensiva de transformar o default numa `var` de pacote. Se ela
// acontecer, o primeiro chamador que ordenar ou mexer no slice altera o painel
// de fábrica de TODOS os usuários seguintes — e a suíte fica verde, porque
// nenhum outro teste compara duas chamadas entre si.
func TestDefaultDashboardLayoutDevolveCopiaNova(t *testing.T) {
	a := Default()
	if len(a) == 0 {
		t.Fatal("o layout de fábrica está vazio; o teste não mediria nada")
	}
	original := a[0].Widget

	a[0].Widget = "corrompido-pelo-chamador"
	a[0].X = 999

	b := Default()
	if b[0].Widget != original {
		t.Fatalf("mexer no slice devolvido contaminou a chamada seguinte: "+
			"esperava %q, veio %q. DefaultDashboardLayout tem que devolver "+
			"uma cópia nova a cada chamada, nunca um var de pacote compartilhado.",
			original, b[0].Widget)
	}
	if b[0].X == 999 {
		t.Error("a geometria também vazou entre chamadas")
	}
}
