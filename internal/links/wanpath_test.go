package links

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestWANPathsUsaOTableIDComoMarca(t *testing.T) {
	// Marca e tabela têm de ser o mesmo número: é o que impede marcar uma
	// conexão com um valor que não tem tabela correspondente.
	got := WANPaths([]storage.Link{
		{ID: "l1", Interface: "wan1", Gateway: "10.0.0.1", TableID: 100, Enabled: true},
	})
	if len(got) != 1 {
		t.Fatalf("veio %d caminhos", len(got))
	}
	if got[0].Mark != 100 || got[0].Table != "100" {
		t.Errorf("marca e tabela divergem: %+v", got[0])
	}
	if got[0].MarkHex() != "0x64" {
		t.Errorf("MarkHex = %q, queria 0x64", got[0].MarkHex())
	}
}

func TestWANPathsIgnoraOQueNaoServe(t *testing.T) {
	got := WANPaths([]storage.Link{
		{Interface: "wan1", TableID: 100, Enabled: false}, // desabilitado
		{Interface: "", TableID: 101, Enabled: true},      // sem interface
		{Interface: "wan3", TableID: 0, Enabled: true},    // sem tabela
		{Interface: "wan4", TableID: 102, Enabled: true},  // esse serve
	})
	if len(got) != 1 || got[0].Interface != "wan4" {
		t.Errorf("filtragem errada: %+v", got)
	}
}

func TestWANPathsTemOrdemEstavel(t *testing.T) {
	// As chains do nft são reescritas a partir desta lista; ordem variável
	// faria o ruleset vivo diferir a cada boot sem mudança real nenhuma.
	entrada := []storage.Link{
		{Interface: "wan-z", TableID: 102, Enabled: true},
		{Interface: "wan-a", TableID: 100, Enabled: true},
		{Interface: "wan-m", TableID: 101, Enabled: true},
	}
	primeira := WANPaths(entrada)
	for i := 0; i < 10; i++ {
		outra := WANPaths(entrada)
		for j := range primeira {
			if primeira[j].Interface != outra[j].Interface {
				t.Fatalf("ordem instável: %v vs %v", primeira, outra)
			}
		}
	}
	if primeira[0].Interface != "wan-a" {
		t.Errorf("não ordenou por interface: %+v", primeira)
	}
}
