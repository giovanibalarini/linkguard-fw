package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNenhumaSerieDeAparelhoNoRegistroAberto é a rede que impede o defeito que
// as issues #115, #117 e #118 criariam juntas.
//
// O /metrics está registrado FORA do grupo autenticado e a suíte exige que ele
// responda pela WAN. Uma série com rótulo de aparelho ali é inventário da rede
// do cliente publicado sem senha — e nenhuma das três issues, sozinha, tem como
// perceber isso, porque não há arquivo em comum entre elas.
func TestNenhumaSerieDeAparelhoNoRegistroAberto(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)

	familias, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if len(familias) == 0 {
		t.Fatal("o registro está vazio: este teste não estaria medindo nada")
	}
	for _, f := range familias {
		if SerieDeAparelho(f.GetName()) {
			t.Errorf("a série %q carrega identidade de aparelho e está no /metrics, que é aberto", f.GetName())
		}
		// E nenhum rótulo pode ser o endereço físico, mesmo numa série de nome
		// inocente: o vazamento seria pelo label, não pelo nome.
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				n := strings.ToLower(l.GetName())
				if n == "mac" || n == "host" || n == "device" || n == "aparelho" {
					t.Errorf("a série %q tem rótulo %q: identidade de aparelho no /metrics aberto", f.GetName(), l.GetName())
				}
			}
		}
	}
}

func TestSerieDeAparelhoReconheceOsPrefixos(t *testing.T) {
	for _, s := range []string{"linkguard_host_rx_bytes", "linkguard_device_seen", "linkguard_client_x"} {
		if !SerieDeAparelho(s) {
			t.Errorf("%q devia ser reconhecida como identidade de aparelho", s)
		}
	}
	for _, s := range []string{"linkguard_alerts_unresolved_total", "linkguard_links_total", "linkguard_system_uptime_seconds"} {
		if SerieDeAparelho(s) {
			t.Errorf("%q é agregado e foi tratado como identidade", s)
		}
	}
}
