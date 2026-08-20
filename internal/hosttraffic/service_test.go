package hosttraffic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

func TestRankHostsOrdenaPorConsumoTotal(t *testing.T) {
	contadores := map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 5000, TxBytes: 1000},
		"192.168.3.51": {RxBytes: 100, TxBytes: 50},
		"192.168.3.52": {RxBytes: 9000, TxBytes: 0},
		"8.8.8.8":      {RxBytes: 999999, TxBytes: 999999}, // fora da LAN
	}
	got := rankHosts(contadores, "192.168.3.0/24")
	if len(got) != 3 {
		t.Fatalf("queria 3 hosts da LAN, veio %d: %+v", len(got), got)
	}
	if got[0].IP != "192.168.3.52" || got[1].IP != "192.168.3.50" {
		t.Errorf("ordem por consumo total errada: %+v", got)
	}
	for _, h := range got {
		if h.IP == "8.8.8.8" {
			t.Error("endereço fora da faixa da LAN entrou no ranking")
		}
	}
}

func TestRankHostsDesempateEhEstavel(t *testing.T) {
	// Sem desempate por endereço a ordem vem do map e muda a cada leitura — e
	// a tela, que atualiza sozinha, pisca trocando as linhas de lugar.
	contadores := map[string]nftables.HostCounter{
		"192.168.3.10": {RxBytes: 100},
		"192.168.3.11": {RxBytes: 100},
		"192.168.3.12": {RxBytes: 100},
	}
	primeira := rankHosts(contadores, "192.168.3.0/24")
	for i := 0; i < 20; i++ {
		outra := rankHosts(contadores, "192.168.3.0/24")
		for j := range primeira {
			if primeira[j].IP != outra[j].IP {
				t.Fatalf("ordem instável entre leituras: %v vs %v", primeira, outra)
			}
		}
	}
}

func TestRankHostsFaixaInvalidaNaoDevolveNil(t *testing.T) {
	// nil vira null no JSON e a tela quebra iterando.
	if got := rankHosts(map[string]nftables.HostCounter{"1.2.3.4": {}}, "faixa-torta"); got == nil {
		t.Error("faixa inválida devolveu nil em vez de lista vazia")
	}
}

type contadorFalso struct {
	dados map[string]nftables.HostCounter
	err   error
}

func (c *contadorFalso) HostCounters(context.Context) (map[string]nftables.HostCounter, error) {
	return c.dados, c.err
}

func TestTopTalkersSemFonteDizQueNaoSabe(t *testing.T) {
	// Lista vazia seria indistinguível de "ninguém trafegou" — o exato engano
	// que a #112 existe para acabar.
	s := NewService(firewall.NewDryRunExecutor())
	if _, err := s.TopTalkers(context.Background(), "192.168.3.0/24"); err == nil {
		t.Error("sem fonte de contadores, TopTalkers devia devolver erro")
	}
}

func TestTopTalkersPropagaErroDaFonte(t *testing.T) {
	s := NewService(firewall.NewDryRunExecutor())
	s.SetCounterSource(&contadorFalso{err: errors.New("nft fora do ar")})
	if _, err := s.TopTalkers(context.Background(), "192.168.3.0/24"); err == nil {
		t.Error("erro do nft foi engolido")
	}
}

func TestTopTalkersUsaAFonteDeContadores(t *testing.T) {
	s := NewService(firewall.NewDryRunExecutor())
	s.SetCounterSource(&contadorFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 10, TxBytes: 20},
	}})
	got, err := s.TopTalkers(context.Background(), "192.168.3.0/24")
	if err != nil {
		t.Fatalf("TopTalkers: %v", err)
	}
	if len(got) != 1 || got[0].RxBytes != 10 || got[0].TxBytes != 20 {
		t.Errorf("resultado: %+v", got)
	}
}

func TestEnsureAccountingEnablesAndPersists(t *testing.T) {
	dir := t.TempDir()
	acct := filepath.Join(dir, "nf_conntrack_acct")
	persist := filepath.Join(dir, "99-linkguard-conntrack.conf")
	// Simulate accounting disabled by the kernel.
	if err := os.WriteFile(acct, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewRealExecutor(0), acctPath: acct, persistPath: persist}
	s.EnsureAccounting()

	got, err := os.ReadFile(acct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1\n" {
		t.Errorf("acct not enabled: got %q, want %q", got, "1\n")
	}
	drop, err := os.ReadFile(persist)
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if !strings.Contains(string(drop), "nf_conntrack_acct = 1") {
		t.Errorf("drop-in missing sysctl line: %q", drop)
	}
}

// TestEnsureAccountingDryRunNoWrite ensures dry-run mode never touches the kernel.
func TestEnsureAccountingDryRunNoWrite(t *testing.T) {
	dir := t.TempDir()
	acct := filepath.Join(dir, "nf_conntrack_acct")
	if err := os.WriteFile(acct, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Service{exec: firewall.NewDryRunExecutor(), acctPath: acct, persistPath: filepath.Join(dir, "drop.conf")}
	s.EnsureAccounting()

	got, _ := os.ReadFile(acct)
	if string(got) != "0\n" {
		t.Errorf("dry-run modified acct: got %q, want %q", got, "0\n")
	}
}
