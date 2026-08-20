// Package hosttraffic responde "quem consumiu link" por host da LAN.
//
// A FONTE MUDOU NA #112. Até a v1.0.133 isto agregava os bytes das conexões
// vivas em /proc/net/nf_conntrack — e conexão fechada some daquela tabela,
// levando os bytes junto. O resultado era um ranking de "quem tem conexão
// aberta gorda neste segundo", exibido com o nome de "top consumidores".
//
// Agora vem dos contadores por endereço que o nftables mantém (ver
// internal/nftables/accounting.go), onde o que já passou não é apagado quando
// a conexão termina.
//
// O sysctl net.netfilter.nf_conntrack_acct continua sendo garantido por
// EnsureAccounting aqui, mas não é mais o que alimenta esta tela: ele fica
// porque outras leituras de conntrack no produto dependem dele.
package hosttraffic

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// AccountingSysctl is the kernel knob that makes conntrack keep per-flow byte
// counters. With it off, /proc/net/nf_conntrack has no bytes= fields and
// per-host traffic can't be computed (every host aggregates to zero).
const AccountingSysctl = "/proc/sys/net/netfilter/nf_conntrack_acct"

// accountingDropIn persists the sysctl so it survives reboots (the runtime
// /proc write is not persistent on its own).
const accountingDropIn = "/etc/sysctl.d/99-linkguard-conntrack.conf"

// HostTraffic is the aggregated active-flow byte counters for one LAN host.
type HostTraffic struct {
	IP      string `json:"ip"`
	RxBytes uint64 `json:"rx_bytes"` // download (reply direction)
	TxBytes uint64 `json:"tx_bytes"` // upload (orig direction)
}

// Service reads conntrack and aggregates per-host traffic.
type Service struct {
	exec     firewall.Executor
	counters CounterSource

	// Paths are fields (not consts) so tests can point them at a temp dir.
	acctPath    string
	persistPath string
}

// NewService creates a hosttraffic Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:        exec,
		acctPath:    AccountingSysctl,
		persistPath: accountingDropIn,
	}
}

// EnsureAccounting turns on conntrack byte accounting so per-host traffic (top
// talkers) can be computed, and persists it so it survives reboots. LinkGuard
// owns this runtime prerequisite rather than relying on external sysctl config.
// Best-effort: it logs and returns on failure instead of blocking startup, and
// is a no-op in dry-run mode. Requires root (the daemon runs as root).
//
// Note: enabling accounting only starts counters for flows created afterwards;
// already-established flows stay uncounted until they are replaced.
func (s *Service) EnsureAccounting() {
	if s.exec.IsDryRun() {
		slog.Info("dry-run: skipping conntrack accounting enable")
		return
	}
	if err := os.WriteFile(s.acctPath, []byte("1\n"), 0o644); err != nil {
		slog.Warn("could not enable conntrack accounting; per-host traffic will be empty",
			"path", s.acctPath, "err", err)
		return
	}
	drop := "# Managed by LinkGuard: required for per-host traffic accounting.\n" +
		"net.netfilter.nf_conntrack_acct = 1\n"
	if err := os.WriteFile(s.persistPath, []byte(drop), 0o644); err != nil {
		slog.Warn("enabled conntrack accounting but could not persist it across reboots",
			"path", s.persistPath, "err", err)
	}
}

// CounterSource entrega os contadores por host mantidos pelo nftables. É
// interface (e não o *nftables.Service direto) para este pacote continuar
// testável sem subir o serviço inteiro de firewall.
type CounterSource interface {
	HostCounters(ctx context.Context) (map[string]nftables.HostCounter, error)
}

// SetCounterSource liga a fonte de contadores. Sem ela, TopTalkers responde
// que não sabe — ver o comentário lá.
func (s *Service) SetCounterSource(src CounterSource) { s.counters = src }

// TopTalkers devolve os hosts da LAN ordenados por consumo no ciclo dos
// contadores (decrescente).
//
// MUDOU EM #112, E A MUDANÇA É O PONTO. Antes isto lia
// /proc/net/nf_conntrack, que só tem conexão VIVA: o host que baixou 5 GB há
// dez minutos aparecia com zero, e mil conexões curtas de navegação eram
// subcontadas enquanto um download longo aparecia inteiro. Agora vem dos
// contadores por endereço que o próprio nftables mantém, onde conexão fechada
// não apaga o que já passou.
//
// SEM FONTE, RESPONDE ERRO — de propósito. Devolver lista vazia seria
// indistinguível de "ninguém trafegou", e mostrar número que não corresponde
// ao que aconteceu é exatamente o defeito que a #112 existe para consertar.
func (s *Service) TopTalkers(ctx context.Context, subnetCIDR string) ([]HostTraffic, error) {
	if s.counters == nil {
		return nil, fmt.Errorf("contabilidade por host indisponível: a chain de contabilidade do nftables não está ligada")
	}
	contadores, err := s.counters.HostCounters(ctx)
	if err != nil {
		return nil, err
	}
	return rankHosts(contadores, subnetCIDR), nil
}

// rankHosts filtra pela faixa da LAN e ordena por consumo total.
//
// O filtro por faixa continua existindo mesmo com as regras já escopadas por
// interface: a chain conta o que atravessa o firewall, e numa caixa com mais
// de uma rede interna nem todo endereço contado pertence à LAN que o painel
// está mostrando.
func rankHosts(contadores map[string]nftables.HostCounter, subnetCIDR string) []HostTraffic {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(subnetCIDR))
	if err != nil {
		return []HostTraffic{}
	}
	out := make([]HostTraffic, 0, len(contadores))
	for host, c := range contadores {
		ip := net.ParseIP(host)
		if ip == nil || !ipnet.Contains(ip) {
			continue
		}
		out = append(out, HostTraffic{IP: host, RxBytes: c.RxBytes, TxBytes: c.TxBytes})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RxBytes+out[i].TxBytes != out[j].RxBytes+out[j].TxBytes {
			return out[i].RxBytes+out[i].TxBytes > out[j].RxBytes+out[j].TxBytes
		}
		// Desempate estável por endereço: sem isto a ordem entre hosts de
		// mesmo consumo muda a cada leitura, e a tela pisca sozinha.
		return out[i].IP < out[j].IP
	})
	return out
}
