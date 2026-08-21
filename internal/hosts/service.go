package hosts

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Host is one LAN host in the inventory: live neighbour data merged with stored
// metadata (alias, blocked flag, first/last seen).
type Host struct {
	IP        string     `json:"ip"`
	MAC       string     `json:"mac"`
	Interface string     `json:"interface"`
	State     string     `json:"state"`
	Online    bool       `json:"online"`
	Hostname  string     `json:"hostname,omitempty"`
	Alias     string     `json:"alias,omitempty"`
	Blocked   bool       `json:"blocked"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// reachableStates are NUD states that mean the host is currently present.
var reachableStates = map[string]bool{
	"REACHABLE": true, "STALE": true, "DELAY": true, "PROBE": true, "PERMANENT": true,
}

// Service builds the host inventory from the kernel neighbour table and the
// stored host metadata.
type Service struct {
	exec firewall.Executor
	db   *storage.DB
	nft  *nftables.Service
	net  netsvc.Provider
}

// NewService creates a hosts Service.
func NewService(exec firewall.Executor, db *storage.DB, nft *nftables.Service, net netsvc.Provider) *Service {
	return &Service{exec: exec, db: db, nft: nft, net: net}
}

// List returns the current host inventory. It records a sighting for every host
// with a MAC (so the inventory persists across reboots/STALE states) and merges
// in stored metadata. Hosts known from storage but not currently in the
// neighbour table are included as offline.
func (s *Service) List(ctx context.Context) ([]Host, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "neigh", "show")
	if err != nil {
		return nil, err
	}
	neighbors := parseNeighbors(out)

	metaList, err := s.db.ListHostMetadata()
	if err != nil {
		return nil, err
	}
	meta := make(map[string]storage.HostMetadata, len(metaList))
	for _, m := range metaList {
		meta[m.MAC] = m
	}

	// Collect sightings and persist them in one transaction at the end (one
	// write per host on every List was extremely slow without WAL).
	sightings := make(map[string]string)
	seen := make(map[string]bool)
	var hosts []Host
	for _, n := range neighbors {
		if n.MAC == "" {
			continue // can't track a host without a stable identifier
		}
		// UM HOST É UM MAC, E NÃO UMA LINHA DE `ip neigh` (#119).
		//
		// O mesmo aparelho aparece na vizinhança uma vez por ENDEREÇO: o IPv4,
		// o IPv6 global e o link-local — três linhas com o mesmo MAC. Antes
		// desta guarda, as três viravam três "hosts" na tela, e o avistamento
		// gravado no banco era o da ÚLTIMA linha lida, que costuma ser um
		// endereço IPv6.
		//
		// O estrago não ficava na tela. O IP guardado alimenta o bloqueio
		// (`blocked_hosts` é `ipv4_addr`) e o direcionamento por host
		// (`host_wan` idem): com um endereço IPv6 gravado ali, o `nft add
		// element` era RECUSADO e o erro descartado por um `_, _ =` — o host
		// aparecia bloqueado na tela e não estava bloqueado em lugar nenhum.
		//
		// Isso não doía enquanto a LAN não tinha IPv6 (forwarding desligado,
		// sem RA do produto). Doeu no primeiro cliente de teste com IPv6, que é
		// como foi encontrado.
		if !ehIPv4(n.IP) {
			if _, jaVisto := seen[n.MAC]; jaVisto {
				continue
			}
			// Host só-IPv6: entra na lista (existe, e a tela precisa mostrá-lo),
			// mas NÃO vira avistamento — gravar um endereço que os sets IPv4
			// não aceitam é pior que não gravar nada.
			seen[n.MAC] = true
			hosts = append(hosts, hostDeVizinho(n, meta))
			continue
		}
		if _, jaVisto := seen[n.MAC]; jaVisto {
			// Já entrou por um endereço não-IPv4; corrige a linha para o IPv4,
			// que é a identidade que o resto do produto sabe usar.
			for i := range hosts {
				if hosts[i].MAC == n.MAC {
					hosts[i].IP, hosts[i].State, hosts[i].Online = n.IP, n.State, reachableStates[n.State]
					break
				}
			}
			sightings[n.MAC] = n.IP
			continue
		}
		seen[n.MAC] = true
		sightings[n.MAC] = n.IP

		hosts = append(hosts, hostDeVizinho(n, meta))
	}

	// Persist all sightings at once; best-effort (don't fail listing on write error).
	_ = s.db.UpsertHostSightings(sightings)

	// Add known-but-currently-absent hosts as offline entries.
	for _, m := range metaList {
		if seen[m.MAC] {
			continue
		}
		first, last := m.FirstSeen, m.LastSeen
		hosts = append(hosts, Host{
			IP:        m.IP,
			MAC:       m.MAC,
			State:     "OFFLINE",
			Online:    false,
			Hostname:  m.Hostname,
			Alias:     m.Alias,
			Blocked:   m.Blocked,
			FirstSeen: &first,
			LastSeen:  &last,
		})
	}

	// Enrich with hostnames from DHCP leases (by MAC) — best-effort.
	if leases, err := s.net.Leases(ctx); err == nil {
		byMAC := make(map[string]string, len(leases))
		for _, l := range leases {
			if l.Hostname != "" {
				byMAC[strings.ToLower(l.MAC)] = l.Hostname
			}
		}
		for i := range hosts {
			if hosts[i].Hostname == "" {
				if hn, ok := byMAC[strings.ToLower(hosts[i].MAC)]; ok {
					hosts[i].Hostname = hn
				}
			}
		}
	}

	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Online != hosts[j].Online {
			return hosts[i].Online // online first
		}
		return hosts[i].IP < hosts[j].IP
	})
	return hosts, nil
}

// MACByIP devolve o mapa IP → MAC da tabela de vizinhança do kernel.
//
// Existe para a série de consumo por host (#113) poder rotular a medição pela
// identidade que o produto usa em todo o resto — alias, bloqueio e inventário
// são indexados por MAC. Sem isto, o amostrador teria de duplicar o parser de
// `ip neigh` que já mora aqui.
//
// Endereço sem MAC conhecido simplesmente não entra: no modelo deste produto,
// host da LAN é host com MAC (ver List), e o que atravessa o firewall sem
// aparecer na vizinhança é roteador de outra rede, não aparelho local.
func (s *Service) MACByIP(ctx context.Context) (map[string]string, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "neigh", "show")
	if err != nil {
		return nil, err
	}
	res := map[string]string{}
	for _, n := range parseNeighbors(out) {
		if n.IP == "" || n.MAC == "" {
			continue
		}
		res[n.IP] = validate.NormalizeMAC(n.MAC)
	}
	return res, nil
}

// SetAlias assigns a friendly name to a host.
func (s *Service) SetAlias(mac, alias string) error {
	return s.db.SetHostAlias(mac, alias)
}

// SetBlocked blocks/unblocks a host: it persists the flag AND enforces it on the
// live firewall by adding/removing the host's current IP in the nft
// `blocked_hosts` set (the FORWARD chain drops traffic to/from that set).
func (s *Service) SetBlocked(ctx context.Context, mac string, blocked bool) error {
	if err := s.db.SetHostBlocked(mac, blocked); err != nil {
		return err
	}
	// O ENDEREÇO FÍSICO VEM PRIMEIRO, E NÃO DEPENDE DE CONHECER O IP (#119).
	//
	// O bloqueio por IP só valia para IPv4, e só depois de o host ter sido
	// visto na rede — até lá a flag ficava guardada sem efeito. O MAC é a
	// identidade que o chamador JÁ tem em mãos: bloquear por ele vale para
	// todas as famílias e vale imediatamente, sem esperar o host aparecer.
	//
	// Best-effort como o resto: elemento duplicado ou ausente não é falha dura,
	// porque a flag no banco é a fonte da verdade.
	if blocked {
		_, _ = s.nft.BlockMAC(ctx, mac)
	} else {
		_, _ = s.nft.UnblockMAC(ctx, mac)
	}

	ip := s.ipForMAC(mac)
	if ip != "" && !ehIPv4(ip) {
		// Endereço não-IPv4 gravado por uma versão anterior (ver a guarda em
		// List). Mandá-lo para um set `ipv4_addr` seria um elemento recusado
		// com o erro descartado — o host apareceria bloqueado e não estaria.
		// O bloqueio por endereço físico acima já está valendo.
		slog.Warn("host com endereço não-IPv4 gravado; só o bloqueio por endereço físico foi aplicado",
			"mac", mac, "ip", ip)
		ip = ""
	}
	if ip == "" {
		// Sem IP conhecido não há o que pôr no set IPv4 — mas o bloqueio por
		// MAC acima JÁ está valendo, que é a diferença desta mudança.
		if rs, err := s.nft.Ruleset(ctx); err == nil {
			_ = s.db.SetSetting(nftables.LiveSnapshotSettingKey, rs)
		}
		return nil
	}
	if blocked {
		_, _ = s.nft.BlockHost(ctx, ip)
	} else {
		_, _ = s.nft.UnblockHost(ctx, ip)
	}
	// Snapshot the live ruleset so a from-scratch reinstall restores this block
	// too, not just the host_metadata flag (mirrors the handlers-package
	// saveNftSnapshot; duplicated here rather than imported to avoid this
	// package depending on internal/api/handlers).
	if rs, err := s.nft.Ruleset(ctx); err == nil {
		_ = s.db.SetSetting(nftables.LiveSnapshotSettingKey, rs)
	}
	return nil
}

func (s *Service) ipForMAC(mac string) string {
	metas, err := s.db.ListHostMetadata()
	if err != nil {
		return ""
	}
	for _, m := range metas {
		if m.MAC == mac {
			return m.IP
		}
	}
	return ""
}

// SincronizaBloqueiosPorMAC põe no firewall o endereço físico de todo host
// marcado como bloqueado no banco.
//
// POR QUE ISTO EXISTE. O bloqueio por endereço físico chegou depois (#119,
// fase 2), e o set nasce vazio. Numa caixa já instalada, os hosts bloqueados
// estão no banco e no set de IPv4 — mas não no de MAC. Sem esta passada, o
// bloqueio deles continuaria valendo só para IPv4 até alguém desbloquear e
// bloquear de novo pela tela, o que ninguém faz porque a tela já diz
// "bloqueado".
//
// Roda a cada boot, e é idempotente: elemento duplicado não é falha.
func (s *Service) SincronizaBloqueiosPorMAC(ctx context.Context) {
	metas, err := s.db.ListHostMetadata()
	if err != nil {
		slog.Warn("não foi possível ler os hosts para sincronizar o bloqueio por endereço físico", "err", err)
		return
	}
	var n int
	for _, m := range metas {
		if !m.Blocked || m.MAC == "" {
			continue
		}
		if _, err := s.nft.BlockMAC(ctx, m.MAC); err == nil {
			n++
		}
	}
	if n > 0 {
		slog.Info("bloqueio por endereço físico sincronizado a partir do banco", "hosts", n)
	}
}

// ehIPv4 diz se o endereço é IPv4. Existe porque os sets do nftables que o
// produto usa para host (`blocked_hosts`, `host_wan`) são `ipv4_addr`: gravar
// outra coisa não é uma limitação, é um elemento recusado com o erro
// descartado.
func ehIPv4(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.Is4()
}

// hostDeVizinho monta a linha da tela a partir de uma entrada de vizinhança,
// juntando o que o banco já sabe sobre aquele MAC.
func hostDeVizinho(n Neighbor, meta map[string]storage.HostMetadata) Host {
	h := Host{
		IP:        n.IP,
		MAC:       n.MAC,
		Interface: n.Interface,
		State:     n.State,
		Online:    reachableStates[n.State],
	}
	if m, ok := meta[n.MAC]; ok {
		h.Hostname = m.Hostname
		h.Alias = m.Alias
		h.Blocked = m.Blocked
		h.FirstSeen = &m.FirstSeen
	}
	return h
}
