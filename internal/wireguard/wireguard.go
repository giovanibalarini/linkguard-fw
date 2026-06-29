// Package wireguard manages a road-warrior WireGuard VPN server on the firewall.
// It follows the "generate config + manage service" model used by keaunbound and
// nftables: the panel owns /etc/wireguard/wg0.conf and drives wg-quick@wg0.
//
// The VPN is opt-in (disabled by default), so installing the package never
// touches the system until an admin enables it.
package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
)

const (
	// Iface is the managed WireGuard interface.
	Iface = "wg0"
	// ConfPath is the wg-quick config the panel owns.
	ConfPath = "/etc/wireguard/wg0.conf"
	// ServiceName is the systemd unit wg-quick provides per interface.
	ServiceName = "wg-quick@wg0"
)

// Peer is a VPN client. The private key is stored so the panel can re-render the
// client config / QR on demand (a deliberate convenience trade-off for ease of
// use on a self-hosted box).
type Peer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
	AllowedIP  string `json:"allowed_ip"` // e.g. 10.7.0.2/32
	CreatedAt  string `json:"created_at"`
}

// Config is the persisted VPN configuration (settings JSON).
type Config struct {
	Enabled    bool   `json:"enabled"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
	Address    string `json:"address"`  // server VPN address, e.g. 10.7.0.1/24
	Subnet     string `json:"subnet"`   // e.g. 10.7.0.0/24
	Endpoint   string `json:"endpoint"` // public host clients dial (no port)
	DNS        string `json:"dns"`      // DNS pushed to clients
	Peers      []Peer `json:"peers"`
}

// Defaults returns a sensible starting configuration.
func Defaults() Config {
	return Config{
		Enabled:    false,
		ListenPort: 51820,
		Address:    "10.7.0.1/24",
		Subnet:     "10.7.0.0/24",
		DNS:        "10.7.0.1",
		Peers:      []Peer{},
	}
}

// Service drives the WireGuard interface.
type Service struct {
	exec firewall.Executor
}

// NewService creates a WireGuard Service.
func NewService(exec firewall.Executor) *Service { return &Service{exec: exec} }

// ─── key generation (Curve25519 / X25519) ────────────────────────────────────

// GenerateKeypair returns a base64 private/public WireGuard keypair.
func GenerateKeypair() (priv string, pub string, err error) {
	var key [32]byte
	if _, err = rand.Read(key[:]); err != nil {
		return "", "", err
	}
	// Clamp per X25519 (RFC 7748).
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	pubBytes, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]),
		base64.StdEncoding.EncodeToString(pubBytes), nil
}

// ─── config rendering ────────────────────────────────────────────────────────

// ServerConfig renders /etc/wireguard/wg0.conf (the server side).
func ServerConfig(c Config) string {
	var b strings.Builder
	b.WriteString("# Managed by LinkGuard FW — do not edit by hand.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# %s\n", p.Name)
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIP)
	}
	return b.String()
}

// ClientConfig renders the .conf a client imports (full-tunnel by default).
func ClientConfig(c Config, p Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", p.AllowedIP)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.PublicKey)
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", c.Endpoint, c.ListenPort)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// NextAllowedIP returns the next free /32 host address in the configured subnet,
// skipping the server's own address.
func NextAllowedIP(c Config) (string, error) {
	_, ipnet, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return "", fmt.Errorf("sub-rede inválida: %w", err)
	}
	used := map[string]bool{}
	if serverIP, _, e := net.ParseCIDR(c.Address); e == nil {
		used[serverIP.String()] = true
	}
	for _, p := range c.Peers {
		if ip, _, e := net.ParseCIDR(p.AllowedIP); e == nil {
			used[ip.String()] = true
		}
	}
	// Network and broadcast addresses are never assignable.
	network := ipnet.IP.Mask(ipnet.Mask)
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^ipnet.Mask[i]
	}

	ip := make(net.IP, len(network))
	copy(ip, network)
	for i := 0; i < 1<<16; i++ {
		incIP(ip)
		if !ipnet.Contains(ip) {
			break
		}
		if ip.Equal(network) || ip.Equal(broadcast) {
			continue
		}
		if s := ip.String(); !used[s] {
			return s + "/32", nil
		}
	}
	return "", fmt.Errorf("sem endereços livres na sub-rede %s", c.Subnet)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ─── apply / status ──────────────────────────────────────────────────────────

// Apply writes the server config and reconciles the systemd service to match
// c.Enabled. Writing happens with 0600 perms (the file holds private keys).
func (s *Service) Apply(ctx context.Context, c Config) (string, error) {
	if s.exec.IsDryRun() {
		return "dry-run", nil
	}
	if err := os.MkdirAll(filepath.Dir(ConfPath), 0o700); err != nil {
		return "", fmt.Errorf("criar /etc/wireguard: %w", err)
	}
	if err := os.WriteFile(ConfPath, []byte(ServerConfig(c)), 0o600); err != nil {
		return "", fmt.Errorf("escrever config: %w", err)
	}
	if !c.Enabled {
		// Bring the interface down and disable it; ignore "not loaded" errors.
		out, _ := s.exec.Execute(ctx, "systemctl", "disable", "--now", ServiceName)
		return out, nil
	}
	// Enable + (re)start to load the new config. wg-quick is idempotent.
	if _, err := s.exec.Execute(ctx, "systemctl", "enable", ServiceName); err != nil {
		return "", fmt.Errorf("habilitar serviço: %w", err)
	}
	return s.exec.Execute(ctx, "systemctl", "restart", ServiceName)
}

// Status returns `wg show wg0` (empty string when the interface is down).
func (s *Service) Status(ctx context.Context) string {
	out, err := s.exec.ExecuteRead(ctx, "wg", "show", Iface)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
