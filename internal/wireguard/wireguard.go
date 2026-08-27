// Package wireguard manages the LinkGuard-owned road-warrior VPN.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	InterfaceName = "linkguard"
	ConfigPath    = "/etc/wireguard/linkguard.conf"
	ServiceName   = "wg-quick@linkguard.service"
	ServerSecret  = "wireguard_server_private_v1"
)

type Config struct {
	Enabled        bool   `json:"enabled"`
	ListenPort     int    `json:"listen_port"`
	Address        string `json:"address"`
	EndpointHost   string `json:"endpoint_host"`
	EndpointLinkID string `json:"endpoint_link_id"`
}

type Peer struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	PublicKey       string `json:"public_key"`
	Address         string `json:"address"`
	FirewallGroupID string `json:"firewall_group_id"`
	CreatedAt       int64  `json:"created_at,omitempty"`
	RotatedAt       int64  `json:"rotated_at,omitempty"`
}

func DefaultConfig() Config {
	return Config{ListenPort: 51820, Address: "10.7.0.1/24"}
}

func GenerateKeypair() (priv, pub string, err error) {
	var key [32]byte
	if _, err = rand.Read(key[:]); err != nil {
		return "", "", err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	public, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(public), nil
}

func PublicKey(private string) (string, error) {
	key, err := decodeKey(private)
	if err != nil {
		return "", err
	}
	public, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func decodeKey(v string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("chave WireGuard inválida")
	}
	return b, nil
}

var (
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	linkIDRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{0,64}$`)
	userIDRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
)

func ValidateConfig(c Config) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(c.Address))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 || prefix != prefix.Masked() && prefix.Addr() == prefix.Masked().Addr() {
		return fmt.Errorf("endereço do túnel inválido: use IPv4 CIDR com prefixo /16 a /30")
	}
	if prefix.Addr() == prefix.Masked().Addr() || prefix.Addr() == lastAddr(prefix.Masked()) {
		return fmt.Errorf("o endereço do servidor não pode ser o endereço de rede ou broadcast")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("porta WireGuard inválida")
	}
	if !linkIDRE.MatchString(c.EndpointLinkID) {
		return fmt.Errorf("link do endpoint inválido")
	}
	if c.EndpointHost != "" && !validEndpointHost(c.EndpointHost) {
		return fmt.Errorf("endpoint inválido: use um endereço IP ou hostname")
	}
	return nil
}

func validEndpointHost(host string) bool {
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "\r\n\t :/[]") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid()
	}
	return len(host) <= 253 && hostnameRE.MatchString(host) && !strings.Contains(host, "..")
}

func validatePeer(c Config, p Peer) error {
	if !userIDRE.MatchString(p.UserID) {
		return fmt.Errorf("id de usuário inválido")
	}
	if _, err := decodeKey(p.PublicKey); err != nil {
		return fmt.Errorf("peer %s: %w", p.UserID, err)
	}
	addr, err := netip.ParsePrefix(p.Address)
	if err != nil || !addr.Addr().Is4() || addr.Bits() != 32 {
		return fmt.Errorf("peer %s: endereço /32 inválido", p.UserID)
	}
	server, _ := netip.ParsePrefix(c.Address)
	if !server.Masked().Contains(addr.Addr()) || server.Addr() == addr.Addr() {
		return fmt.Errorf("peer %s: endereço fora do túnel", p.UserID)
	}
	return nil
}

func RenderServerConfig(c Config, private string, peers []Peer) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	if _, err := decodeKey(private); err != nil {
		return "", err
	}
	ordered := append([]Peer(nil), peers...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Address < ordered[j].Address })
	var b strings.Builder
	b.WriteString("# Managed by LinkGuard FW — do not edit by hand.\n[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\nListenPort = %d\nPrivateKey = %s\n", c.Address, c.ListenPort, private)
	for _, p := range ordered {
		if err := validatePeer(c, p); err != nil {
			return "", err
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\nAllowedIPs = %s\n", p.PublicKey, p.Address)
	}
	return b.String(), nil
}

func RenderClientConfig(c Config, serverPublic string, p Peer, private, endpoint string) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	if _, err := decodeKey(serverPublic); err != nil {
		return "", err
	}
	if _, err := decodeKey(private); err != nil {
		return "", err
	}
	if err := validatePeer(c, p); err != nil {
		return "", err
	}
	if !validEndpointHost(endpoint) {
		return "", fmt.Errorf("endpoint inválido")
	}
	server, _ := netip.ParsePrefix(c.Address)
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		private, p.Address, server.Addr(), serverPublic, net.JoinHostPort(endpoint, fmt.Sprint(c.ListenPort))), nil
}

func NextAddress(c Config, peers []Peer) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	server, _ := netip.ParsePrefix(c.Address)
	network := server.Masked()
	used := map[netip.Addr]bool{server.Addr(): true, network.Addr(): true, lastAddr(network): true}
	for _, p := range peers {
		if a, err := netip.ParsePrefix(p.Address); err == nil {
			used[a.Addr()] = true
		}
	}
	for addr := network.Addr().Next(); addr.IsValid() && network.Contains(addr); addr = addr.Next() {
		if !used[addr] {
			return addr.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("sem endereços livres no túnel %s", network)
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	mask := uint32(1<<hostBits) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
