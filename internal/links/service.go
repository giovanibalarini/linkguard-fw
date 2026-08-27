// Package links manages WAN link configuration and state.
package links

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const (
	StatusOnline   = "online"
	StatusOffline  = "offline"
	StatusDegraded = "degraded"
	StatusUnknown  = "unknown"
)

// ErrNotFound distinguishes an authoritative missing link from a storage
// failure. Recovery callers may safely interpret it as disabled intent while
// retaining operational leases for every other load error.
var ErrNotFound = errors.New("link not found")

// Service handles link CRUD and state management.
type Service struct {
	db *storage.DB
}

// DetectedWANLink represents a WAN interface detected from system routes.
type DetectedWANLink struct {
	Interface string `json:"interface"`
	IPAddress string `json:"ip_address"`
	Gateway   string `json:"gateway"`
}

// DiscoverResult summarizes auto-detection changes.
type DiscoverResult struct {
	Detected []DetectedWANLink `json:"detected"`
	Created  []storage.Link    `json:"created"`
	Updated  []storage.Link    `json:"updated"`
	Existing []storage.Link    `json:"existing"`
}

var readProcNetRoute = func() ([]byte, error) {
	return os.ReadFile("/proc/net/route")
}

var listInterfaces = net.Interfaces

// NewService creates a new links Service.
func NewService(db *storage.DB) *Service {
	return &Service{db: db}
}

// List returns all links.
func (s *Service) List() ([]storage.Link, error) {
	return s.db.GetLinks()
}

// Get returns a single link by ID.
func (s *Service) Get(id string) (*storage.Link, error) {
	l, err := s.db.GetLink(id)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return l, nil
}

// Create validates and inserts a new link.
func (s *Service) Create(l *storage.Link) error {
	if err := validateLink(l); err != nil {
		return err
	}
	if l.Status == "" {
		l.Status = StatusUnknown
	}
	if l.TableID == 0 {
		// Assign next available table ID (100+)
		links, err := s.db.GetLinks()
		if err != nil {
			return err
		}
		maxTable := 100
		for _, existing := range links {
			if existing.TableID >= maxTable {
				maxTable = existing.TableID + 1
			}
		}
		l.TableID = maxTable
	}
	return s.db.CreateLink(l)
}

// Update validates and updates an existing link.
func (s *Service) Update(l *storage.Link) error {
	if err := validateLink(l); err != nil {
		return err
	}
	return s.db.UpdateLinkNonQoS(l)
}

// Delete removes a link by ID.
func (s *Service) Delete(id string) error {
	return s.db.DeleteLink(id)
}

// UpdateStatus updates the status, latency, and packet loss for a link.
func (s *Service) UpdateStatus(id, status string, latencyMs, packetLoss float64) error {
	l, err := s.db.GetLink(id)
	if err != nil {
		return err
	}
	if l == nil {
		return fmt.Errorf("link %q not found", id)
	}
	l.Status = status
	l.LatencyMs = latencyMs
	l.PacketLoss = packetLoss
	now := time.Now()
	l.LastCheck = &now
	return s.db.UpdateLinkStatus(l.ID, status, latencyMs, packetLoss, l.LastCheck)
}

// DiscoverAndSyncWANLinks auto-detects WAN interfaces and creates/updates link records.
func (s *Service) DiscoverAndSyncWANLinks() (*DiscoverResult, error) {
	detected, err := detectWANLinks()
	if err != nil {
		return nil, err
	}

	res := &DiscoverResult{Detected: detected}
	existing, err := s.db.GetLinks()
	if err != nil {
		return nil, err
	}

	byInterface := make(map[string]storage.Link, len(existing))
	for _, l := range existing {
		byInterface[l.Interface] = l
	}

	for _, d := range detected {
		if cur, ok := byInterface[d.Interface]; ok {
			changed := false
			if d.IPAddress != "" && d.IPAddress != cur.IPAddress {
				cur.IPAddress = d.IPAddress
				changed = true
			}
			if d.Gateway != "" && d.Gateway != cur.Gateway {
				cur.Gateway = d.Gateway
				changed = true
			}
			if strings.TrimSpace(cur.Name) == "" {
				cur.Name = fmt.Sprintf("WAN %s", d.Interface)
				changed = true
			}
			if changed {
				if err := s.db.UpdateLinkDiscovery(cur.ID, cur.Interface, cur.Name, cur.IPAddress, cur.Gateway); err != nil {
					return nil, err
				}
				res.Updated = append(res.Updated, cur)
			} else {
				res.Existing = append(res.Existing, cur)
			}
			continue
		}

		created := storage.Link{
			Name:         fmt.Sprintf("WAN %s", d.Interface),
			Interface:    d.Interface,
			IPAddress:    d.IPAddress,
			Gateway:      d.Gateway,
			Weight:       100,
			DNSTest:      "8.8.8.8",
			MonitorHosts: "1.1.1.1,8.8.8.8",
			Status:       StatusUnknown,
			Enabled:      true,
		}
		if err := s.Create(&created); err != nil {
			return nil, err
		}
		res.Created = append(res.Created, created)
	}

	return res, nil
}

func detectWANLinks() ([]DetectedWANLink, error) {
	buf, err := readProcNetRoute()
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/route: %w", err)
	}
	defaultRoutes, err := parseDefaultRoutes(string(buf))
	if err != nil {
		return nil, err
	}
	if len(defaultRoutes) == 0 {
		return []DetectedWANLink{}, nil
	}

	ifaces, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	links := make([]DetectedWANLink, 0, len(defaultRoutes))
	for _, iface := range ifaces {
		gw, ok := defaultRoutes[iface.Name]
		if !ok {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		links = append(links, DetectedWANLink{
			Interface: iface.Name,
			IPAddress: firstIPv4(&iface),
			Gateway:   gw,
		})
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Interface < links[j].Interface
	})
	return links, nil
}

func parseDefaultRoutes(routeTable string) (map[string]string, error) {
	routes := map[string]string{}
	lines := strings.Split(strings.TrimSpace(routeTable), "\n")
	if len(lines) <= 1 {
		return routes, nil
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		iface := fields[0]
		destinationHex := fields[1]
		gatewayHex := fields[2]

		if destinationHex != "00000000" {
			continue
		}

		gw, err := parseRouteHexIPv4(gatewayHex)
		if err != nil {
			continue
		}
		routes[iface] = gw
	}

	return routes, nil
}

func parseRouteHexIPv4(hexAddr string) (string, error) {
	v, err := strconv.ParseUint(hexAddr, 16, 32)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(v))
	return net.IP(buf).String(), nil
}

func firstIPv4(iface *net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}

// ─── Validation ──────────────────────────────────────────────────────────────

func validateLink(l *storage.Link) error {
	if strings.TrimSpace(l.Name) == "" {
		return fmt.Errorf("link name is required")
	}
	if strings.TrimSpace(l.Interface) == "" {
		return fmt.Errorf("interface is required")
	}
	if !isValidInterface(l.Interface) {
		return fmt.Errorf("invalid interface name: %q", l.Interface)
	}
	if l.IPAddress != "" && !isValidIP(l.IPAddress) {
		return fmt.Errorf("invalid IP address: %q", l.IPAddress)
	}
	if l.Gateway != "" && !isValidIP(l.Gateway) {
		return fmt.Errorf("invalid gateway address: %q", l.Gateway)
	}
	if l.Weight < 0 || l.Weight > 1000 {
		return fmt.Errorf("weight must be between 0 and 1000")
	}
	if l.DNSTest != "" && !isValidIP(l.DNSTest) && !isValidHostname(l.DNSTest) {
		return fmt.Errorf("invalid dns_test address: %q", l.DNSTest)
	}
	return nil
}

func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isValidInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}
