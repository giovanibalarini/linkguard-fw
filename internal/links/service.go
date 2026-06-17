// Package links manages WAN link configuration and state.
package links

import (
	"fmt"
	"net"
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

// Service handles link CRUD and state management.
type Service struct {
	db *storage.DB
}

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
		return nil, fmt.Errorf("link %q not found", id)
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
	return s.db.UpdateLink(l)
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
	return s.db.UpdateLink(l)
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
