// This file: Fase A da nomeação estável de interface — ver
// docs/superpowers/specs/2026-08-10-networkd-cutover-and-fase3-design.md §3.
// Escopo desta fase: só interfaces físicas com Role == RoleWAN. Membro de
// bridge LAN fica de fora — participação em bridge ainda não é um conceito
// de primeira classe no modelo (chega na Fase C), então não há um jeito
// confiável de saber "este membro deveria ter nome estável" sem inferir a
// partir do estado vivo do kernel, o que essa fase evita de propósito.
package netif

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/netif/networkd"
)

// maxIfaceName is IFNAMSIZ-1, o limite rígido do kernel Linux pro nome de
// uma interface de rede. Todo nome gerado por esta fase tem que caber aqui,
// sempre — não existe truncamento "silencioso" aceitável, o kernel rejeita
// (ou trunca de um jeito imprevisível) um rename além disso.
const maxIfaceName = 15

// StableNameEntry is one physical WAN interface eligible for a persistent,
// MAC-matched kernel name.
type StableNameEntry struct {
	Interface  string `json:"interface"`
	MAC        string `json:"mac"`
	LinkName   string `json:"link_name"`
	StableName string `json:"stable_name"`
}

// StableNames previews the stable name every eligible interface would get,
// without writing anything.
func (s *Service) StableNames(ctx context.Context) ([]StableNameEntry, error) {
	views, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	wanLinkNames, err := s.wanLinkNamesByInterface()
	if err != nil {
		return nil, err
	}
	return stableNameEntries(views, wanLinkNames), nil
}

// ApplyStableNames writes the .link file for every eligible interface.
// Best-effort per file: one failure doesn't block the rest — every error is
// joined and returned so the caller can report exactly which interfaces
// didn't get a stable name, while the ones that succeeded still take
// effect after the next reboot (this never applies live — see
// networkd.WriteLinkFile).
func (s *Service) ApplyStableNames(ctx context.Context) ([]StableNameEntry, error) {
	entries, err := s.StableNames(ctx)
	if err != nil {
		return nil, err
	}
	var errs []error
	desired := make(map[string]bool, len(entries))
	for _, e := range entries {
		f := networkd.RenderLink(e.MAC, e.StableName, s.networkDir)
		desired[f.Path] = true
		if err := networkd.WriteLinkFile(s.exec, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Interface, err))
		}
	}
	errs = append(errs, s.pruneOrphanedLinkFiles(desired)...)
	return entries, errors.Join(errs...)
}

// pruneOrphanedLinkFiles removes previously-written, LinkGuard-managed
// .link files that are no longer in the desired set — e.g. after a Link is
// renamed (old stable name's file would otherwise linger and race the new
// one for which name wins after reboot, since systemd applies whichever
// .link file matching a MAC sorts first) or deleted entirely. Only ever
// touches files carrying the "# managed by linkguard" header, never an
// unrelated file that happens to match the glob. Best-effort: one removal
// failure doesn't stop the rest.
func (s *Service) pruneOrphanedLinkFiles(desired map[string]bool) []error {
	dir := networkd.ResolveNetworkDir(s.networkDir)
	matches, err := filepath.Glob(filepath.Join(dir, "10-lg-*.link"))
	if err != nil {
		return []error{fmt.Errorf("listar .link files em %s: %w", dir, err)}
	}
	var errs []error
	for _, path := range matches {
		if desired[path] {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("ler %s: %w", path, err))
			}
			continue
		}
		if !strings.Contains(string(content), "# managed by linkguard") {
			continue
		}
		if err := networkd.RemoveLinkFile(s.exec, path); err != nil {
			errs = append(errs, fmt.Errorf("remover %s: %w", path, err))
		}
	}
	return errs
}

func (s *Service) wanLinkNamesByInterface() (map[string]string, error) {
	linksList, err := s.linkSvc.List()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	out := make(map[string]string, len(linksList))
	for _, l := range linksList {
		out[l.Interface] = l.Name
	}
	return out, nil
}

// stableNameEntries computes, but does not write, the stable name for every
// eligible interface — shared by StableNames and ApplyStableNames.
func stableNameEntries(views []IfaceView, wanLinkNames map[string]string) []StableNameEntry {
	seen := make(map[string]bool, len(views))
	var entries []StableNameEntry
	for _, v := range views {
		if v.Kind != KindPhysical || v.Role != RoleWAN || v.Live.MAC == "" {
			continue
		}
		linkName, ok := wanLinkNames[v.Name]
		if !ok {
			continue
		}
		stable := stableIfaceName(linkName, v.Live.MAC, seen)
		seen[stable] = true
		entries = append(entries, StableNameEntry{
			Interface:  v.Name,
			MAC:        v.Live.MAC,
			LinkName:   linkName,
			StableName: stable,
		})
	}
	return entries
}

// stableIfaceName derives a kernel-safe, human-readable interface name from
// a link's admin-chosen name — "WAN VIVO" -> "lg-wan-vivo" — truncated to
// fit maxIfaceName, and disambiguated against seen (already-assigned names
// in this batch) by appending a short MAC-derived suffix on collision.
func stableIfaceName(linkName, mac string, seen map[string]bool) string {
	const prefix = "lg-"
	slug := slugify(linkName)
	budget := maxIfaceName - len(prefix)
	if len(slug) > budget {
		slug = slug[:budget]
	}
	name := prefix + slug
	if !seen[name] {
		return name
	}
	suffix := strings.ReplaceAll(mac, ":", "")
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	budget = maxIfaceName - len(prefix) - len(suffix) - 1
	if budget < 0 {
		budget = 0
	}
	if len(slug) > budget {
		slug = slug[:budget]
	}
	return prefix + slug + "-" + suffix
}

// slugify converts a human-chosen name into a lowercase, hyphen-separated
// token safe for a systemd/kernel interface name.
func slugify(s string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}
