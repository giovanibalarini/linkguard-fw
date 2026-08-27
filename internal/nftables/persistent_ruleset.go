package nftables

import (
	"context"
	"strings"
)

var transientDomainObjects = map[string]bool{
	"set " + DomBlockedSet + " {":  true,
	"set " + DomBlockedSet6 + " {": true,
	"map " + DomWanMap + " {":      true,
}

// PersistentRuleset devolve a tabela do LinkGuard sem os ELEMENTOS aprendidos
// de DNS. As declarações e as regras que consultam os objetos permanecem.
// Ruleset continua sendo a visão viva e não passa por esta filtragem.
func (s *Service) PersistentRuleset(ctx context.Context) (string, error) {
	live, err := s.Ruleset(ctx)
	if err != nil {
		return "", err
	}
	return stripTransientDomainElements(live), nil
}

// stripTransientDomainElements entende só a forma emitida por `nft list`:
// uma declaração `set/map nome {` e, dentro dela, `elements = { ... }`, que
// pode ocupar várias linhas. O escopo fechado por nome é intencional: elementos
// de host_wan, blocklist e objetos de terceiros continuam persistentes.
func stripTransientDomainElements(ruleset string) string {
	lines := strings.Split(ruleset, "\n")
	out := make([]string, 0, len(lines))
	inDomainObject := false
	skippingElements := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inDomainObject && transientDomainObjects[trimmed] {
			inDomainObject = true
			out = append(out, line)
			continue
		}
		if inDomainObject {
			if skippingElements {
				if strings.Contains(line, "}") {
					skippingElements = false
				}
				continue
			}
			if strings.HasPrefix(trimmed, "elements = {") {
				rest := strings.TrimPrefix(trimmed, "elements = {")
				if !strings.Contains(rest, "}") {
					skippingElements = true
				}
				continue
			}
			if trimmed == "}" {
				inDomainObject = false
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
