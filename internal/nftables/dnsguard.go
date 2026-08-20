package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// Fechar a fuga de DNS (issue #124).
//
// O PROBLEMA. A blocklist de DNS do painel age no resolver da própria caixa
// (`local-zone` do unbound). Nada obriga ninguém a usá-lo: basta configurar
// 8.8.8.8 no aparelho e a lista inteira deixa de existir. Celular e navegador
// modernos ainda usam DoH por padrão, que sai como HTTPS comum na 443, e DoT na
// 853 passa livre. O resultado é uma capacidade que o painel oferece e que não
// vale exatamente para o aparelho que o admin quer conter — a "confiança falsa"
// que a Regra de Entrega do FEATURES.md chama de pior que não ter.
//
// O QUE ISTO FAZ, E O QUE NÃO FAZ. Duas medidas, as duas desligadas por padrão:
//
//   - redirecionar a porta 53 da LAN para o resolver local, de modo que quem
//     insiste em 8.8.8.8 seja atendido pela caixa. É transparente: o cliente
//     não percebe e nada quebra;
//   - recusar DoT (853) com RST, para o cliente cair de volta em DNS comum
//     rápido, em vez de ficar pendurado até o timeout.
//
// **DoH em servidor não listado, com IP fixo, continua passando** — e sempre
// vai, porque é HTTPS na 443 e indistinguível do resto. Isto REDUZ contorno;
// não elimina. O controle que não se contorna é o de destino no firewall
// (#123), não o de DNS. A tela diz isso com todas as letras: sem essa frase, a
// feature vira a mesma confiança falsa que ela existe para corrigir.
//
// EXCEÇÃO POR HOST existe porque quem roda resolver próprio na LAN de propósito
// (um Pi-hole, um servidor de teste) seria quebrado pelo redirecionamento sem
// entender por quê.
const (
	// DNSRedirectChain é NAT: captura a consulta e a entrega ao resolver local.
	DNSRedirectChain = "dns_redirect"
	// DNSGuardChain é filtro: recusa os transportes alternativos.
	DNSGuardChain = "dns_guard"

	// dstnat + 10 põe o redirecionamento DEPOIS do encaminhamento de porta:
	// um admin que publicou um DNS próprio por DNAT continua mandando nele.
	dnsRedirectChainSpec = "{ type nat hook prerouting priority dstnat + 10; policy accept; }"
	// filter - 10 põe a recusa ANTES das regras do admin, como os bloqueios
	// administrativos da Fase C1: é enforcement, não preferência.
	dnsGuardChainSpec = "{ type filter hook forward priority filter - 10; policy accept; }"
)

// DNSGuardConfig é o que a tela de DNS controla.
type DNSGuardConfig struct {
	// ForceLocal redireciona a porta 53 da LAN para o resolver local.
	ForceLocal bool
	// BlockDoT recusa DNS sobre TLS (853).
	BlockDoT bool
	// LANInterface é de onde vem a consulta a ser capturada.
	LANInterface string
	// Resolver é o endereço do resolver local (normalmente o próprio firewall).
	Resolver string
	// ExceptIPs são hosts que ficam de fora — quem roda resolver próprio.
	ExceptIPs []string
}

// EnsureDNSGuard reconstrói as duas chains a partir da configuração.
//
// Sempre reconstrói, inclusive quando tudo está desligado: é assim que desligar
// no painel realmente desliga. Uma versão que só acrescentasse regras deixaria
// o redirecionamento vivo depois de o admin desmarcar a caixa — e ele não teria
// como saber.
func (s *Service) EnsureDNSGuard(ctx context.Context, cfg DNSGuardConfig) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, DNSRedirectChain, dnsRedirectChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", DNSRedirectChain, err, out)
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, DNSGuardChain, dnsGuardChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", DNSGuardChain, err, out)
	}
	if err := s.rebuildChain(ctx, DNSRedirectChain, dnsRedirectRules(cfg)); err != nil {
		return err
	}
	if err := s.rebuildChain(ctx, DNSGuardChain, dnsGuardRules(cfg)); err != nil {
		return err
	}
	slog.Info("controle de fuga de DNS reconciliado",
		"redireciona", cfg.ForceLocal, "recusa_dot", cfg.BlockDoT, "excecoes", len(cfg.ExceptIPs))

	if err := s.Persist(ctx); err != nil {
		slog.Warn("controle de DNS reconciliado, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// dnsRedirectRules devolve as regras de captura da porta 53 — vazio quando
// desligado, ou quando falta o que é indispensável para capturar (interface da
// LAN e endereço do resolver).
func dnsRedirectRules(cfg DNSGuardConfig) [][]string {
	if !cfg.ForceLocal {
		return nil
	}
	iface, ok := dnsIface(cfg.LANInterface)
	if !ok {
		return nil
	}
	if net.ParseIP(cfg.Resolver) == nil || net.ParseIP(cfg.Resolver).To4() == nil {
		return nil
	}
	alvo := cfg.Resolver + ":53"
	regras := make([][]string, 0, 2)
	for _, proto := range []string{"udp", "tcp"} {
		r := []string{"iifname", iface}
		r = append(r, excecaoTokens(cfg.ExceptIPs)...)
		r = append(r, proto, "dport", "53", "counter", "dnat", "ip", "to", alvo)
		regras = append(regras, r)
	}
	return regras
}

// dnsGuardRules devolve a recusa de DoT.
//
// `reject with tcp reset`, e não `drop`: descartado em silêncio deixa o cliente
// pendurado até o timeout antes de tentar DNS comum, e o usuário sente isso
// como "a internet está lenta". O RST faz a queda ser imediata.
func dnsGuardRules(cfg DNSGuardConfig) [][]string {
	if !cfg.BlockDoT {
		return nil
	}
	iface, ok := dnsIface(cfg.LANInterface)
	if !ok {
		return nil
	}
	r := []string{"iifname", iface}
	r = append(r, excecaoTokens(cfg.ExceptIPs)...)
	return [][]string{append(r, "tcp", "dport", "853", "counter", "reject", "with", "tcp", "reset")}
}

// excecaoTokens monta o `ip saddr != { ... }` dos hosts isentos. Lista vazia
// devolve nada — e não um set vazio, que o nft recusa.
func excecaoTokens(ips []string) []string {
	limpos := make([]string, 0, len(ips))
	vistos := map[string]bool{}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil || vistos[ip] {
			continue
		}
		vistos[ip] = true
		limpos = append(limpos, ip)
	}
	if len(limpos) == 0 {
		return nil
	}
	return []string{"ip", "saddr", "!=", "{ " + strings.Join(limpos, ", ") + " }"}
}

func dnsIface(name string) (string, bool) {
	if len(sanitizeInterfaces([]string{name})) == 0 {
		return "", false
	}
	return fmt.Sprintf("%q", name), true
}
