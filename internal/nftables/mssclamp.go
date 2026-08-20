package nftables

import (
	"context"
	"fmt"
	"log/slog"
)

// Ajuste de MSS na saída para a WAN (issue #130).
//
// O SINTOMA, QUE É O PIOR DETALHE. Link PPPoE tem MTU 1492, não 1500. Sem
// ajuste, o cliente da LAN anuncia MSS de 1460 achando que cabe, o pacote
// grande precisa fragmentar, e o ICMP "fragmentation needed" que resolveria
// isso é frequentemente descartado no caminho pelo provedor. O resultado não é
// "não tem internet": ping funciona, DNS funciona, site pequeno abre, site
// grande trava no meio do carregamento, anexo para de subir. Parece problema do
// site. Some e volta. É das falhas de rede que mais consomem tempo de
// diagnóstico justamente porque tudo o que se testa primeiro funciona.
//
// `rt mtu` É O PONTO. A regra não carrega número nenhum: ela pega a MTU da rota
// que o pacote vai tomar. Num link de 1492 ela corrige; num link de 1500 ela
// calcula exatamente o MSS que o cliente já teria negociado. Ou seja, **é
// no-op por construção onde não há o que corrigir** — e não por acaso. É o que
// permite aplicá-la sempre, sem tela de configuração e sem perguntar ao admin
// qual é a MTU do provedor dele (que ele frequentemente não sabe).
//
// SÓ NA SAÍDA PARA A WAN. Isto ajusta o que o cliente da LAN anuncia. O que o
// servidor do outro lado anuncia depende de o PMTU dele funcionar — que é o
// comportamento padrão de qualquer roteador de borda, incluindo o que o
// OpenWrt faz. Prometer mais que isso seria prometer o que a regra não entrega.
const (
	MSSClampChain = "mss_clamp"
	// priority mangle: antes da filtragem, para que o ajuste valha inclusive
	// para o SYN que uma regra de grupo vai aceitar depois.
	mssClampChainSpec = "{ type filter hook forward priority mangle; policy accept; }"
)

// EnsureMSSClamp reconstrói a chain de ajuste a partir da lista de WANs.
func (s *Service) EnsureMSSClamp(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)
	if len(ifaces) == 0 {
		slog.Warn("ajuste de MSS: nenhuma interface WAN válida; a chain não foi reconciliada")
		return nil
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, MSSClampChain, mssClampChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", MSSClampChain, err, out)
	}
	if err := s.rebuildChain(ctx, MSSClampChain, mssClampRules(ifaces)); err != nil {
		return err
	}
	slog.Info("ajuste de MSS reconciliado", "wans", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("ajuste de MSS reconciliado, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// mssClampRules é a definição canônica: uma regra por WAN.
//
// `tcp flags syn / syn,rst` casa SYN e SYN-ACK e ignora RST — o MSS só é
// negociado no aperto de mão, e mexer em qualquer outro pacote seria mexer
// numa conexão já estabelecida.
func mssClampRules(wanIfaces []string) [][]string {
	regras := make([][]string, 0, len(wanIfaces))
	for _, iface := range wanIfaces {
		regras = append(regras, []string{
			"oifname", fmt.Sprintf("%q", iface),
			"tcp", "flags", "syn", "/", "syn,rst",
			"counter",
			"tcp", "option", "maxseg", "size", "set", "rt", "mtu",
		})
	}
	return regras
}
