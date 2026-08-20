package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

// Contabilidade de tráfego por host, no próprio nftables (issue #112).
//
// O QUE ISTO SUBSTITUI, E POR QUÊ. O consumo por host era lido de
// /proc/net/nf_conntrack, que só contém conexão VIVA: quando a conexão fecha e
// o kernel a remove, os bytes dela evaporam. O painel chamava aquilo de "top
// consumidores", mas o que mostrava era "quem tem conexão aberta gorda neste
// segundo" — o host que baixou 5 GB às 14h aparecia com zero às 14h05, e todo
// o tráfego web (mil conexões curtas) era sistematicamente subcontado enquanto
// um download longo aparecia inteiro. Número errado exibido com cara de certo.
//
// COMO FUNCIONA AGORA. Dois sets dinâmicos com `counter`: o kernel mantém
// bytes e pacotes por endereço, sem varrer nada, e conexão fechada não zera o
// contador. A leitura é um `nft list set`, não uma varredura linear de dezenas
// de milhares de linhas a cada consulta do painel.
//
// A CHAIN É SEPARADA, E ISSO É O PONTO DE SEGURANÇA. A contabilidade vive numa
// base chain própria em `hook forward priority filter + 10`, e não dentro das
// chains de filtragem. Duas consequências, as duas desejadas:
//
//   - nenhuma regra de filtro é tocada por esta feature. O ruleset que decide
//     o que passa continua exatamente o que era;
//   - ela conta o que REALMENTE passou. Um `drop` numa chain de prioridade
//     menor encerra a travessia do pacote, então ele nunca chega aqui.
//     Medido na VM (2026-08-20): com um destino descartado pela chain de
//     filtro, o endereço não aparece no set; com um destino liberado, aparece
//     com `counter packets 4 bytes 440`.
//
// POR QUE ESCOPADO POR INTERFACE, E NÃO POR FAIXA DE REDE. As regras usam
// `iifname !=` / `oifname !=` a lista de WANs em vez de um CIDR de LAN. O
// motivo é o tamanho do set: sem escopo, `ip saddr` de tráfego de entrada
// criaria um elemento para CADA endereço da internet que responde, enchendo o
// set (65.535 elementos) em minutos. Escopando pelo que NÃO é WAN, só entra
// endereço local. E a lista de WANs o produto já conhece — é a mesma que
// alimenta o masquerade.
const (
	// AcctChain é a base chain de contabilidade.
	AcctChain = "acct"
	// AcctUpSet conta por endereço de ORIGEM: o que o host da LAN enviou.
	AcctUpSet = "acct_up"
	// AcctDownSet conta por endereço de DESTINO: o que chegou ao host da LAN.
	AcctDownSet = "acct_down"

	// acctSetSpec é a definição dos dois sets. `timeout 1d` faz o host que
	// sumiu da rede sair sozinho, em vez de o set crescer para sempre; o
	// contador de quem continua falando é renovado a cada pacote.
	acctSetSpec = "{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1d; counter; }"

	// acctChainSpec põe a chain DEPOIS da filtragem (priority filter + 10),
	// que é o que faz ela contar só o que passou.
	acctChainSpec = "{ type filter hook forward priority filter + 10; policy accept; }"
)

// HostCounter é o acumulado de um endereço, direto do kernel.
type HostCounter struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

// reCounterElement casa um elemento de set com contador, na forma que o nft
// imprime: "10.0.2.2 counter packets 4 bytes 440 expires 59m59s988ms".
// Deliberadamente indiferente a quebras de linha e à parte do `expires`, que
// muda a cada leitura.
var reCounterElement = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3}) counter packets (\d+) bytes (\d+)`)

// EnsureAccounting cria os sets e a chain de contabilidade e reconstrói as
// regras dela a partir da definição canônica — a cada boot, como
// ReconcileMasquerade e ReconcileStructuralChains, e pelo mesmo motivo: uma
// máquina já provisionada nunca passa pelo EnsureTable, então sem isto ela
// jamais ganharia a contabilidade.
//
// `add set` e `add chain` são idempotentes no nft (verificado na VM), então
// esta função é segura de chamar em todo boot, em máquina nova ou antiga. As
// REGRAS não são idempotentes — por isso a chain é limpa e reescrita, o mesmo
// flush-e-reescreve de rebuildChain. Limpar a chain não zera os sets: os
// contadores sobrevivem à reconciliação.
func (s *Service) EnsureAccounting(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)
	if len(ifaces) == 0 {
		// Sem saber quais interfaces são WAN não há como distinguir host local
		// de endereço da internet, e contar tudo encheria o set. Mesma decisão
		// do ReconcileMasquerade diante de uma fonte vazia: não agir é mais
		// seguro do que agir errado.
		slog.Warn("contabilidade por host: nenhuma interface WAN configurada; a chain não foi reconciliada",
			"solicitado", wanInterfaces)
		return nil
	}

	for _, set := range []string{AcctUpSet, AcctDownSet} {
		if out, err := s.exec.Execute(ctx, "nft", "add", "set", Family, Table, set, acctSetSpec); err != nil {
			return fmt.Errorf("criar set %s: %w (%s)", set, err, strings.TrimSpace(out))
		}
	}
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, AcctChain, acctChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", AcctChain, err, strings.TrimSpace(out))
	}

	if err := s.rebuildChain(ctx, AcctChain, acctChainRules(ifaces)); err != nil {
		return err
	}
	slog.Info("contabilidade por host reconciliada", "wans", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("contabilidade por host reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// acctChainRules é a definição canônica da chain — a única fonte do que ela
// contém, do mesmo jeito que markHostsChainRules é para a mark_hosts.
func acctChainRules(wanIfaces []string) [][]string {
	quoted := make([]string, len(wanIfaces))
	for i, iface := range wanIfaces {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	set := "{ " + strings.Join(quoted, ", ") + " }"
	return [][]string{
		// Saiu de um host local em direção à WAN: upload dele.
		{"iifname", "!=", set, "update", "@" + AcctUpSet, "{", "ip", "saddr", "}"},
		// Vai para um host local: download dele.
		{"oifname", "!=", set, "update", "@" + AcctDownSet, "{", "ip", "daddr", "}"},
	}
}

// HostCounters lê os dois sets e devolve o acumulado por endereço.
//
// Erro é propagado em vez de virar mapa vazio: mapa vazio é indistinguível de
// "ninguém trafegou", e essa é exatamente a confusão que a issue #112 existe
// para acabar. Quem chama decide como dizer "não sei" ao admin.
func (s *Service) HostCounters(ctx context.Context) (map[string]HostCounter, error) {
	up, err := s.readCounterSet(ctx, AcctUpSet)
	if err != nil {
		return nil, err
	}
	down, err := s.readCounterSet(ctx, AcctDownSet)
	if err != nil {
		return nil, err
	}

	out := make(map[string]HostCounter, len(up)+len(down))
	for ip, c := range up {
		h := out[ip]
		h.TxBytes, h.TxPackets = c.bytes, c.packets
		out[ip] = h
	}
	for ip, c := range down {
		h := out[ip]
		h.RxBytes, h.RxPackets = c.bytes, c.packets
		out[ip] = h
	}
	return out, nil
}

type rawCounter struct{ packets, bytes uint64 }

func (s *Service) readCounterSet(ctx context.Context, set string) (map[string]rawCounter, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "list", "set", Family, Table, set)
	if err != nil {
		return nil, fmt.Errorf("ler set %s: %w", set, err)
	}
	return parseCounterSet(out), nil
}

// parseCounterSet extrai os elementos de um `nft list set`. Set vazio não traz
// a linha `elements =` nenhuma, e o resultado é um mapa vazio — que é a
// resposta certa: ninguém trafegou ainda.
func parseCounterSet(out string) map[string]rawCounter {
	res := map[string]rawCounter{}
	for _, m := range reCounterElement.FindAllStringSubmatch(out, -1) {
		pkts, _ := strconv.ParseUint(m[2], 10, 64)
		bytes, _ := strconv.ParseUint(m[3], 10, 64)
		res[m[1]] = rawCounter{packets: pkts, bytes: bytes}
	}
	return res
}
