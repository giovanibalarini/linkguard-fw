package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
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

	// mssClampMinPathMTU é o piso de sanidade da MTU de caminho. Abaixo de 576
	// — o mínimo de remontagem do IPv4 — o número não é MTU de caminho nenhum:
	// é lixo, e um clamp derivado de lixo TRAVA conexão em vez de corrigi-la.
	// Trata-se como desconhecido. Ver sanitizePathMTU, em zone.go.
	mssClampMinPathMTU = 576
	// mssClampIPv4Overhead: 20 bytes de cabeçalho IP mais 20 de TCP. É o que
	// separa a MTU do MSS.
	mssClampIPv4Overhead = 40
)

// EnsureMSSClamp reconstrói a chain de ajuste a partir da lista de WANs.
func (s *Service) EnsureMSSClamp(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)
	z, err := s.zone(ifaces)
	if err != nil {
		return err
	}
	// A CHAIN É CRIADA SEMPRE, MESMO QUE NASÇA VAZIA, e isto é a correção de
	// uma desistência antiga: até aqui esta função devolvia nil ANTES do `add
	// chain` quando não havia WAN cadastrada, e o resultado era uma caixa em
	// que a mss_clamp simplesmente NÃO EXISTIA — nem vazia. Quem fosse
	// conferir o ruleset não achava a chain e não tinha como saber se a
	// feature estava desligada ou quebrada.
	//
	// Chain vazia é o estado honesto: a estrutura está montada, e não há regra
	// porque não há link cadastrado. É seguro porque a chain é `policy accept`
	// e não decide nada sozinha. (Para o registro de conversa a conclusão é a
	// OPOSTA — ver EnsureFlows.)
	if out, err := s.exec.Execute(ctx, "nft", "add", "chain", Family, Table, MSSClampChain, mssClampChainSpec); err != nil {
		return fmt.Errorf("criar chain %s: %w (%s)", MSSClampChain, err, out)
	}
	regras := mssClampRules(z)
	if len(regras) == 0 {
		slog.Warn("ajuste de MSS: a chain foi criada VAZIA",
			"motivo", motivoDeMSSClampVazia(z), "wans", ifaces)
	}
	if err := s.rebuildChain(ctx, MSSClampChain, regras); err != nil {
		return err
	}
	slog.Info("ajuste de MSS reconciliado", "wans", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("ajuste de MSS reconciliado, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// mssClampRules é a definição canônica da chain de ajuste: uma regra por WAN
// onde há várias, e UMA regra com o número da plataforma onde há uma só.
//
// `tcp flags syn / syn,rst` casa SYN e SYN-ACK e ignora RST — o MSS só é
// negociado no aperto de mão, e mexer em qualquer outro pacote seria mexer
// numa conexão já estabelecida. Vale nos dois ramos.
func mssClampRules(z Zone) [][]string {
	// A DECISÃO DE POR-LINK VEM PRIMEIRO, E É ISSO QUE PROTEGE A PRODUÇÃO.
	//
	// Enquanto este ramo for escolhido por PerLink() — e não pelo PathMTU —,
	// nenhum valor que a plataforma venha a reportar um dia pode reescrever a
	// chain mss_clamp da caixa on-prem. Hoje platform.NetFacts.PathMTU é sempre
	// 0 fora da nuvem, mas "hoje" não é garantia nenhuma; a ORDEM DOS RAMOS é.
	if z.PerLink() {
		ifaces := z.WANIfaces()
		regras := make([][]string, 0, len(ifaces))
		for _, iface := range ifaces {
			regras = append(regras, zoneRule(z.ToExternalIface(iface),
				"tcp", "flags", "syn", "/", "syn,rst",
				"counter",
				"tcp", "option", "maxseg", "size", "set", "rt", "mtu",
			))
		}
		return regras
	}

	// HAIRPIN. Um caminho só para fora, e `rt mtu` leria a MTU que a interface
	// ANUNCIA — 9000 na OCI —, não a que o caminho realmente suporta (1500).
	// O número certo agora existe: platform.Facts.Net.PathMTU chega aqui por
	// ZoneFacts.PathMTU.
	//
	// ISTO É BLOQUEANTE DE VERDADE, não cosmético. Os nós de dentro da VCN têm
	// MTU 9000 e anunciam MSS ~8960; o servidor remoto responde com pacotes
	// desse tamanho, que precisam sair por um caminho de 1500. Sem o ajuste,
	// ping e DNS funcionam e `docker pull` e `apt` PENDURAM — o sintoma mais
	// confuso de diagnosticar que existe.
	//
	// RISCO CONHECIDO E ACEITO: a regra casa TUDO que sai pela WAN, inclusive o
	// trânsito leste-oeste da própria nuvem, cujo caminho suporta 9000. Esses
	// fluxos passam a negociar 1460 — perda de vazão, não quebra. Qualificar
	// com `ip daddr != { locais }` resolveria só em parte, porque as redes
	// locais conhecidas são as da PRÓPRIA sub-rede, nunca o CIDR da nuvem
	// inteira: a sub-rede dos outros nós ficaria de fora da exceção de qualquer
	// jeito. Uma qualificação incompleta que PARECE completa é pior que a
	// ausência dela. Vira incremento próprio no dia em que a plataforma souber
	// o CIDR de cima.
	mtu := z.PathMTU()
	if mtu < mssClampMinPathMTU || len(z.WANIfaces()) == 0 {
		// DESCONHECIDO CONTINUA SENDO CHAIN VAZIA, e continua sendo a resposta
		// certa: uma regra que casa tudo e clampa para um valor inventado é
		// pior do que nenhuma, porque dá a impressão de que o ajuste está
		// feito. Quem chama avisa, com motivoDeChainVazia dizendo por quê.
		return nil
	}
	n := strconv.Itoa(mtu - mssClampIPv4Overhead)
	// ToExternal() e não ToExternalIface(): o segundo está documentado como "só
	// faz sentido com PerLink()", e usá-lo aqui contradiria o próprio contrato.
	return [][]string{zoneRule(z.ToExternal(),
		"tcp", "flags", "syn", "/", "syn,rst",
		// A GUARDA `size > N` É O QUE TORNA ISTO SEGURO EM QUALQUER KERNEL.
		// Sem ela a regra ESCREVE N em todo SYN — inclusive num que já negociou
		// 536 —, e um clamp que AUMENTA o MSS é a forma de quebrar conexão que
		// nenhum teste local pega. Com ela a regra só REDUZ, seja qual for a
		// semântica de `size set`.
		"tcp", "option", "maxseg", "size", ">", n,
		// `counter` DEPOIS da guarda e ANTES do `set`: assim ele conta
		// exatamente o que foi clampado, que é o número de que o operador
		// precisa para saber se a regra está fazendo alguma coisa.
		"counter",
		"tcp", "option", "maxseg", "size", "set", n,
	)}
}

// motivoDeMSSClampVazia explica por que ESTA chain — e não uma chain qualquer —
// nasceu sem regra.
//
// SEPARADA DE motivoDeChainVazia, e não um caso a mais dentro dela, porque a
// resposta só vale aqui. Aquela função escreve o aviso de cinco chamadores; uma
// frase sobre MTU acrescentada lá passaria a explicar também a conn_mark de uma
// VM de nuvem, que nasce vazia porque existe UM LINK SÓ para marcar e não tem
// relação nenhuma com MTU. O operador iria investigar a rede errada a partir de
// um aviso que o produto emitiu com convicção.
//
// A ORDEM É A DESTE GERADOR, não a da função genérica: mssClampRules não olha
// para os CIDRs locais, então "nenhuma rede local conhecida" nunca é o motivo
// de a mss_clamp estar vazia, por mais que seja o motivo de outras.
func motivoDeMSSClampVazia(z Zone) string {
	if z.hairpin && len(z.wanIfaces) > 0 && z.pathMTU < mssClampMinPathMTU {
		return "máquina de interface única e MTU do caminho externo desconhecida; " +
			"sem ela o ajuste de MSS usaria a MTU que a interface anuncia, que na nuvem é maior que a real"
	}
	return motivoDeChainVazia(z)
}
