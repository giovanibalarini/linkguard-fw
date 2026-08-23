package routes

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// Roteamento de retorno por WAN (issue #120) — a metade de roteamento.
//
// A outra metade está em internal/nftables/connmark.go, que lembra por qual WAN
// cada conexão entrou e devolve essa lembrança à marca do pacote. O que este
// arquivo faz é dar significado à marca: uma tabela de rota por link, com o
// default daquele link, e uma `ip rule` que manda o que está marcado consultar
// aquela tabela.
//
// POR QUE A TABELA POR LINK JÁ EXISTE E MESMO ASSIM PRECISA DISTO. Cada link
// tem `table_id` desde sempre, e o failover escreve o default lá quando um link
// cai e volta. Mas numa caixa onde nenhum link caiu ainda, a tabela nunca foi
// preenchida — foi o que se viu na máquina de produção: `ip route show table
// 100` vazio, e nenhuma `ip rule` além das três do kernel. Sem preencher e sem
// a regra, a marca não muda rota nenhuma.
//
// PRIORIDADE ABAIXO DA MAIN. As regras entram em 32700+, antes da `main`
// (32766). Precisa ser antes, ou a main resolve primeiro pelo default e a marca
// não serve para nada. E precisa ser depois da `local` (0), ou o tráfego para a
// própria máquina passaria a ser roteado para fora.
const replyRulePriorityBase = 32700

// ReplyRoute é o caminho de volta de uma WAN.
type ReplyRoute struct {
	Interface string
	Gateway   string
	Table     string // table_id do link, como texto
	Mark      string // a mesma marca que o nftables grava na conexão
}

// EnsureReplyRouting popula a tabela de cada WAN e garante a `ip rule` que
// aponta para ela. Idempotente: pode rodar em todo boot e a cada mudança de
// link.
//
// Best-effort por rota: uma WAN sem gateway conhecido não impede as outras de
// serem configuradas. Falha registrada, nunca silenciosa.
func (s *Service) EnsureReplyRouting(ctx context.Context, rotas []ReplyRoute) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if len(rotas) == 0 {
		slog.Warn("roteamento de retorno: nenhuma WAN válida; nada foi configurado")
		return nil
	}

	existentes, err := s.exec.ExecuteRead(ctx, "ip", "rule", "show")
	if err != nil {
		return fmt.Errorf("ler regras de roteamento: %w", err)
	}

	var falhas []string
	for i, r := range rotas {
		if r.Table == "" || r.Mark == "" {
			continue
		}
		if r.Gateway != "" && r.Interface != "" {
			// O GATEWAY VEM DO KERNEL, E NÃO DO BANCO (issue #154).
			//
			// r.Gateway é uma cópia de storage.Link.Gateway, e o único caminho
			// que reescreve esse campo é o admin clicar em "detectar links" ou
			// editar o link à mão. Nenhum timer, nenhum boot e nenhum monitor o
			// refrescam. Troque-se o modem do provedor, ou o DHCP entregue outro
			// router: o dhclient conserta a tabela `main`, e esta função
			// continuava gravando o gateway ANTIGO na tabela do link — com
			// `onlink`, que faz o kernel aceitar sem reclamar mesmo fora da
			// sub-rede.
			//
			// O efeito é seletivo e por isso enganoso: a navegação da LAN
			// continua funcionando pela `main`, mas tudo que CHEGA por aquela
			// WAN deixa de ser respondido. É literalmente a "forma silenciosa
			// de mandar a resposta para o vazio" que o comentário abaixo diz
			// estar impedindo — impedida só para o caso em que alguém clicou.
			gw := r.Gateway
			if vivo := s.gatewayVivo(ctx, r.Interface); vivo != "" && vivo != gw {
				slog.Warn("o gateway gravado do link está desatualizado; usando o que o kernel tem",
					"interface", r.Interface, "gravado", gw, "vivo", vivo)
				gw = vivo
			}
			// `replace`, e não `add`: o gateway do link muda (DHCP do
			// provedor, troca de modem) e um `add` falharia com "File exists"
			// deixando a tabela apontando para o gateway antigo — que é uma
			// forma silenciosa de mandar a resposta para o vazio.
			if out, err := s.ReplaceRoute(ctx, "default", gw, r.Interface, r.Table); err != nil {
				falhas = append(falhas, fmt.Sprintf("tabela %s: %v (%s)", r.Table, err, strings.TrimSpace(out)))
				continue
			}
		}
		// A regra é procurada pelo par (marca, tabela) em vez de recriada: `ip
		// rule add` é aditivo e repetiria a mesma regra a cada boot, do jeito
		// que o append-only do iptables repetia regra antes da Fase 0.
		if regraPresente(existentes, r.Mark, r.Table) {
			continue
		}
		if out, err := s.AddRule(ctx, "", r.Mark, r.Table, replyRulePriorityBase+i); err != nil {
			falhas = append(falhas, fmt.Sprintf("regra marca %s → tabela %s: %v (%s)", r.Mark, r.Table, err, strings.TrimSpace(out)))
		}
	}

	if len(falhas) > 0 {
		return fmt.Errorf("%d caminho(s) de retorno não configurado(s): %s", len(falhas), strings.Join(falhas, "; "))
	}
	slog.Info("roteamento de retorno reconciliado", "wans", len(rotas))
	return nil
}

// regraPresente procura por uma linha de `ip rule show` que já ligue esta marca
// a esta tabela.
//
// O kernel imprime a marca em hexadecimal ("fwmark 0x64") mesmo quando ela foi
// adicionada em decimal, então a comparação normaliza os dois lados — sem isso
// a regra seria adicionada de novo a cada boot, uma cópia por reinício.
func regraPresente(saida, marca, tabela string) bool {
	alvos := marcasEquivalentes(marca)
	for _, linha := range strings.Split(saida, "\n") {
		if !strings.Contains(linha, "lookup "+tabela) {
			continue
		}
		for _, m := range alvos {
			if strings.Contains(linha, "fwmark "+m) {
				return true
			}
		}
	}
	return false
}

// marcasEquivalentes devolve as formas em que a mesma marca pode aparecer.
func marcasEquivalentes(marca string) []string {
	marca = strings.TrimSpace(marca)
	if marca == "" {
		return nil
	}
	out := []string{marca}
	var n uint64
	var err error
	if strings.HasPrefix(marca, "0x") || strings.HasPrefix(marca, "0X") {
		_, err = fmt.Sscanf(marca[2:], "%x", &n)
	} else {
		_, err = fmt.Sscanf(marca, "%d", &n)
	}
	if err != nil {
		return out
	}
	return append(out, fmt.Sprintf("0x%x", n), fmt.Sprintf("%d", n))
}

// ReplaceRoute substitui uma rota (idempotente, ao contrário de AddRoute).
func (s *Service) ReplaceRoute(ctx context.Context, dest, gw, iface, table string) (string, error) {
	if !validDest(dest) || !optIP(gw) || !optOK(iface, reRIface) || !optOK(table, reRTable) {
		return "", fmt.Errorf("parâmetros de rota inválidos")
	}
	args := []string{"route", "replace", dest}
	if gw != "" {
		args = append(args, "via", gw)
	}
	if iface != "" {
		args = append(args, "dev", iface, "onlink")
	}
	if table != "" {
		args = append(args, "table", table)
	}
	return s.exec.Execute(ctx, "ip", args...)
}

// gatewayVivo devolve o gateway padrão que o kernel tem AGORA naquela interface,
// ou "" quando não há (link caído, endereçamento estático sem default).
//
// Vazio não é erro: cai no valor gravado, que é o último conhecido bom. Trocar
// um gateway possivelmente velho por nenhum gateway deixaria a tabela do link
// sem rota de volta, o que é pior do que uma rota velha.
func (s *Service) gatewayVivo(ctx context.Context, iface string) string {
	if iface == "" {
		return ""
	}
	out, err := s.exec.ExecuteRead(ctx, "ip", "-4", "route", "show", "default", "dev", iface)
	if err != nil {
		return ""
	}
	return viaDaInterface(out, iface)
}

// viaDaInterface acha o gateway QUE PERTENCE à interface pedida, dentro da
// saída de `ip route show default dev <iface>`.
//
// POR QUE ISTO NÃO É "PEGAR O PRIMEIRO via". Em modo de balanceamento a default
// é uma rota multipath, e o filtro `dev` casa a rota INTEIRA quando qualquer um
// dos nexthops usa aquela interface — a saída vem com todos eles:
//
//	default
//	    nexthop via 192.168.18.1 dev lg-wan-giga weight 256 onlink
//	    nexthop via 192.168.15.1 dev lg-wan-vivo weight 110 onlink
//
// Pegar o primeiro `via` devolvia o gateway do PRIMEIRO nexthop para qualquer
// interface perguntada. Medido em produção: a tabela de retorno da WAN VIVO
// ficou com `default via 192.168.18.1 dev lg-wan-vivo` — o gateway da outra
// WAN, na interface certa, gravado com `onlink`, que faz o kernel aceitar sem
// reclamar mesmo fora da sub-rede. Tudo que CHEGA por aquela WAN deixa de ser
// respondido, e a navegação da LAN continua funcionando pela `main`: seletivo,
// silencioso, e exatamente o modo de falha que a #154 existia para impedir.
//
// A correção da #154 (ler o gateway do kernel em vez do banco) continua certa;
// o que faltava era ler o pedaço certo da resposta.
//
// Devolver "" quando não achar é deliberado: o chamador mantém o gateway do
// banco, que é o comportamento de antes da #154 e nunca é pior que um chute.
func viaDaInterface(out, iface string) string {
	campos := strings.Fields(out)
	var ultimoVia string
	for i, c := range campos {
		switch {
		case c == "via" && i+1 < len(campos):
			ultimoVia = campos[i+1]
		case c == "dev" && i+1 < len(campos) && campos[i+1] == iface:
			// O `dev` fecha o trecho: o `via` mais recente é o deste nexthop.
			return ultimoVia
		}
	}
	return ""
}
