package nftables

import (
	"context"
	"fmt"
	"strings"
)

// Contenção de tentativa repetida na borda (issue #127).
//
// O QUE ISTO RESOLVE. O login tem 2FA e limite de taxa na aplicação, mas nada
// no firewall: cada tentativa era uma conexão aceita, um handshake TLS e um
// hash de senha calculado. A defesa inteira dependia da camada de aplicação
// estar perfeita, todas as vezes.
//
// A LIÇÃO DA FASE 1 DA #119 ESTÁ NO DESENHO, E É O QUE TORNA ISTO SEGURO.
// Contenção por taxa que pega o próprio admin é tranca com outro nome — e este
// projeto já pagou por uma. Aqui o risco não é mitigado, é ELIMINADO por
// construção: a regra que ADICIONA ao set casa `iifname` das WANs, então só
// origem que chega pela internet pode ser contida. Quem entra pela LAN não pode
// ser posto no set por caminho nenhum, e por isso o descarte pode ser global sem
// perigo.
//
// `limit rate over` É UM CASAMENTO, e a direção importa: `over` casa o que
// EXCEDE a taxa (o contrário do `limit rate` usado no registro de bloqueios,
// que casa o que cabe nela). Escrever um no lugar do outro conteria exatamente
// quem se comporta.
//
// O set expira sozinho — `timeout`, sem daemon. É fail2ban sem fail2ban, e sem
// um processo a mais para morrer em silêncio.
const (
	// AbusersSet guarda quem excedeu a taxa de tentativas.
	AbusersSet = "abusers"

	// abusersTimeout é quanto tempo a origem fica contida. Uma hora é o
	// suficiente para tornar a varredura cara e curto o suficiente para um
	// falso positivo não virar chamado de suporte no dia seguinte.
	abusersTimeout = "1h"

	// abusersRate é a taxa acima da qual a origem é contida. Dez conexões novas
	// por minuto às portas de gerência é muito acima de qualquer uso humano —
	// quem digita a senha errada três vezes não chega perto — e muito abaixo do
	// que uma varredura faz.
	abusersRate = "10/minute"
)

// abusersSetSpec é a declaração do set. `dynamic` porque quem escreve nele é o
// próprio kernel, a partir da regra; `timeout` porque contenção sem prazo é
// bloqueio permanente por acidente.
const abusersSetSpec = "{ type ipv4_addr; flags dynamic,timeout; timeout " + abusersTimeout + "; }"

// EnsureAbusersSet cria o set se ele não existir.
//
// Idempotente, e chamada a cada reconciliação — não no bootstrap. É a lição da
// #119 fase 2: coisa nova que precisa existir em instalação EXISTENTE não pode
// nascer só no EnsureTable, que é no-op em máquina já provisionada. Sem isto, a
// regra que referencia o set não pode ser escrita e some em silêncio da chain.
func (s *Service) EnsureAbusersSet(ctx context.Context) error {
	if _, err := s.exec.Execute(ctx, "nft", "add", "set", Family, Table, AbusersSet,
		abusersSetSpec); err != nil {
		return fmt.Errorf("criar a set %s: %w", AbusersSet, err)
	}
	return nil
}

// abuseRules devolve o par (descarta contido, contém quem excede).
//
// A ORDEM É A DECISÃO, como na fase 1: o descarte vem ANTES da liberação das
// portas de gerência, senão o accept curto-circuita e a contenção não vale
// nada. E a regra que contém vem logo depois, para medir a taxa de quem ainda
// não está contido.
func abuseRules(wanIfaces []string, portas string) [][]string {
	if len(wanIfaces) == 0 || portas == "" {
		// Sem WAN não há de quem se defender por este caminho, e sem porta de
		// gerência não há o que medir. Emitir a regra de descarte sozinha seria
		// um set que nada alimenta — enfeite com cara de proteção.
		return nil
	}
	set := "{ " + strings.Join(quoteIfaces(wanIfaces), ", ") + " }"
	return [][]string{
		// Contido é descartado, venha de onde vier. Pode ser global porque só
		// origem vinda das WANs entra no set (regra abaixo).
		{"ip", "saddr", "@" + AbusersSet, "counter", "drop"},
		// E quem excede a taxa entra. `over` casa o EXCEDENTE.
		{"iifname", set, "tcp", "dport", portas, "ct", "state", "new",
			"limit", "rate", "over", abusersRate,
			"counter", "add", "@" + AbusersSet, "{", "ip", "saddr", "}"},
	}
}

// quoteIfaces prepara nomes de interface para o argv do nft, descartando o que
// não passa pelo mesmo guarda dos outros geradores deste pacote.
func quoteIfaces(ifaces []string) []string {
	out := make([]string, 0, len(ifaces))
	vistos := map[string]bool{}
	for _, i := range ifaces {
		if i == "" || vistos[i] || !reIface.MatchString(i) {
			continue
		}
		vistos[i] = true
		out = append(out, fmt.Sprintf("%q", i))
	}
	return out
}

// Contido é uma origem sob contenção, como a tela precisa mostrar.
type Contido struct {
	IP string `json:"ip"`
	// ExpiraEmSeg é quanto falta para a contenção acabar. Bloqueio invisível é
	// o pior tipo de suporte: quem está contido tem de aparecer, com prazo.
	ExpiraEmSeg int `json:"expira_em_seg"`
}

// Contidos lê o set e devolve quem está contido e por quanto tempo.
func (s *Service) Contidos(ctx context.Context) ([]Contido, error) {
	out, err := s.exec.ExecuteRead(ctx, "nft", "-a", "list", "set", Family, Table, AbusersSet)
	if err != nil {
		// Set ausente não é erro para a tela: é "ninguém contido". A criação
		// dela é responsabilidade da reconciliação, e um erro aqui viraria uma
		// faixa vermelha sobre uma caixa que está bem.
		return []Contido{}, nil
	}
	return parseContidos(out), nil
}

// parseContidos extrai os elementos e o prazo restante.
//
// O nft imprime `elements = { 1.2.3.4 expires 59m30s512ms, ... }`. O prazo é
// opcional na saída quando o elemento acabou de entrar.
func parseContidos(out string) []Contido {
	i := strings.Index(out, "elements = {")
	if i < 0 {
		return []Contido{}
	}
	corpo := out[i+len("elements = {"):]
	if j := strings.Index(corpo, "}"); j >= 0 {
		corpo = corpo[:j]
	}
	var res []Contido
	for _, item := range strings.Split(corpo, ",") {
		campos := strings.Fields(item)
		if len(campos) == 0 {
			continue
		}
		c := Contido{IP: campos[0]}
		for k, f := range campos {
			if f == "expires" && k+1 < len(campos) {
				c.ExpiraEmSeg = duracaoNftEmSegundos(campos[k+1])
			}
		}
		res = append(res, c)
	}
	if res == nil {
		return []Contido{}
	}
	return res
}

// duracaoNftEmSegundos traduz "59m30s512ms" em segundos.
func duracaoNftEmSegundos(s string) int {
	total, num := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			num = num*10 + int(c-'0')
		case c == 'd':
			total += num * 86400
			num = 0
		case c == 'h':
			total += num * 3600
			num = 0
		case c == 'm':
			// "ms" é milissegundo, e não minuto — somar como minuto daria um
			// prazo absurdo na tela.
			if i+1 < len(s) && s[i+1] == 's' {
				i++
			} else {
				total += num * 60
			}
			num = 0
		case c == 's':
			total += num
			num = 0
		default:
			num = 0
		}
	}
	return total
}

// Liberar tira uma origem da contenção — o botão de "foi engano" da tela.
func (s *Service) Liberar(ctx context.Context, ip string) error {
	if !validIPv4OrCIDR(ip) || strings.Contains(ip, "/") {
		return fmt.Errorf("endereço inválido: %q", ip)
	}
	if _, err := s.exec.Execute(ctx, "nft", "delete", "element", Family, Table, AbusersSet,
		"{", ip, "}"); err != nil {
		return fmt.Errorf("liberar %s: %w", ip, err)
	}
	return nil
}
