// Package ddns mantém um nome de DNS apontando para o endereço público de um
// link WAN (issue #129).
//
// POR QUE ISTO É PRÉ-REQUISITO, E NÃO ENFEITE. Todo IP de WAN residencial e boa
// parte dos empresariais são dinâmicos. O encaminhamento de porta é capacidade
// entregue e visível no painel, e ele aponta para um endereço que muda sem
// aviso: quem depende dele descobre que caiu justamente quando precisa. A VPN
// (#128) nasceria com o mesmo problema.
//
// POR LINK, E NÃO POR CAIXA. Numa máquina com duas WANs são DOIS endereços que
// mudam, e o nome de cada um precisa acompanhar o seu. Publicar um serviço com
// failover exige, além disso, um nome que siga o link que está de pé — por isso
// existe também a entrada "link ativo".
//
// PROTOCOLO GENÉRICO, E NÃO UM SDK POR PROVEDOR. Praticamente todo serviço de
// DNS dinâmico aceita uma URL de atualização com o endereço embutido e, quando
// muito, autenticação básica. Um modelo de URL com {hostname} e {ip} cobre
// DuckDNS, No-IP, Cloudflare via API token e a maioria dos outros sem trazer
// nenhuma dependência nova — que num appliance de segurança é superfície de
// cadeia de suprimentos por conveniência.
package ddns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	// checkInterval é de quanto em quanto tempo o endereço público é
	// conferido. Cinco minutos: IP de provedor não muda a cada minuto, e cada
	// checagem que passa por descoberta externa é uma requisição a um terceiro.
	checkInterval = 5 * time.Minute

	// httpTimeout vale tanto para a descoberta quanto para a atualização.
	httpTimeout = 15 * time.Second
)

// Config é o que o admin configura para um link.
type Config struct {
	LinkID string `json:"link_id"`
	// Enabled desliga sem apagar o que foi configurado.
	Enabled bool `json:"enabled"`
	// Hostname é o nome que deve apontar para este link.
	Hostname string `json:"hostname"`
	// URLTemplate é o endereço de atualização do provedor, com {hostname} e
	// {ip} onde eles entram.
	URLTemplate string `json:"url_template"`
	// Username é a autenticação básica, quando o provedor usa. A senha/token
	// vive em internal/secrets e NUNCA aqui — este struct vai para o painel.
	Username string `json:"username"`
}

// State é o que aconteceu na última tentativa. Guardado para a tela poder
// dizer "está funcionando" com evidência, em vez de só repetir a configuração.
type State struct {
	LinkID string `json:"link_id"`
	// PublicIP é o endereço visto por último.
	PublicIP string `json:"public_ip"`
	// BehindNAT diz que o endereço da interface NÃO é o público — o link está
	// atrás de NAT do provedor (CGNAT). É informação cara de descobrir sozinho
	// e que muda o que o admin pode esperar: atrás de CGNAT, encaminhamento de
	// porta não funciona de jeito nenhum, e o DDNS continua útil só para
	// alcançar a caixa por VPN de saída.
	BehindNAT bool   `json:"behind_nat"`
	UpdatedAt int64  `json:"updated_at"`
	LastError string `json:"last_error"`
}

// Provider descobre o endereço público de um link.
type Provider interface {
	PublicIP(ctx context.Context, sourceIP string) (netip.Addr, error)
}

// httpProvider descobre o endereço perguntando a um serviço externo, com a
// requisição AMARRADA ao endereço de origem do link.
//
// A amarração é o ponto: sem ela, a consulta sairia pela rota default e
// devolveria o endereço da OUTRA WAN — o nome do link secundário passaria a
// apontar para o link principal, e ninguém notaria até tentar usar.
type httpProvider struct{ endpoint string }

// NewHTTPProvider cria o descobridor. endpoint deve devolver o endereço em
// texto puro (api.ipify.org, checkip.amazonaws.com e similares).
func NewHTTPProvider(endpoint string) Provider { return &httpProvider{endpoint: endpoint} }

func (p *httpProvider) PublicIP(ctx context.Context, sourceIP string) (netip.Addr, error) {
	dialer := &net.Dialer{Timeout: httpTimeout}
	if sourceIP != "" {
		ip, err := netip.ParseAddr(sourceIP)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("endereço de origem inválido: %w", err)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(ip.AsSlice())}
	}
	cli := &http.Client{
		Timeout:   httpTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	corpo, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(string(corpo)))
}

// IsPrivate diz se o endereço não pode ser o público do link — RFC1918,
// loopback, link-local ou o espaço de CGNAT (100.64.0.0/10, RFC 6598).
//
// O CGNAT é o caso que engana: 100.64.x.x parece endereço normal e roteável, e
// é exatamente o que o provedor entrega quando NÃO dá endereço público. Sem
// reconhecê-lo, o produto anunciaria no DNS um endereço que ninguém alcança.
func IsPrivate(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate() || a.IsUnspecified() {
		return true
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return cgnat.Contains(a)
}

// BuildURL põe o nome e o endereço no modelo do provedor.
//
// Erro em vez de URL pela metade quando falta {ip}: um modelo sem o lugar do
// endereço atualizaria o nome para o IP de quem CHAMA (é o que a maioria dos
// provedores faz por padrão) — e como a chamada sai amarrada ao link, na
// maioria das vezes daria certo por acidente e falharia em silêncio quando não
// desse. Melhor recusar e dizer.
func BuildURL(modelo, hostname string, ip netip.Addr) (string, error) {
	if strings.TrimSpace(modelo) == "" {
		return "", fmt.Errorf("modelo de URL vazio")
	}
	if !strings.Contains(modelo, "{ip}") {
		return "", fmt.Errorf("o modelo precisa conter {ip}")
	}
	u := strings.ReplaceAll(modelo, "{hostname}", hostname)
	u = strings.ReplaceAll(u, "{ip}", ip.String())
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return "", fmt.Errorf("o modelo precisa começar com http:// ou https://")
	}
	return u, nil
}

// Updater executa a atualização no provedor.
type Updater struct {
	// SecretFor devolve a senha/token do link. Função, e não valor, porque o
	// segredo é lido no momento do uso — nunca guardado nesta struct, que
	// atravessa camadas e acaba em log de depuração.
	SecretFor func(linkID string) (string, error)
}

// Update avisa o provedor do endereço novo, amarrando a requisição ao link
// pelo mesmo motivo da descoberta: uma atualização que sai pela outra WAN
// registraria o endereço errado.
func (u *Updater) Update(ctx context.Context, cfg Config, sourceIP string, ip netip.Addr) error {
	alvo, err := BuildURL(cfg.URLTemplate, cfg.Hostname, ip)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: httpTimeout}
	if sourceIP != "" {
		if addr, err := netip.ParseAddr(sourceIP); err == nil {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(addr.AsSlice())}
		}
	}
	cli := &http.Client{Timeout: httpTimeout, Transport: &http.Transport{DialContext: dialer.DialContext}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alvo, nil)
	if err != nil {
		return err
	}
	if cfg.Username != "" && u.SecretFor != nil {
		senha, err := u.SecretFor(cfg.LinkID)
		if err != nil {
			return fmt.Errorf("ler o segredo do provedor: %w", err)
		}
		req.SetBasicAuth(cfg.Username, senha)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	corpo, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	texto := strings.TrimSpace(string(corpo))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provedor respondeu %d: %s", resp.StatusCode, resumo(texto))
	}
	// HTTP 200 NÃO basta: DuckDNS, No-IP e a maioria respondem 200 com o erro
	// no corpo ("KO", "nohost", "badauth"). Aceitar o 200 e parar aí faria o
	// painel dizer "atualizado" para um nome que continua apontando para o
	// endereço velho — e o admin só descobriria tentando alcançar a caixa.
	if erro := erroNoCorpo(texto); erro != "" {
		return fmt.Errorf("provedor recusou: %s", erro)
	}
	return nil
}

// erroNoCorpo reconhece as respostas de erro que os provedores mandam com
// status 200. Lista fechada e minúscula: o que não está aqui é tratado como
// sucesso, porque inventar erro a partir de texto desconhecido seria pior —
// a atualização teria funcionado e o painel diria que não.
func erroNoCorpo(texto string) string {
	t := strings.ToLower(strings.TrimSpace(texto))
	for _, ruim := range []string{"badauth", "nohost", "notfqdn", "abuse", "!donator", "911", "dnserr"} {
		if t == ruim || strings.HasPrefix(t, ruim+" ") {
			return t
		}
	}
	// DuckDNS responde exatamente "KO" quando recusa.
	if t == "ko" {
		return "KO"
	}
	return ""
}

func resumo(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) > 120 {
		return s[:120] + "…"
	}
	if s == "" {
		return "(sem corpo)"
	}
	return s
}
