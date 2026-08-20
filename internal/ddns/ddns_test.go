package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIsPrivateReconheceCGNAT(t *testing.T) {
	// 100.64.x.x é o caso que engana: parece endereço normal e roteável, e é
	// exatamente o que o provedor entrega quando NÃO dá endereço público. Sem
	// reconhecê-lo, o produto anunciaria no DNS um endereço que ninguém
	// alcança.
	casos := map[string]bool{
		"100.64.0.1":      true, // CGNAT (RFC 6598)
		"100.127.255.254": true, // ainda CGNAT
		"192.168.3.1":     true,
		"10.0.0.1":        true,
		"172.16.0.1":      true,
		"127.0.0.1":       true,
		"169.254.1.1":     true,
		"100.128.0.1":     false, // logo depois da faixa: é público
		"8.8.8.8":         false,
		"200.1.2.3":       false,
	}
	for ip, querido := range casos {
		if got := IsPrivate(netip.MustParseAddr(ip)); got != querido {
			t.Errorf("IsPrivate(%s) = %v, queria %v", ip, got, querido)
		}
	}
}

func TestBuildURL(t *testing.T) {
	ip := netip.MustParseAddr("200.1.2.3")
	got, err := BuildURL("https://www.duckdns.org/update?domains={hostname}&ip={ip}", "casa", ip)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if got != "https://www.duckdns.org/update?domains=casa&ip=200.1.2.3" {
		t.Errorf("URL montada: %q", got)
	}
}

func TestBuildURLExigeOLugarDoEndereco(t *testing.T) {
	// Modelo sem {ip} atualizaria o nome para o IP de QUEM CHAMA, que é o
	// padrão da maioria dos provedores. Como a chamada sai amarrada ao link,
	// daria certo por acidente na maioria das vezes e falharia em silêncio
	// quando não desse.
	if _, err := BuildURL("https://exemplo/update?host={hostname}", "casa", netip.MustParseAddr("200.1.2.3")); err == nil {
		t.Error("modelo sem {ip} foi aceito")
	}
}

func TestBuildURLRecusaModeloQueNaoEhURL(t *testing.T) {
	casos := []string{"", "duckdns.org/update?ip={ip}", "ftp://x/{ip}"}
	for _, m := range casos {
		if _, err := BuildURL(m, "casa", netip.MustParseAddr("200.1.2.3")); err == nil {
			t.Errorf("modelo %q foi aceito", m)
		}
	}
}

func TestPublicIPLeORetornoDoServico(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("200.1.2.3\n"))
	}))
	defer srv.Close()

	got, err := NewHTTPProvider(srv.URL).PublicIP(context.Background(), "")
	if err != nil {
		t.Fatalf("PublicIP: %v", err)
	}
	if got.String() != "200.1.2.3" {
		t.Errorf("endereço = %v", got)
	}
}

func TestPublicIPRecusaRespostaQueNaoEhEndereco(t *testing.T) {
	// Serviço fora do ar costuma devolver página de erro em HTML. Aceitar isso
	// como endereço faria o produto tentar publicar lixo no DNS.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	defer srv.Close()
	if _, err := NewHTTPProvider(srv.URL).PublicIP(context.Background(), ""); err == nil {
		t.Error("resposta em HTML foi aceita como endereço")
	}
}

func TestUpdateChamaOProvedorComOEnderecoNovo(t *testing.T) {
	var recebida string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recebida = r.URL.String()
		w.Write([]byte("good 200.1.2.3"))
	}))
	defer srv.Close()

	u := &Updater{}
	err := u.Update(context.Background(), Config{
		Hostname: "casa", URLTemplate: srv.URL + "/update?host={hostname}&ip={ip}",
	}, "", netip.MustParseAddr("200.1.2.3"))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !strings.Contains(recebida, "host=casa") || !strings.Contains(recebida, "ip=200.1.2.3") {
		t.Errorf("URL recebida pelo provedor: %q", recebida)
	}
}

func TestUpdateNaoAceitaErroEscondidoEmHTTP200(t *testing.T) {
	// DuckDNS, No-IP e a maioria respondem 200 com o erro no corpo. Parar no
	// status faria o painel dizer "atualizado" para um nome que continua
	// apontando para o endereço velho.
	for _, corpo := range []string{"KO", "badauth", "nohost", "notfqdn", "abuse"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(corpo))
		}))
		u := &Updater{}
		err := u.Update(context.Background(), Config{
			Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}",
		}, "", netip.MustParseAddr("200.1.2.3"))
		srv.Close()
		if err == nil {
			t.Errorf("corpo %q com status 200 passou como sucesso", corpo)
		}
	}
}

func TestUpdateAceitaRespostaDesconhecidaComoSucesso(t *testing.T) {
	// A lista de erros é fechada de propósito: inventar erro a partir de texto
	// desconhecido faria o painel dizer que falhou uma atualização que
	// funcionou.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":"ok","id":"abc"}`))
	}))
	defer srv.Close()
	u := &Updater{}
	if err := u.Update(context.Background(), Config{
		Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}",
	}, "", netip.MustParseAddr("200.1.2.3")); err != nil {
		t.Errorf("resposta desconhecida virou erro: %v", err)
	}
}

func TestUpdateMandaAutenticacaoQuandoHaUsuario(t *testing.T) {
	var usuario, senha string
	var tinha bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usuario, senha, tinha = r.BasicAuth()
		w.Write([]byte("good"))
	}))
	defer srv.Close()

	u := &Updater{SecretFor: func(string) (string, error) { return "s3nh4", nil }}
	err := u.Update(context.Background(), Config{
		LinkID: "l1", Username: "eu", Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}",
	}, "", netip.MustParseAddr("200.1.2.3"))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !tinha || usuario != "eu" || senha != "s3nh4" {
		t.Errorf("autenticação: %v %q %q", tinha, usuario, senha)
	}
}

func TestUpdatePropagaErroDoProvedor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("credenciais inválidas"))
	}))
	defer srv.Close()
	u := &Updater{}
	err := u.Update(context.Background(), Config{Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}"},
		"", netip.MustParseAddr("200.1.2.3"))
	if err == nil {
		t.Fatal("status 401 passou como sucesso")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("o erro não diz o status: %v", err)
	}
}
