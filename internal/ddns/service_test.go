package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

type segredoFalso struct{ valor string }

func (s segredoFalso) Get(string) (string, error) { return s.valor, nil }

func novoDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func novoServico(t *testing.T, db *storage.DB, ipDaInterface string) *Service {
	t.Helper()
	return NewService(db, segredoFalso{"tok"}, func(context.Context, string) string { return ipDaInterface })
}

func TestSaveConfigValidaOModeloNaHora(t *testing.T) {
	// O erro tem de aparecer enquanto o admin está na tela — não daqui a cinco
	// minutos, num log que ele não está lendo.
	s := novoServico(t, novoDB(t), "200.1.2.3")
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: "https://x/?host={hostname}"}); err == nil {
		t.Error("modelo sem {ip} foi aceito ao salvar")
	}
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, URLTemplate: "https://x/?ip={ip}"}); err == nil {
		t.Error("configuração ligada sem hostname foi aceita")
	}
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: "https://x/?h={hostname}&ip={ip}"}); err != nil {
		t.Errorf("configuração válida recusada: %v", err)
	}
}

func TestConfigDesligadaNaoPrecisaSerValida(t *testing.T) {
	// Desligar não pode exigir consertar o que está sendo desligado.
	s := novoServico(t, novoDB(t), "200.1.2.3")
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: false}); err != nil {
		t.Errorf("configuração desligada recusada: %v", err)
	}
}

func TestAtualizaQuandoOEnderecoMuda(t *testing.T) {
	var chamadas int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chamadas++
		w.Write([]byte("good"))
	}))
	defer srv.Close()

	db := novoDB(t)
	// IPAddress é o endereço a que a requisição é AMARRADA; 127.0.0.1 é o que
	// esta máquina tem. O endereço "público" do link vem do ifaceIP abaixo.
	if err := db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "wan1", IPAddress: "127.0.0.1", Enabled: true, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	s := novoServico(t, db, "200.1.2.3")
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: srv.URL + "/?h={hostname}&ip={ip}"}); err != nil {
		t.Fatal(err)
	}

	s.CheckOnce(context.Background())
	if chamadas != 1 {
		t.Fatalf("primeira passada: %d chamadas, queria 1", chamadas)
	}

	// Segunda passada com o MESMO endereço não pode incomodar o provedor:
	// vários tratam atualização repetida como abuso e bloqueiam a conta.
	s.CheckOnce(context.Background())
	if chamadas != 1 {
		t.Errorf("endereço inalterado gerou %d chamadas", chamadas)
	}

	// Endereço novo: atualiza de novo.
	s.ifaceIP = func(context.Context, string) string { return "200.9.9.9" }
	s.CheckOnce(context.Background())
	if chamadas != 2 {
		t.Errorf("endereço novo gerou %d chamadas no total, queria 2", chamadas)
	}
}

func TestFalhaDoProvedorFicaRegistradaEEhTentadaDeNovo(t *testing.T) {
	// Erro registrado sem nova tentativa deixaria o nome errado até o endereço
	// mudar outra vez — que pode ser semanas.
	var chamadas int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chamadas++
		w.Write([]byte("badauth"))
	}))
	defer srv.Close()

	db := novoDB(t)
	db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "wan1", IPAddress: "127.0.0.1", Enabled: true, Weight: 1})
	s := novoServico(t, db, "200.1.2.3")
	s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}"})

	s.CheckOnce(context.Background())
	estados, _ := s.States()
	if estados["l1"].LastError == "" {
		t.Error("a falha do provedor não foi registrada")
	}
	s.CheckOnce(context.Background())
	if chamadas != 2 {
		t.Errorf("depois de falhar, não tentou de novo: %d chamadas", chamadas)
	}
}

func TestEnderecoPublicoNaInterfaceNaoConsultaTerceiro(t *testing.T) {
	// Quando o endereço da interface já é público, não há por que perguntar a
	// ninguém: é mais rápido, não conta a um terceiro que esta máquina existe,
	// e não depende de o serviço externo estar de pé.
	var consultado bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		consultado = true
		w.Write([]byte("1.2.3.4"))
	}))
	defer srv.Close()

	s := novoServico(t, novoDB(t), "200.1.2.3")
	s.provider = NewHTTPProvider(srv.URL)
	ip, atras, err := s.enderecoPublico(context.Background(), "wan1")
	if err != nil {
		t.Fatalf("enderecoPublico: %v", err)
	}
	if consultado {
		t.Error("consultou serviço externo com endereço público na interface")
	}
	if atras || ip.String() != "200.1.2.3" {
		t.Errorf("resultado: %v atrasNAT=%v", ip, atras)
	}
}

func TestCGNATEhDetectadoEDescobertoPorFora(t *testing.T) {
	s := novoServico(t, novoDB(t), "100.64.5.5") // CGNAT
	// Provider de mentira: amarrar a requisição a 100.64.5.5 é o comportamento
	// certo em produção e impossível nesta máquina, que não tem esse endereço.
	s.provider = providerFalso{ip: "200.9.9.9"}
	ip, atras, err := s.enderecoPublico(context.Background(), "wan1")
	if err != nil {
		t.Fatalf("enderecoPublico: %v", err)
	}
	if !atras {
		t.Error("CGNAT não foi reconhecido como estar atrás de NAT")
	}
	if ip.String() != "200.9.9.9" {
		t.Errorf("endereço público = %v", ip)
	}
}

func TestFalhaDeDescobertaPreservaOUltimoEnderecoConhecido(t *testing.T) {
	// Apagar o endereço numa falha momentânea de rede faria a tela dizer "sem
	// endereço" enquanto o nome continua apontando para um endereço válido.
	db := novoDB(t)
	db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "wan1", IPAddress: "10.0.0.2", Enabled: true, Weight: 1})
	s := novoServico(t, db, "10.0.0.2")
	s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: "https://x/?ip={ip}"})
	s.saveState(State{LinkID: "l1", PublicIP: "200.1.2.3", UpdatedAt: time.Now().Unix()})

	// Provedor de descoberta inalcançável.
	s.provider = NewHTTPProvider("http://127.0.0.1:1")
	s.CheckOnce(context.Background())

	estados, _ := s.States()
	if estados["l1"].PublicIP != "200.1.2.3" {
		t.Errorf("o último endereço conhecido foi perdido: %+v", estados["l1"])
	}
	if estados["l1"].LastError == "" {
		t.Error("a falha não foi registrada")
	}
}

type providerFalso struct {
	ip  string
	err error
}

func (p providerFalso) PublicIP(context.Context, string) (netip.Addr, error) {
	if p.err != nil {
		return netip.Addr{}, p.err
	}
	return netip.ParseAddr(p.ip)
}

func TestSemConseguirAmarrarAoLinkFalhaEmVezDeChutar(t *testing.T) {
	// Se a consulta não puder sair PELO link, a resposta pode ser o endereço
	// da outra WAN — e publicar isso no DNS apontaria o nome para o link
	// errado, em silêncio. Falhar é a resposta certa.
	//
	// Acontece de verdade quando o endereço gravado do link ficou velho (o
	// DHCP do provedor trocou) — e é justamente quando o nome mais precisa ser
	// corrigido, então o erro precisa aparecer.
	db := novoDB(t)
	db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "wan1",
		IPAddress: "203.0.113.77", Enabled: true, Weight: 1}) // não existe nesta máquina
	s := novoServico(t, db, "200.1.2.3")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("o provedor foi chamado apesar de não ser possível amarrar ao link")
	}))
	defer srv.Close()
	s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "casa", URLTemplate: srv.URL + "/?ip={ip}"})
	s.CheckOnce(context.Background())

	estados, _ := s.States()
	if estados["l1"].LastError == "" {
		t.Error("a impossibilidade de amarrar ao link não foi registrada")
	}
}

func TestTrocarAConfiguracaoRepublicaMesmoComOMesmoEndereco(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE. A verificação pula o provedor quando o
	// endereço não mudou — proteção contra as contas que os provedores bloqueiam
	// por atualização repetida. Só que "não mudou" era sobre o ENDEREÇO, e o
	// admin que corrige o nome errado não muda endereço nenhum: o nome novo
	// ficaria sem ser publicado até o provedor trocar o IP, o que pode levar
	// semanas. Mexer na configuração tem de republicar.
	var nomes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomes = append(nomes, r.URL.Query().Get("h"))
		w.Write([]byte("good"))
	}))
	defer srv.Close()

	db := novoDB(t)
	if err := db.CreateLink(&storage.Link{ID: "l1", Name: "WAN1", Interface: "wan1", IPAddress: "127.0.0.1", Enabled: true, Weight: 1}); err != nil {
		t.Fatal(err)
	}
	s := novoServico(t, db, "200.1.2.3")
	modelo := srv.URL + "/?h={hostname}&ip={ip}"

	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "errado.exemplo.org", URLTemplate: modelo}); err != nil {
		t.Fatal(err)
	}
	s.CheckOnce(context.Background())

	// Mesmo endereço, nome corrigido.
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "certo.exemplo.org", URLTemplate: modelo}); err != nil {
		t.Fatal(err)
	}
	s.CheckOnce(context.Background())

	if len(nomes) != 2 || nomes[1] != "certo.exemplo.org" {
		t.Fatalf("nomes publicados: %v; queria o corrigido na segunda passada", nomes)
	}

	// E salvar sem mexer em nada continua não incomodando o provedor.
	if err := s.SaveConfig(Config{LinkID: "l1", Enabled: true, Hostname: "certo.exemplo.org", URLTemplate: modelo}); err != nil {
		t.Fatal(err)
	}
	s.CheckOnce(context.Background())
	if len(nomes) != 2 {
		t.Errorf("salvar a mesma configuração republicou: %v", nomes)
	}
}

func TestClearStateDeUmLinkNaoMexeNoOutro(t *testing.T) {
	db := novoDB(t)
	s := novoServico(t, db, "200.1.2.3")
	s.saveState(State{LinkID: "l1", PublicIP: "200.1.2.3"})
	s.saveState(State{LinkID: "l2", PublicIP: "200.4.5.6"})

	s.ClearState("l1")

	estados, err := s.States()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := estados["l1"]; ok {
		t.Error("o estado do link mexido sobreviveu")
	}
	if estados["l2"].PublicIP != "200.4.5.6" {
		t.Errorf("o estado do outro link foi afetado: %+v", estados["l2"])
	}
}
