package platform

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── IMDS de mentira ─────────────────────────────────────────────────────────

// fixture lê um corpo de resposta gravado a partir do IMDS da instância real.
func fixture(t *testing.T, nome string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", nome))
	if err != nil {
		t.Fatalf("ler a fixture %s: %v", nome, err)
	}
	return b
}

// clienteIMDS sobe um IMDS de mentira e devolve o cliente e a base.
//
// O cliente é o de PRODUÇÃO (newIMDSClient), e não srv.Client(): são os
// timeouts e o Proxy nil dele que precisam estar sob teste, não os do
// httptest.
func clienteIMDS(t *testing.T, h http.Handler) (*http.Client, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return newIMDSClient(), srv.URL
}

// imdsDaInstanciaReal responde exatamente o que a VM medida responde, e
// registra os cabeçalhos recebidos para o teste poder afirmar sobre eles.
type imdsDaInstanciaReal struct {
	t          *testing.T
	auth       map[string]string // caminho -> Authorization recebido
	statusV2   int               // != 0 substitui a resposta de /opc/v2/instance/
	statusVNIC int               // != 0 substitui a resposta de /opc/v2/vnics/
	statusCert int               // 0 vale 200
	corpoV2    []byte            // != nil substitui o corpo da instância v2
	semShape   bool
}

func (s *imdsDaInstanciaReal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		s.auth = map[string]string{}
	}
	s.auth[r.URL.Path] = r.Header.Get("Authorization")

	// Um IMDS que recusa a v2 recusa a v2 INTEIRA — é o que uma imagem antiga
	// faz. Responder as VNICs da v2 a quem levou 401 na instância da v2 é o
	// que fazia o teste do fallback passar sem que um único caminho da v1
	// fosse usado.
	if s.statusV2 != 0 && strings.HasPrefix(r.URL.Path, "/opc/v2/") {
		w.WriteHeader(s.statusV2)
		return
	}

	switch r.URL.Path {
	case imdsInstancePathV2, imdsInstancePathV1:
		w.Write(s.instancia(s.t))
	case imdsVNICsPathV2, imdsVNICsPathV1:
		if s.statusVNIC != 0 {
			w.WriteHeader(s.statusVNIC)
			return
		}
		w.Write(fixture(s.t, "vnics_v2.json"))
	case imdsCertPathV2, imdsCertPathV1:
		st := s.statusCert
		if st == 0 {
			st = http.StatusOK
		}
		w.WriteHeader(st)
		if st == http.StatusOK {
			w.Write([]byte("-----BEGIN CERTIFICATE-----\nnao-guardamos-isto\n-----END CERTIFICATE-----\n"))
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// pedido diz se um caminho chegou a ser requisitado. Existe porque
// auth[caminho] devolve "" tanto para "não mandou cabeçalho" quanto para
// "nunca foi pedido", e afirmar sobre a segunda achando que é a primeira é
// como um teste de fallback passa sem exercitar o fallback.
func (s *imdsDaInstanciaReal) pedido(path string) bool {
	_, ok := s.auth[path]
	return ok
}

func (s *imdsDaInstanciaReal) instancia(t *testing.T) []byte {
	if s.corpoV2 != nil {
		return s.corpoV2
	}
	if s.semShape {
		return []byte(`{"id":"ocid1.instance.oc1.sa-saopaulo-1.antxeljrgbtechbastionexampleuniqueid",
			"canonicalRegionName":"sa-saopaulo-1","shape":"VM.Standard.E2.1.Micro"}`)
	}
	return fixture(t, "instance_v2.json")
}

// envComIMDS devolve um ambiente on-prem cujo IMDS é o servidor dado.
func envComIMDS(t *testing.T, h http.Handler) Env {
	t.Helper()
	env := maquinaOnPrem(t)
	env.HTTP, env.IMDSBase = clienteIMDS(t, h)
	return env
}

// ─── os fatos medidos ────────────────────────────────────────────────────────

func TestIMDSv2ComBearerDevolveOsFatosMedidos(t *testing.T) {
	imds := &imdsDaInstanciaReal{t: t}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, imds))
	if err != nil {
		t.Fatalf("queryIMDS: %v", err)
	}

	// A v2 exige o cabeçalho: sem ele o IMDS responde 401 e a detecção
	// silenciosamente cairia na v1 (ou em nada).
	if got := imds.auth[imdsInstancePathV2]; got != "Bearer Oracle" {
		t.Errorf("Authorization em %s = %q, esperado %q", imdsInstancePathV2, got, "Bearer Oracle")
	}
	if got := imds.auth[imdsVNICsPathV2]; got != "Bearer Oracle" {
		t.Errorf("Authorization em %s = %q, esperado %q", imdsVNICsPathV2, got, "Bearer Oracle")
	}

	// Campo a campo contra a instância real (gbtech-bastion, GRU).
	casos := []struct {
		campo string
		got   any
		want  any
	}{
		{"Region", facts.Region, "sa-saopaulo-1"},
		{"RegionKey", facts.RegionKey, "GRU"},
		{"RealmKey", facts.RealmKey, "oc1"},
		{"AvailabilityDomain", facts.AvailabilityDomain, "Wgnm:SA-SAOPAULO-1-AD-1"},
		{"DisplayName", facts.DisplayName, "gbtech-bastion"},
		{"Shape", facts.Shape, "VM.Standard.E2.1.Micro"},
		{"OCPUs", facts.OCPUs, 1.0},
		{"MemoryGB", facts.MemoryGB, 1.0},
		{"BandwidthGbps", facts.BandwidthGbps, 0.48},
		{"MaxVNICAttachments", facts.MaxVNICAttachments, 1},
		{"AlwaysFree", facts.AlwaysFree, true},
		{"InstancePrincipal", facts.InstancePrincipal, true},
		{"IMDSVersion", facts.IMDSVersion, 2},
	}
	for _, c := range casos {
		if c.got != c.want {
			t.Errorf("%s = %v, esperado %v", c.campo, c.got, c.want)
		}
	}
	if facts.InstanceOCID == "" || facts.CompartmentOCID == "" || facts.TenancyOCID == "" {
		t.Errorf("um dos OCIDs veio vazio: %+v", facts)
	}

	if len(facts.VNICs) != 1 {
		t.Fatalf("VNICs = %d, esperado 1", len(facts.VNICs))
	}
	v := facts.VNICs[0]
	// O IMDS manda o MAC MAIÚSCULO; sem canonizar, o casamento com a
	// interface de kernel (que sai minúscula) nunca aconteceria.
	if v.MAC != "02:00:17:0a:19:30" {
		t.Errorf("MAC da VNIC = %q, esperado a grafia canônica minúscula", v.MAC)
	}
	if v.PrivateIP != "10.0.0.10" || v.SubnetCIDR != "10.0.0.0/24" || v.VirtualRouterIP != "10.0.0.1" || v.VLANTag != 1531 {
		t.Errorf("a VNIC não bate com o que foi medido: %+v", v)
	}
}

func TestMACDaVNICSaiNaGrafiaDoKernel(t *testing.T) {
	// O casamento VNIC->interface é por string. validate.NormalizeMAC sozinha
	// não basta e o doc dela diz por quê: ela aceita "aa-bb-cc-dd-ee-ff" e
	// "aabb.ccdd.eeff" e só passa para minúsculas, mantendo a pontuação de
	// origem. Se o provedor mandasse uma dessas, o MAC passaria na validação,
	// não casaria com interface nenhuma, e o campo Interface ficaria vazio sem
	// um único erro (issue #161).
	casos := map[string]string{
		"02:00:17:0A:19:30":   "02:00:17:0a:19:30", // o que a instância real manda
		"02:00:17:0a:19:30":   "02:00:17:0a:19:30",
		"02-00-17-0A-19-30":   "02:00:17:0a:19:30",
		"0200.170a.1930":      "02:00:17:0a:19:30",
		" 02:00:17:0A:19:30 ": "02:00:17:0a:19:30",
		"nao-e-um-mac":        "nao-e-um-mac", // volta como veio, para a tela mostrar
	}
	for entrada, esperado := range casos {
		if got := normalizeVNICMAC(entrada); got != esperado {
			t.Errorf("normalizeVNICMAC(%q) = %q, esperado %q", entrada, got, esperado)
		}
	}
}

func TestIMDSv2Com401CaiParaV1SemHeader(t *testing.T) {
	imds := &imdsDaInstanciaReal{t: t, statusV2: http.StatusUnauthorized}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, imds))
	if err != nil {
		t.Fatalf("queryIMDS não caiu para a v1: %v", err)
	}
	if facts.IMDSVersion != 1 {
		t.Errorf("IMDSVersion = %d, esperado 1", facts.IMDSVersion)
	}
	// A v1 NÃO exige o cabeçalho, e mandá-lo é o que faz algumas imagens
	// antigas recusarem a requisição.
	if got := imds.auth[imdsInstancePathV1]; got != "" {
		t.Errorf("a v1 recebeu Authorization %q; ela não pede cabeçalho", got)
	}
	// E o fallback vale para as três requisições, não só para a primeira:
	// perguntar as VNICs (ou a credencial) na v2 a um IMDS que já recusou a v2
	// devolve 404 e vira "esta máquina não tem", numa máquina que tem.
	for _, caminho := range []string{imdsVNICsPathV1, imdsCertPathV1} {
		if !imds.pedido(caminho) {
			t.Errorf("%s nunca foi pedido: o fallback parou na primeira requisição", caminho)
		}
		if got := imds.auth[caminho]; got != "" {
			t.Errorf("%s recebeu Authorization %q; a v1 não pede cabeçalho", caminho, got)
		}
	}
	if len(facts.VNICs) != 1 {
		t.Errorf("o fallback da v1 não trouxe as VNICs: %+v", facts.VNICs)
	}
	if !facts.InstancePrincipal {
		t.Error("a credencial de instância sumiu no fallback da v1 — foi perguntada no caminho da v2")
	}
}

func TestIMDSQueRecusaAsDuasVersoesNaoEhOCI(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := queryIMDS(context.Background(), envComIMDS(t, h)); err == nil {
		t.Error("um IMDS que respondeu 404 nas duas versões virou OCI")
	}
}

// ─── o gate de sanidade ──────────────────────────────────────────────────────

func TestIMDSQueRespondeJSONDeOutroProvedorNaoEhOCI(t *testing.T) {
	// Numa rede on-prem o 169.254.0.0/16 pode estar roteado para um appliance
	// qualquer, e um proxy pode devolver uma página de erro com status 200. Um
	// corpo sem OCID de instância e sem região canônica NÃO é uma instância
	// OCI, por mais que tenha respondido.
	corpos := map[string]string{
		"outro provedor":      `{"instanceId":"i-0abc123","region":"us-east-1","instanceType":"t3.micro"}`,
		"sem região":          `{"id":"ocid1.instance.oc1.sa-saopaulo-1.abc"}`,
		"sem ocid":            `{"canonicalRegionName":"sa-saopaulo-1","shape":"VM.Standard.E2.1.Micro"}`,
		"ocid de outra coisa": `{"id":"ocid1.volume.oc1.sa-saopaulo-1.abc","canonicalRegionName":"sa-saopaulo-1"}`,
		"página de erro":      `{"error":"not found"}`,
	}
	for nome, corpo := range corpos {
		imds := &imdsDaInstanciaReal{t: t, corpoV2: []byte(corpo)}
		if _, err := queryIMDS(context.Background(), envComIMDS(t, imds)); err == nil {
			t.Errorf("%s passou pelo gate de sanidade", nome)
		}
	}
}

func TestIMDSComJSONMalformadoNaoEhOCI(t *testing.T) {
	imds := &imdsDaInstanciaReal{t: t, corpoV2: []byte(`{"id":"ocid1.instance.oc1.`)}
	if _, err := queryIMDS(context.Background(), envComIMDS(t, imds)); err == nil {
		t.Error("um corpo truncado virou OCI")
	}
}

func TestCampoComTipoInesperadoNaoDerrubaOVereditoOCI(t *testing.T) {
	// O provedor trocar o tipo de um campo não pode declarar on-prem uma
	// máquina comprovadamente OCI: o gate é o que manda, o resto é bônus.
	corpo := `{"id":"ocid1.instance.oc1.sa-saopaulo-1.abc","canonicalRegionName":"sa-saopaulo-1",
		"shape":"VM.Standard.E2.1.Micro","shapeConfig":{"maxVnicAttachments":"1","ocpus":1.0}}`
	imds := &imdsDaInstanciaReal{t: t, corpoV2: []byte(corpo)}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, imds))
	if err != nil {
		t.Fatalf("um campo de tipo trocado derrubou o veredito: %v", err)
	}
	// E o campo que não pôde ser lido fica DESCONHECIDO, não restritivo.
	if facts.MaxVNICAttachments != 0 {
		t.Errorf("MaxVNICAttachments = %d, esperado 0 (desconhecido)", facts.MaxVNICAttachments)
	}
	if !DeriveCapabilities(Facts{Kind: KindOCI, OCI: facts}).MultiWAN {
		t.Error("um campo ilegível desligou multi-WAN")
	}
}

func TestMaxVnicAttachmentsAusenteMantemMultiWAN(t *testing.T) {
	imds := &imdsDaInstanciaReal{t: t, semShape: true}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, imds))
	if err != nil {
		t.Fatalf("queryIMDS: %v", err)
	}
	if facts.MaxVNICAttachments != 0 {
		t.Errorf("MaxVNICAttachments = %d, esperado 0 (desconhecido)", facts.MaxVNICAttachments)
	}
	if c := DeriveCapabilities(Facts{Kind: KindOCI, OCI: facts}); !c.MultiWAN || !c.LinkFailover {
		t.Errorf("shapeConfig ausente virou restrição: %+v", c)
	}
}

// ─── o que não derruba o veredito ────────────────────────────────────────────

func TestVNICsComFalhaNaoDerrubamOVereditoOCI(t *testing.T) {
	imds := &imdsDaInstanciaReal{t: t, statusVNIC: http.StatusInternalServerError}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, imds))
	if err != nil {
		t.Fatalf("a falha ao listar VNICs derrubou o veredito: %v", err)
	}
	if len(facts.VNICs) != 0 {
		t.Errorf("VNICs = %+v, esperado vazio", facts.VNICs)
	}
	if facts.Region != "sa-saopaulo-1" {
		t.Errorf("os fatos da instância se perderam junto com as VNICs: %+v", facts)
	}
}

func TestCertPem200LigaInstancePrincipal(t *testing.T) {
	ligado := &imdsDaInstanciaReal{t: t, statusCert: http.StatusOK}
	facts, err := queryIMDS(context.Background(), envComIMDS(t, ligado))
	if err != nil {
		t.Fatalf("queryIMDS: %v", err)
	}
	if !facts.InstancePrincipal {
		t.Error("cert.pem respondeu 200 e a capacidade não subiu")
	}

	desligado := &imdsDaInstanciaReal{t: t, statusCert: http.StatusNotFound}
	facts, err = queryIMDS(context.Background(), envComIMDS(t, desligado))
	if err != nil {
		t.Fatalf("queryIMDS: %v", err)
	}
	if facts.InstancePrincipal {
		t.Error("cert.pem respondeu 404 e a capacidade ficou ligada")
	}
}

// ─── orçamento ───────────────────────────────────────────────────────────────

func TestIMDSQueNaoRespondeDevolveOnPremDentroDoOrcamento(t *testing.T) {
	// Servidor fechado antes da consulta: é o que acontece numa caixa on-prem
	// cujo sinal local foi falso positivo.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close()

	env := maquinaOnPrem(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), base

	inicio := time.Now()
	if _, err := queryIMDS(context.Background(), env); err == nil {
		t.Error("um IMDS que não respondeu virou OCI")
	}
	if gasto := time.Since(inicio); gasto >= DetectBudget {
		t.Errorf("a sondagem gastou %s, acima do orçamento de %s", gasto, DetectBudget)
	}
}

// imdsQueNuncaResponde aceita a conexão e nunca devolve corpo. O handler só
// sai quando a requisição é cancelada, para o httptest.Server fechar na hora
// em vez de segurar o teste até o fim do sono.
func imdsQueNuncaResponde(t *testing.T) string {
	t.Helper()
	liberar := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-liberar:
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(func() { close(liberar); srv.Close() })
	return srv.URL
}

func TestIMDSLentoParaNoTimeoutDoProprioCliente(t *testing.T) {
	// SEM prazo no contexto, de propósito: o que está sob teste aqui é o
	// http.Client.Timeout de newIMDSClient. Ele é a segunda tranca — a
	// primeira é o orçamento que Detect põe no contexto —, e sem ela uma
	// máquina cujo IMDS aceita a conexão e emudece seguraria o boot pelo tempo
	// que o outro lado quisesse.
	env := maquinaOnPrem(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), imdsQueNuncaResponde(t)

	inicio := time.Now()
	if _, err := queryIMDS(context.Background(), env); err == nil {
		t.Error("um IMDS que não respondeu nunca virou OCI")
	}
	if gasto := time.Since(inicio); gasto >= DetectBudget {
		t.Errorf("a sondagem gastou %s sem prazo no contexto; o cliente tem que se cortar sozinho em %s",
			gasto, imdsRequestTimeout)
	}
}

func TestOPrazoDoContextoCortaASondagem(t *testing.T) {
	// A outra metade: o prazo que vem no contexto TEM que chegar na
	// requisição. É ele que faz as três requisições juntas caberem em
	// DetectBudget, e é ele que o cancelamento do boot usa. Sem
	// NewRequestWithContext nada disto acontece e o único limite passa a ser o
	// timeout por requisição do cliente — que os outros testes não conseguem
	// distinguir, porque os dois cortam o mesmo caso.
	env := maquinaOnPrem(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), imdsQueNuncaResponde(t)

	const prazo = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), prazo)
	defer cancel()

	inicio := time.Now()
	if _, err := queryIMDS(ctx, env); err == nil {
		t.Error("um IMDS que não respondeu nunca virou OCI")
	}
	// Folga generosa para não ficar frágil em CI carregado, e ainda bem abaixo
	// do timeout por requisição: só passa se o prazo do contexto tiver valido.
	if gasto := time.Since(inicio); gasto >= imdsRequestTimeout/2 {
		t.Errorf("a sondagem gastou %s com um prazo de %s no contexto; o contexto não chegou na requisição",
			gasto, prazo)
	}
}

func TestOClienteDoIMDSIgnoraProxyERecusaRedirecionamento(t *testing.T) {
	// Estas duas decisões não dá para provar de ponta a ponta, e é por isso
	// que elas são afirmadas aqui sobre o cliente em si:
	//
	//   - Proxy: http.ProxyFromEnvironment NUNCA usa proxy para endereço de
	//     loopback, que é onde todo httptest.Server mora, e além disso lê o
	//     ambiente uma vez por processo. Um teste com t.Setenv("HTTP_PROXY")
	//     batendo num httptest passa com Proxy nil e passa igual com
	//     ProxyFromEnvironment: ele não mede nada. O que importa é a decisão —
	//     o serviço roda pelo systemd e pode herdar HTTP_PROXY da máquina, e
	//     uma requisição ao 169.254.169.254 que sai para um proxy fala com
	//     qualquer coisa menos com o IMDS.
	//
	//   - Timeout do cliente e prazo de dial: o teto de cada requisição.
	cli := newIMDSClient()

	tr, ok := cli.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("o transporte do cliente do IMDS deixou de ser *http.Transport: %T", cli.Transport)
	}
	if tr.Proxy != nil {
		t.Error("o cliente do IMDS voltou a usar proxy: uma consulta ao link-local que sai pelo HTTP_PROXY da máquina não fala com o IMDS")
	}
	if tr.DialContext == nil {
		t.Error("o cliente do IMDS ficou sem DialContext: o prazo de dial é o que corta uma rede que não responde")
	}
	if cli.Timeout != imdsRequestTimeout {
		t.Errorf("Timeout do cliente = %s, esperado %s", cli.Timeout, imdsRequestTimeout)
	}
	if cli.CheckRedirect == nil {
		t.Fatal("o cliente do IMDS voltou a seguir redirecionamento")
	}
}

func TestRedirecionamentoDoIMDSNaoEhSeguido(t *testing.T) {
	// Um 30x no 169.254.169.254 é sinal de que quem respondeu não é o IMDS.
	// Seguir o salto levaria a sondagem para fora do link-local — e, como o
	// destino aqui devolve um documento de instância PERFEITAMENTE válido,
	// seguir o salto também classificaria esta máquina como uma OCI.
	pedidoNoDestino := false
	destino := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pedidoNoDestino = true
		w.Write(fixture(t, "instance_v2.json"))
	}))
	t.Cleanup(destino.Close)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destino.URL+r.URL.Path, http.StatusFound)
	})

	if _, err := queryIMDS(context.Background(), envComIMDS(t, h)); err == nil {
		t.Error("um 30x virou OCI: a sondagem seguiu o salto para fora do link-local")
	}
	if pedidoNoDestino {
		t.Error("a sondagem saiu do endereço do IMDS atrás de um redirecionamento")
	}
}

func TestCorpoGiganteDoIMDSTemTeto(t *testing.T) {
	// Quem responde no 169.254.169.254 de uma rede on-prem pode ser qualquer
	// coisa, inclusive algo que transmite sem parar. O corpo é lido com teto, e
	// este teste é o que impede alguém de "simplificar" para io.ReadAll.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bloco := strings.Repeat("A", 64<<10)
		for i := 0; i < 64; i++ { // 4 MB, oito vezes o teto
			if _, err := fmt.Fprint(w, bloco); err != nil {
				return
			}
		}
	})
	env := maquinaOnPrem(t)
	env.HTTP, env.IMDSBase = clienteIMDS(t, h)

	_, body, err := imdsGet(context.Background(), env, imdsInstancePathV2, true)
	if err != nil {
		t.Fatalf("imdsGet: %v", err)
	}
	if len(body) != imdsMaxBody {
		t.Errorf("corpo lido = %d bytes, esperado o teto de %d", len(body), imdsMaxBody)
	}
}
