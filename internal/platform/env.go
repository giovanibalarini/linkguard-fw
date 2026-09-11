package platform

import (
	"net"
	"net/http"
	"os"
	"time"
)

// defaultIMDSBase é o link-local do serviço de metadados. Mesmo endereço em
// todos os provedores; o que muda é o caminho e o cabeçalho.
const defaultIMDSBase = "http://169.254.169.254"

// Orçamentos da camada de rede. Ver DetectBudget, em detect.go, para o teto de
// tudo.
const (
	imdsDialTimeout    = 500 * time.Millisecond
	imdsRequestTimeout = 1 * time.Second // por requisição
)

// Env é tudo o que a detecção lê de FORA do processo, num lugar só.
//
// Struct de funções e não interface: cada teste troca UMA sonda e herda o
// resto de RealEnv, em vez de implementar seis métodos para exercitar uma.
// Mesma razão dos campos agora/validade de hostflows.Servico.
//
// Nenhum destes campos é um executor de comando, e isso é a regra do pacote e
// não um acaso da implementação — ver o cabeçalho de platform.go.
type Env struct {
	ReadFile   func(name string) ([]byte, error)
	Exists     func(name string) bool
	Interfaces func() ([]net.Interface, error)
	HTTP       *http.Client
	IMDSBase   string // defaultIMDSBase em produção
	Now        func() time.Time
}

// RealEnv é a máquina de verdade.
func RealEnv() Env {
	return Env{
		ReadFile:   os.ReadFile,
		Exists:     func(name string) bool { _, err := os.Stat(name); return err == nil },
		Interfaces: net.Interfaces,
		HTTP:       newIMDSClient(),
		IMDSBase:   defaultIMDSBase,
		Now:        time.Now,
	}
}

// withDefaults completa os campos vazios com a sonda real.
//
// Existe porque SetEnv recebe um struct montado do lado de fora: um campo
// esquecido viraria nil-deref no CAMINHO DE BOOT do produto, que é o pior
// lugar possível para um panic. Um teste que quer provar "não tocou a rede"
// continua provando, porque ele passa um HTTP explícito — o padrão só entra
// onde o chamador não disse nada.
func (e Env) withDefaults() Env {
	real := RealEnv()
	if e.ReadFile == nil {
		e.ReadFile = real.ReadFile
	}
	if e.Exists == nil {
		e.Exists = real.Exists
	}
	if e.Interfaces == nil {
		e.Interfaces = real.Interfaces
	}
	if e.HTTP == nil {
		e.HTTP = real.HTTP
	}
	if e.IMDSBase == "" {
		e.IMDSBase = real.IMDSBase
	}
	if e.Now == nil {
		e.Now = real.Now
	}
	return e
}

// newIMDSClient monta o cliente do serviço de metadados.
//
// PROXY NIL, E NÃO http.ProxyFromEnvironment (o padrão do http.DefaultTransport).
// O serviço roda pelo systemd e pode herdar HTTP_PROXY do ambiente da máquina:
// com o padrão, a requisição ao 169.254.169.254 sairia para o proxy — que
// responde qualquer coisa, ou nada, e em nenhum dos dois casos é o IMDS.
// Link-local nunca passa por proxy, e NO_PROXY não serve de defesa porque
// depende de o operador tê-lo configurado.
func newIMDSClient() *http.Client {
	return &http.Client{
		Timeout: imdsRequestTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: imdsDialTimeout}).DialContext,
			ResponseHeaderTimeout: imdsRequestTimeout,
			// Três requisições seguidas para o mesmo host: keep-alive vale.
			MaxIdleConns:    1,
			IdleConnTimeout: 2 * time.Second,
		},
		// Uma resposta do IMDS não redireciona. Um 30x aqui é sinal de que
		// quem respondeu não é o IMDS — seguir o salto levaria a sondagem
		// para fora do link-local, que é justamente o que não pode acontecer.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
