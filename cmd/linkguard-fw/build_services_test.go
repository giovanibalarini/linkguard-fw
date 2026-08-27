package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/config"
	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Este arquivo é o que a issue #24 pede por último: uma afirmação sobre a
// MONTAGEM DE PRODUÇÃO que não é sobre o texto de main.go.
//
// A diferença para as duas redes que já existem no pacote:
//
//   - boot_order_test.go lê a árvore sintática. Ele pega a linha REMOVIDA, mas
//     não a linha trocada por outra que compila igual;
//   - boot_wiring_runtime_test.go executa a ligação de verdade, e é a rede que
//     importa — só que sobre uma dupla que o TESTE monta à mão, com a mesma
//     composição que main.go usa. Se buildServices parar de fazer essa
//     composição, ele continua verde.
//
// Aqui quem monta é buildServices, a função que o boot chama. É a única
// afirmação do repositório que amarra as duas pontas: o Service que o produto
// realmente usa sai com a guarda do /etc/nftables.conf ligada.
//
// Só existe porque run() foi quebrada: antes, chegar a este objeto exigia
// passar por flags, sinais e ListenAndServe.

// buildTestServices monta o produto como o boot monta, sobre um banco
// descartável.
//
// DryRun fica FALSE de propósito: nftables.Persist devolve antes de tudo
// quando o executor é de dry-run (service.go), e um dry-run aqui mediria esse
// atalho em vez da guarda. O preço é que o único comando que este teste pode
// disparar é o `nft list table` do caminho de controle — leitura pura, que
// falha de forma inofensiva numa máquina sem nft.
//
// secretKeyPath e nftables.ConfPath (este redirecionado pelo TestMain de
// boot_wiring_runtime_test.go) são os dois pontos em que a montagem tocaria em
// /etc; os dois apontam para t.TempDir().
func buildTestServices(t *testing.T) *services {
	t.Helper()

	dir := t.TempDir()

	origKeyPath := secretKeyPath
	secretKeyPath = filepath.Join(dir, "secret.key")
	t.Cleanup(func() { secretKeyPath = origKeyPath })

	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("abrir o banco: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{
		ListenAddr:           "127.0.0.1",
		Port:                 0,
		DBPath:               filepath.Join(dir, "test.db"),
		JWTSecret:            "segredo-de-teste-que-nao-vai-a-lugar-nenhum",
		MonitorInterval:      30,
		ProbeIntervalSeconds: 5,
		ProbeCount:           3,
		FailoverEnabled:      false,
	}

	s, err := buildServices(cfg, db)
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}
	return s
}

func TestBuildServicesWiresWireGuardIntoUnbound(t *testing.T) {
	s := buildTestServices(t)
	if s.wgSvc == nil {
		t.Fatal("buildServices did not create the WireGuard service")
	}
	if err := s.db.SaveWireGuardConfig(&storage.WireGuardConfig{
		Enabled: true, ListenPort: 51820, Address: "10.7.0.1/24", EndpointHost: "vpn.example.test",
	}); err != nil {
		t.Fatalf("SaveWireGuardConfig: %v", err)
	}
	files, err := s.keaSvc.GenerateConfigs(netsvc.DefaultConfig(), nil, nil, "")
	if err != nil {
		t.Fatalf("GenerateConfigs: %v", err)
	}
	joined := ""
	for _, file := range files {
		joined += file.Content
	}
	if !strings.Contains(joined, "interface: 10.7.0.1") ||
		!strings.Contains(joined, "access-control: 10.7.0.0/24 allow") {
		t.Fatalf("WireGuard DNS binding was not wired into unbound:\n%s", joined)
	}
}

// TestBuildServicesWiresThePersistGuard mede, no objeto que o boot usa, o que
// TestMainWiresThePersistGuard só consegue ver como uma chamada no texto: com
// uma mudança de firewall aguardando confirmação, o Service montado por
// buildServices NÃO TENTA gravar o arquivo de boot.
//
// A afirmação é sobre PersistState().Attempted, e não sobre o conteúdo do
// arquivo, porque é ela que separa as duas causas possíveis de um arquivo
// intacto: "a guarda parou antes da escrita" e "a escrita foi tentada e
// falhou". Persist só tem esses dois pontos de saída antes da tentativa real
// (dry-run, que este teste desliga, e a guarda), então Attempted==false aqui é
// a guarda e nada mais.
//
// O que a falha significa na máquina: um refactor apagou
// nftSvc.SetPersistGuard de buildServices, o /etc/nftables.conf volta a
// receber a regra de escopo input não confirmada, e uma queda de energia
// dentro dos 90 segundos devolve a máquina sem SSH e sem painel — com o
// operador do outro lado da rede.
func TestBuildServicesWiresThePersistGuard(t *testing.T) {
	ctx := context.Background()
	s := buildTestServices(t)

	// O arquivo de boot deste teste. Sem isto, o alvo seria o
	// nftables.ConfPath redirecionado pelo TestMain do pacote — que já não é
	// o /etc/nftables.conf da máquina, mas é compartilhado.
	confPath := filepath.Join(t.TempDir(), "nftables.conf")
	s.nftSvc.SetConfPath(confPath)

	// A janela de 90 s aberta, como uma mutação de escopo input a deixa.
	err := s.db.SavePendingChange(storage.PendingChange{
		ID:        "00000000-0000-4000-8000-00000000beef",
		Snapshot:  `{"groups":[],"rules":[]}`,
		ExpiresAt: time.Now().Add(90 * time.Second),
		AppliedBy: "admin",
		Summary:   "regra de escopo input que dropa tcp/22",
	})
	if err != nil {
		t.Fatalf("abrir a janela de confirmação: %v", err)
	}

	// O erro do Persist é lido DEPOIS do estado, e nunca como a afirmação
	// principal: numa máquina sem `nft` a tentativa falha, e um t.Fatal aqui
	// esconderia a única coisa que este teste mede atrás de uma mensagem sobre
	// o PATH.
	persistErr := s.nftSvc.Persist(ctx)
	if st := s.nftSvc.PersistState(); st.Attempted {
		t.Errorf("o Service montado por buildServices TENTOU gravar o arquivo de boot com uma mudança aguardando confirmação (estado %+v, erro %v): a guarda do Persist não chegou nele, e o /etc/nftables.conf volta a poder congelar uma regra que tranca o operador fora da máquina", st, persistErr)
	} else if persistErr != nil {
		t.Errorf("a guarda parou antes de qualquer escrita, então Persist tinha que devolver nil: %v", persistErr)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("o arquivo de boot não podia existir: stat devolveu %v", err)
	}

	// Controle, para que o assert de cima não passe por um Persist que parou
	// por outro motivo: fechada a janela, a MESMA chamada tem que tentar de
	// verdade. Só se afirma Attempted — se a tentativa deu certo depende de a
	// máquina ter `nft` e a tabela, e isso não é assunto deste teste.
	if err := s.db.ClearPendingChange(); err != nil {
		t.Fatalf("fechar a janela de confirmação: %v", err)
	}
	_ = s.nftSvc.Persist(ctx)
	if st := s.nftSvc.PersistState(); !st.Attempted {
		t.Fatal("controle quebrado: fechada a janela, o Persist tinha que TENTAR gravar. Se ele parou mesmo assim, o assert acima pode estar verde por outro motivo — reveja os dois juntos")
	}
}

// TestBuildServicesKeepsTheNTPSourceItGaveToTheService é a outra metade, medida
// do mesmo jeito: a fonte de estado do NTP que buildServices entrega ao Service
// tem que continuar ligada depois da montagem.
//
// Sem executor falso não dá para ler os comandos emitidos, então o que se mede
// é a fonte em si — s.ntpInputState guarda a função, e é ela que a reconciliação
// da chain input consulta. Se alguém a trocar por um retorno vazio que compila
// igual, este teste pega.
//
// É menos do que boot_wiring_runtime_test.go mede, e é sobre o objeto de
// produção, que é o que falta lá.
//
// LACUNA CONHECIDA: a fonte de GRUPOS (s.nftSvc) não tem teste equivalente
// neste arquivo. Prová-la exige um grupo de escopo input criado no banco depois
// da montagem e um executor falso para ler o jump emitido.
func TestBuildServicesKeepsTheNTPSourceItGaveToTheService(t *testing.T) {
	s := buildTestServices(t)

	if s.ntpInputState == nil {
		t.Fatal("buildServices devolveu um *services sem a fonte do estado do NTP: a reconciliação de boot (startBackground) precisa da MESMA fonte que foi entregue a SetInputChainSources, senão as duas passam a poder discordar sobre o que está configurado")
	}

	// A chave nunca gravada: "servir NTP desligado", sem erro.
	networks, serving, err := s.ntpInputState()
	if err != nil || serving || len(networks) != 0 {
		t.Fatalf("pré-condição: banco novo tinha que ser NTP desligado sem erro, veio %v/%v/%v", networks, serving, err)
	}

	// E ela lê o banco DESTE *services, em runtime — não uma cópia congelada
	// na montagem.
	if err := s.db.SetSetting("ntp_config", `{"serve_lan":true,"allowed_networks":["192.168.3.0/24"]}`); err != nil {
		t.Fatalf("gravar ntp_config: %v", err)
	}
	networks, serving, err = s.ntpInputState()
	if err != nil {
		t.Fatalf("ler o estado do NTP: %v", err)
	}
	if !serving || len(networks) != 1 || networks[0] != "192.168.3.0/24" {
		t.Errorf("a fonte do NTP não está lendo o banco em runtime: %v/%v", networks, serving)
	}
}

func TestBuildServicesUsesTheSameQosServiceForAPIAndBoot(t *testing.T) {
	s := buildTestServices(t)
	if s.qosSvc == nil {
		t.Fatal("buildServices did not create a QoS service for boot reconciliation")
	}
	serverField := reflect.ValueOf(s.server).Elem().FieldByName("qosSvc")
	if !serverField.IsValid() || serverField.IsNil() {
		t.Fatal("api.Server does not hold the QoS service created by buildServices")
	}
	if serverField.Pointer() != reflect.ValueOf(s.qosSvc).Pointer() {
		t.Fatalf("API and boot received different QoS service instances: api=%#x boot=%p", serverField.Pointer(), s.qosSvc)
	}
}

func TestBuildServicesUsesOneDurableStressServiceForAPIAndBoot(t *testing.T) {
	s := buildTestServices(t)
	if s.stressSvc == nil {
		t.Fatal("buildServices did not create the stress service used for boot recovery")
	}
	serverField := reflect.ValueOf(s.server).Elem().FieldByName("stressSvc")
	if !serverField.IsValid() || serverField.IsNil() {
		t.Fatal("api.Server does not hold the stress service created by buildServices")
	}
	if serverField.Pointer() != reflect.ValueOf(s.stressSvc).Pointer() {
		t.Fatalf("API and boot received different stress service instances: api=%#x boot=%p", serverField.Pointer(), s.stressSvc)
	}
	recoveryField := reflect.ValueOf(s.stressSvc).Elem().FieldByName("recovery")
	if !recoveryField.IsValid() || recoveryField.IsNil() {
		t.Fatal("production stress service has no durable recovery store")
	}
}
