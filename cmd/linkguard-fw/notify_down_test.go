package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/notify"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Este arquivo cobre o caminho do --notify-down pelo CÓDIGO DE SAÍDA, que é a
// única coisa que a máquina enxerga dele.
//
// A unidade que o chama é Type=oneshot, disparada pelo OnFailure= da unidade
// principal. Ela não lê o log: o que vira estado no `systemctl status` e no
// `is-failed` é o inteiro que notifyDownRun devolve. Um teste que conferisse
// só o texto do log deixaria passar exatamente o defeito da issue #60 — lá o
// log até existia (não, nem isso: era o silêncio absoluto), mas o processo
// saía 0 de qualquer jeito.

// notifyDownDB prepara um banco descartável e aponta secretKeyPath para dentro
// do t.TempDir(), para que o teste nunca toque em /etc/linkguard-fw.
func notifyDownDB(t *testing.T) (dbPath string) {
	t.Helper()
	dir := t.TempDir()

	old := secretKeyPath
	secretKeyPath = filepath.Join(dir, "secret.key")
	t.Cleanup(func() { secretKeyPath = old })

	return filepath.Join(dir, "test.db")
}

// configurarWebhook liga um único canal (webhook) apontando para url.
func configurarWebhook(t *testing.T, dbPath, url string) {
	t.Helper()
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // teste

	key, err := secrets.LoadOrGenerateKey(secretKeyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	cfg := notify.Config{}
	cfg.Webhook.Enabled = true
	cfg.Webhook.URL = url
	if err := notify.NewService(db, sec).SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
}

// TestNotifyDownBancoIlegivelSaiDiferenteDeZero é a issue #60 literal.
//
// Antes da correção o storage.Open era seguido de `if err == nil { … }` sem
// else e sem log, e a função caía num `return 0`: o processo dizia "avisei"
// tendo enviado nada. E banco ilegível no instante em que o serviço caiu não é
// um detalhe — é sinal de um problema maior, isto é, exatamente quando o aviso
// mais importa.
func TestNotifyDownBancoIlegivelSaiDiferenteDeZero(t *testing.T) {
	dir := t.TempDir()

	// Um DIRETÓRIO no lugar do arquivo do banco: storage.Open falha sem
	// depender de permissão, que varia com o usuário que roda a suíte (root em
	// container ignora o 0000 e faria este teste passar por engano).
	dbPath := filepath.Join(dir, "nao-e-um-banco")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if got := notifyDownRun(dbPath); got != 1 {
		t.Errorf("notifyDownRun com banco ilegível = %d, esperado 1 — "+
			"exit 0 diz a quem chamou que a notificação saiu", got)
	}
}

// TestNotifyDownSemCanalConfiguradoSaiZero: não ter canal é escolha do admin,
// não falha.
//
// Sair diferente de zero aqui deixaria uma unidade permanentemente vermelha em
// toda instalação sem notificação configurada — e unidade que vive vermelha é
// unidade que ninguém mais olha, o que custaria justamente o sinal que o código
// de saída existe para dar.
func TestNotifyDownSemCanalConfiguradoSaiZero(t *testing.T) {
	dbPath := notifyDownDB(t)

	if got := notifyDownRun(dbPath); got != 0 {
		t.Errorf("notifyDownRun sem canal habilitado = %d, esperado 0", got)
	}
}

// TestNotifyDownCanalEntregaSaiZero: o caminho feliz, e a prova de que o teste
// acima não passa por acidente de nada ser enviado nunca.
func TestNotifyDownCanalEntregaSaiZero(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dbPath := notifyDownDB(t)
	configurarWebhook(t, dbPath, srv.URL)

	if got := notifyDownRun(dbPath); got != 0 {
		t.Errorf("notifyDownRun com canal entregando = %d, esperado 0", got)
	}
	if hits == 0 {
		t.Error("o webhook não foi chamado — o teste não exercitou envio nenhum")
	}
}

// TestNotifyDownTodosOsCanaisFalhamSaiDiferenteDeZero fecha o outro silêncio do
// mesmo caminho.
//
// A issue #60 fala do banco, mas o erro de entrega tinha a mesma forma: os
// erros de SendNow eram logados como Warn e o `return 0` vinha logo abaixo. Se
// o aviso não saiu por canal nenhum, a máquina não pode ficar sabendo disso só
// por uma linha de log que ninguém vai ler.
func TestNotifyDownTodosOsCanaisFalhamSaiDiferenteDeZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dbPath := notifyDownDB(t)
	configurarWebhook(t, dbPath, srv.URL)

	if got := notifyDownRun(dbPath); got != 1 {
		t.Errorf("notifyDownRun com todos os canais falhando = %d, esperado 1", got)
	}
}
