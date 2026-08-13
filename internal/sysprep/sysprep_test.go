package sysprep

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// O que o postinst fazia à mão (e o install.sh e o `make install` não
// faziam): deixar a máquina pelada com os caminhos que a unidade declara em
// ReadWritePaths= já existindo. Sem isso o serviço morre em 226/NAMESPACE.
func TestPrepareCriaOsCaminhosNumaMaquinaPelada(t *testing.T) {
	root := t.TempDir()

	created, err := Prepare(root, StageServiceStart)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(created) != len(Entries) {
		t.Fatalf("esperava %d objetos criados, veio %d: %v", len(Entries), len(created), created)
	}

	for _, e := range Entries {
		st, err := os.Stat(filepath.Join(root, e.Path))
		if err != nil {
			t.Fatalf("%s não foi criado: %v", e.Path, err)
		}
		if st.IsDir() != e.Dir {
			t.Errorf("%s: IsDir=%v, esperava %v", e.Path, st.IsDir(), e.Dir)
		}
		if got := st.Mode().Perm(); got != e.Mode.Perm() {
			t.Errorf("%s: modo %o, esperava %o", e.Path, got, e.Mode.Perm())
		}
	}
}

// O defeito da instalação em máquina pelada, em forma de teste.
//
// /etc/nftables.conf é conffile do pacote `nftables`. Enquanto um instalador
// o criava, `apt install ./linkguard-fw_*.deb` numa máquina sem o nftables
// parava no prompt de conffile do dpkg ("File on system created by you or by
// a script") — interativo o apt espera para sempre, não interativo ele morre
// com "end of file on stdin at conffile prompt" e deixa o `nftables` em
// `iU`. Reproduzido em duas VMs recriadas do zero.
//
// Então: na fase de instalação, o arquivo NÃO pode nascer. Na partida do
// serviço (fora de qualquer transação do dpkg), ele TEM que nascer — a
// unidade lista o caminho em ReadWritePaths= e um arquivo ausente no start
// nunca fica gravável para o processo em execução.
func TestOInstaladorNaoCriaConffileDeOutroPacote(t *testing.T) {
	root := t.TempDir()

	created, err := Prepare(root, StageInstall)
	if err != nil {
		t.Fatalf("Prepare(StageInstall): %v", err)
	}
	for _, line := range created {
		if strings.HasPrefix(line, NftablesConfPath+" ") {
			t.Errorf("a instalação criou %s; ele é conffile do pacote nftables e o dpkg "+
				"para no prompt de conffile no meio do `apt install`", NftablesConfPath)
		}
	}
	if _, err := os.Stat(filepath.Join(root, NftablesConfPath)); !os.IsNotExist(err) {
		t.Fatalf("%s existe depois de Prepare(StageInstall) (err=%v): "+
			"criá-lo dentro da transação do dpkg é exatamente o defeito", NftablesConfPath, err)
	}

	// E tudo o que NÃO é de outro pacote continua saindo do instalador: sem
	// isso a unidade morre em 226/NAMESPACE antes de executar uma linha.
	for _, e := range Entries {
		if e.OnlyAtServiceStart {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Path)); err != nil {
			t.Errorf("%s não foi criado na instalação: %v", e.Path, err)
		}
	}

	// A partida do serviço fecha o buraco.
	created, err = Prepare(root, StageServiceStart)
	if err != nil {
		t.Fatalf("Prepare(StageServiceStart): %v", err)
	}
	if len(created) == 0 {
		t.Fatal("Prepare(StageServiceStart) não criou nada depois da instalação: " +
			"o /etc/nftables.conf ficaria faltando para sempre")
	}
	if _, err := os.Stat(filepath.Join(root, NftablesConfPath)); err != nil {
		t.Fatalf("%s não nasceu na partida do serviço: %v", NftablesConfPath, err)
	}
}

// O /etc/nftables.conf nasce com o cabeçalho que o próprio Persist() gera —
// vazio, mas um arquivo que o `nft -f` aceita.
func TestNftablesConfNasceComCabecalhoValido(t *testing.T) {
	root := t.TempDir()
	if _, err := Prepare(root, StageServiceStart); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(root, NftablesConfPath))
	if err != nil {
		t.Fatalf("ler nftables.conf: %v", err)
	}
	if !strings.HasPrefix(string(b), "#!/usr/sbin/nft -f") {
		t.Errorf("nftables.conf sem shebang do nft:\n%s", b)
	}
}

// Numa máquina que já tem os pacotes, o dono e o modo dos diretórios são do
// pacote: Prepare não pode mexer no que já existe.
func TestPrepareNaoMexeNoQueJaExiste(t *testing.T) {
	root := t.TempDir()
	kea := filepath.Join(root, "/etc/kea")
	if err := os.MkdirAll(kea, 0o750); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, NftablesConfPath)
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("table inet linkguard {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Prepare(root, StageServiceStart); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	st, _ := os.Stat(kea)
	if st.Mode().Perm() != 0o750 {
		t.Errorf("/etc/kea teve o modo trocado para %o", st.Mode().Perm())
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "table inet linkguard {}\n" {
		t.Errorf("nftables.conf existente foi sobrescrito: %q", b)
	}
}

// Rodar duas vezes (reinstalação, upgrade) não pode criar nada na segunda.
func TestPrepareEIdempotente(t *testing.T) {
	root := t.TempDir()
	if _, err := Prepare(root, StageServiceStart); err != nil {
		t.Fatalf("Prepare 1: %v", err)
	}
	created, err := Prepare(root, StageServiceStart)
	if err != nil {
		t.Fatalf("Prepare 2: %v", err)
	}
	if len(created) != 0 {
		t.Errorf("a segunda execução criou %v", created)
	}
}

func TestCovers(t *testing.T) {
	cases := map[string]bool{
		"/etc/nftables.conf":      true,
		"/etc/kea":                true,
		"/etc/kea/kea-dhcp4.conf": true,
		"/etc/unbound":            true, // criado a caminho do conf.d
		"/etc/unbound/unbound.conf.d/linkguard.conf": true,
		"/var/lib/linkguard-fw":                      true,
		"/etc/resolv.conf":                           false,
		"/etc/dhcp":                                  false,
	}
	for path, want := range cases {
		if got := Covers(path); got != want {
			t.Errorf("Covers(%q) = %v, esperava %v", path, got, want)
		}
	}
}

func TestSandboxHintSoExplicaOSandboxQuandoEArmadilha(t *testing.T) {
	trap := SandboxHint("/etc/chrony/conf.d/linkguard.conf", syscall.EROFS)
	if !strings.Contains(trap, "systemctl restart linkguard-fw") {
		t.Errorf("read-only file system tem que virar a dica de reinício:\n%s", trap)
	}
	if !strings.Contains(trap, "/etc/chrony/conf.d/linkguard.conf") {
		t.Errorf("a dica tem que dizer qual caminho falhou:\n%s", trap)
	}

	// Disco cheio não é a armadilha: mandar reiniciar o serviço aqui seria
	// mandar o admin repetir um erro que vai acontecer igual.
	other := SandboxHint("/etc/kea", syscall.ENOSPC)
	if strings.Contains(other, "systemctl restart linkguard-fw") {
		t.Errorf("erro que não é a armadilha não pode mandar reiniciar:\n%s", other)
	}
	if !strings.Contains(other, "/etc/kea") {
		t.Errorf("o motivo cru tem que dizer o caminho:\n%s", other)
	}
}
