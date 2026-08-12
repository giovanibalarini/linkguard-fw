package sysprep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O que o postinst fazia à mão (e o install.sh e o `make install` não
// faziam): deixar a máquina pelada com os caminhos que a unidade declara em
// ReadWritePaths= já existindo. Sem isso o serviço morre em 226/NAMESPACE.
func TestPrepareCriaOsCaminhosNumaMaquinaPelada(t *testing.T) {
	root := t.TempDir()

	created, err := Prepare(root)
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

// O /etc/nftables.conf nasce com o cabeçalho que o próprio Persist() gera —
// vazio, mas um arquivo que o `nft -f` aceita.
func TestNftablesConfNasceComCabecalhoValido(t *testing.T) {
	root := t.TempDir()
	if _, err := Prepare(root); err != nil {
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

	if _, err := Prepare(root); err != nil {
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
	if _, err := Prepare(root); err != nil {
		t.Fatalf("Prepare 1: %v", err)
	}
	created, err := Prepare(root)
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
