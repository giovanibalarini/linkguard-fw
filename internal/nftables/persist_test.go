package nftables

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPersistWritesOnlyTheLinkguardTable is the regression guard for the
// production incident: an operator's manually-added `table ip nat { ...
// masquerade }` rule got captured by a full `nft list ruleset` dump into
// ConfPath and resurrected on every boot, masquerading loopback traffic and
// breaking the box's own DNS. Persist must serialize only `table inet
// linkguard`, never a foreign table, however the fake executor answers.
func TestPersistWritesOnlyTheLinkguardTable(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{
		tableOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n",
		// If Persist ever regresses to dumping the whole ruleset, this is
		// what a real `nft list ruleset` would return on the incident box —
		// it must never end up in the written file.
		rulesetOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n" +
			"table ip nat {\n\tchain POSTROUTING {\n\t\tmasquerade\n\t}\n}\n",
	}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	body, err := os.ReadFile(ConfPath)
	if err != nil {
		t.Fatalf("read ConfPath: %v", err)
	}
	content := string(body)

	if !strings.Contains(content, "table inet linkguard") {
		t.Errorf("expected persisted file to contain the linkguard table, got:\n%s", content)
	}
	if strings.Contains(content, "table ip nat") {
		t.Errorf("persisted file must never contain a foreign table (table ip nat), got:\n%s", content)
	}

	// The command issued must ask for the specific table, not the whole
	// ruleset — guards against a future refactor silently going back to
	// `nft list ruleset`.
	askedForTable := false
	askedForRuleset := false
	for _, c := range exec.calls {
		if strings.Contains(c, "list table "+Family+" "+Table) {
			askedForTable = true
		}
		if strings.Contains(c, "list ruleset") {
			askedForRuleset = true
		}
	}
	if !askedForTable {
		t.Errorf("expected Persist to issue `nft list table %s %s`; calls: %v", Family, Table, exec.calls)
	}
	if askedForRuleset {
		t.Errorf("Persist must not issue `nft list ruleset`; calls: %v", exec.calls)
	}
}

// TestPersistedFileIsIdempotentOnReload guards against the second defect from
// the same incident: a bare `table inet linkguard { ... }` block with no
// reset makes `nft -f` APPEND to an already-existing table at boot instead of
// replacing it, which is how the box ended up with two masquerade rules (one
// referencing a since-removed interface). The file must lead with the
// standard create-then-delete preamble so the load always starts clean.
func TestPersistedFileIsIdempotentOnReload(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{
		tableOut: "table inet linkguard {\n\tchain forward {\n\t}\n}\n",
	}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	body, err := os.ReadFile(ConfPath)
	if err != nil {
		t.Fatalf("read ConfPath: %v", err)
	}
	content := string(body)

	if strings.Contains(content, "flush ruleset") {
		t.Errorf("persisted file must not flush ruleset (would destroy foreign tables at boot), got:\n%s", content)
	}

	createIdx := strings.Index(content, "table "+Family+" "+Table+"\n")
	deleteIdx := strings.Index(content, "delete table "+Family+" "+Table+"\n")
	defIdx := strings.Index(content, "table "+Family+" "+Table+" {")

	if createIdx < 0 {
		t.Fatalf("expected a bare `table %s %s` preamble line, got:\n%s", Family, Table, content)
	}
	if deleteIdx < 0 {
		t.Fatalf("expected a `delete table %s %s` preamble line, got:\n%s", Family, Table, content)
	}
	if defIdx < 0 {
		t.Fatalf("expected the full table definition to follow, got:\n%s", content)
	}
	if !(createIdx < deleteIdx && deleteIdx < defIdx) {
		t.Errorf("expected order: bare `table` create, then `delete table`, then full definition; got:\n%s", content)
	}
}

// TestPersistIsNoopInDryRun ensures Persist never touches ConfPath (or asks
// the executor for anything) when running in dry-run mode.
func TestPersistIsNoopInDryRun(t *testing.T) {
	dir := t.TempDir()
	old := ConfPath
	ConfPath = filepath.Join(dir, "nftables.conf")
	defer func() { ConfPath = old }()

	exec := &recordExec{dryRun: true}
	s := NewService(exec)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	if _, err := os.Stat(ConfPath); !os.IsNotExist(err) {
		t.Errorf("expected ConfPath to not be written in dry-run, stat err: %v", err)
	}
	if len(exec.calls) != 0 {
		t.Errorf("expected no executor calls in dry-run, got: %v", exec.calls)
	}
}

// N-5. O caminho do arquivo é do SERVIÇO, não da variável de pacote — e o
// motivo é que Persist é a única escrita em disco deste pacote que NÃO passa
// pelo Executor.
//
// Um executor falso intercepta todo comando de nft, mas não intercepta um
// os.WriteFile: a suíte inteira escrevia, de verdade, no caminho de sistema.
// Numa estação de trabalho isso só falha por permissão; rodada como root na
// própria appliance — mesmo binário, mesma máquina, e diagnosticar em produção
// é coisa que se faz como root —, sobrescrevia o /etc/nftables.conf com o dump
// do executor falso (`table inet linkguard {}`), isto é, o firewall VAZIO no
// próximo boot. Este projeto já perdeu um boot de produção por configuração
// corrompida (2026-07-24).
func TestPersistWritesTheServiceConfPath(t *testing.T) {
	exec := &recordExec{tableOut: "table inet linkguard {\n}\n"}
	s := NewService(exec)

	meu := filepath.Join(t.TempDir(), "nftables.conf")
	s.SetConfPath(meu)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if _, err := os.Stat(meu); err != nil {
		t.Fatalf("Persist tinha que gravar no caminho injetado no Service: %v", err)
	}
	if _, err := os.Stat(ConfPath); !os.IsNotExist(err) {
		t.Errorf("com um caminho injetado, Persist não pode escrever no caminho padrão do pacote (stat: %v) -- é assim que a suíte sobrescrevia o /etc/nftables.conf da máquina", err)
	}
}

// E o default continua sendo o caminho de sistema: um Service de PRODUÇÃO
// (NewService, sem injeção) tem que gravar o ruleset de boot onde o
// nftables.service vai procurá-lo. Injetável não pode virar "não persiste mais".
func TestNewServiceDefaultsToTheSystemConfPath(t *testing.T) {
	// ConfPath aqui é o temporário do TestMain; o que importa é que o Service
	// nasce apontando para ele, e não para vazio.
	if got := NewService(&recordExec{}).PersistPath(); got != ConfPath {
		t.Errorf("um Service novo tem que nascer apontando para o ConfPath do pacote (%q), obtive %q", ConfPath, got)
	}
	// E o valor de produção é o arquivo que o systemd carrega no boot.
	if defaultConfPath != "/etc/nftables.conf" {
		t.Errorf("o caminho de produção do ruleset de boot mudou para %q -- o nftables.service carrega /etc/nftables.conf", defaultConfPath)
	}
}

// TestPersistOmitsDynamicAccountingElements protects the boot snapshot from
// reviving live accounting state. Dynamic set elements contain traffic
// counters and expiry data; static set and map elements are configuration and
// must remain in the persisted table.
func TestPersistOmitsDynamicAccountingElements(t *testing.T) {
	dir := t.TempDir()
	exec := &recordExec{tableOut: `table inet linkguard {
	set acct_up {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		counter
		timeout 1d
		elements = { 192.168.3.50 counter packets 10 bytes 1000 expires 59m59s996ms,
			     192.168.3.51 counter packets 1204 bytes 1548221 expires 23h58m }
	}
	set acct_down {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		counter
		timeout 1d
		elements = { 192.168.3.50 counter packets 20 bytes 5000 expires 1d }
	}
	set static_hosts {
		type ipv4_addr
		elements = { 192.168.3.1, 192.168.3.2 }
	}
	map static_marks {
		type ipv4_addr : mark
		elements = { 192.168.3.3 : 0x12c }
	}
}
`}
	s := NewService(exec)
	confPath := filepath.Join(dir, "nftables.conf")
	s.SetConfPath(confPath)

	if err := s.Persist(context.Background()); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	body, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	content := string(body)

	wantPreamble := "#!/usr/sbin/nft -f\n\ntable inet linkguard\ndelete table inet linkguard\n\n"
	if !strings.HasPrefix(content, wantPreamble) {
		t.Errorf("persisted file lost the create-then-delete preamble; got:\n%s", content)
	}

	for _, setName := range []string{"acct_up", "acct_down"} {
		start := strings.Index(content, "\tset "+setName+" {\n")
		if start < 0 {
			t.Fatalf("persisted file lost dynamic set %q; got:\n%s", setName, content)
		}
		end := strings.Index(content[start:], "\n\t}")
		if end < 0 {
			t.Fatalf("persisted file contains an unterminated dynamic set %q; got:\n%s", setName, content[start:])
		}
		block := content[start : start+end]
		wantDeclaration := "\tset " + setName + " {\n" +
			"\t\ttype ipv4_addr\n\t\tsize 65535\n" +
			"\t\tflags dynamic,timeout\n\t\tcounter\n\t\ttimeout 1d"
		if !strings.HasPrefix(block, wantDeclaration) {
			t.Errorf("dynamic set %q declaration changed; got:\n%s", setName, block)
		}
		if strings.Contains(block, "elements =") || strings.Contains(block, "counter packets") || strings.Contains(block, "expires ") {
			t.Errorf("dynamic set %q must retain its declaration but omit live elements, counters, and expiry records; got:\n%s", setName, block)
		}
	}

	for _, want := range []string{
		"\tset static_hosts {\n\t\ttype ipv4_addr\n\t\telements = { 192.168.3.1, 192.168.3.2 }\n\t}",
		"\tmap static_marks {\n\t\ttype ipv4_addr : mark\n\t\telements = { 192.168.3.3 : 0x12c }\n\t}",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("persisted file lost static elements; missing:\n%s\nfull file:\n%s", want, content)
		}
	}
}
