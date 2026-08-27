package nftables

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesetComCacheDeDominio = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
		elements = { 192.168.3.50 : 0x0000012c }
	}

	set dom_blocked {
		type ipv4_addr
		flags timeout
		elements = { 1.1.1.1 timeout 1h expires 59m,
			     8.8.8.8 timeout 1h expires 58m }
	}

	set dom_blocked6 {
		type ipv6_addr
		flags timeout
		elements = { 2606:4700:4700::1111 timeout 1h expires 57m }
	}

	map dom_wan {
		type ipv4_addr : mark
		flags timeout
		elements = { 9.9.9.9 timeout 1h expires 56m : 0x00000064 }
	}

	chain mark_hosts {
		ip daddr map @dom_wan
	}
}
`

type persistentExec struct{ out string }

func (*persistentExec) Execute(context.Context, string, ...string) (string, error) { return "", nil }
func (e *persistentExec) ExecuteRead(context.Context, string, ...string) (string, error) {
	return e.out, nil
}
func (*persistentExec) IsDryRun() bool                              { return false }
func (*persistentExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestPersistentRulesetRemovesOnlyTransientDomainElements(t *testing.T) {
	s := NewService(&persistentExec{out: rulesetComCacheDeDominio})
	got, err := s.PersistentRuleset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, transient := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "9.9.9.9"} {
		if strings.Contains(got, transient) {
			t.Errorf("cache transitório %s entrou no dump persistente:\n%s", transient, got)
		}
	}
	for _, durable := range []string{
		"map host_wan {", "192.168.3.50 : 0x0000012c",
		"set dom_blocked {", "set dom_blocked6 {", "map dom_wan {",
		"ip daddr map @dom_wan",
	} {
		if !strings.Contains(got, durable) {
			t.Errorf("estado durável %q foi removido junto com o cache:\n%s", durable, got)
		}
	}
}

func TestRulesetStillShowsTheLiveDomainCache(t *testing.T) {
	s := NewService(&persistentExec{out: rulesetComCacheDeDominio})
	got, err := s.Ruleset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "9.9.9.9") {
		t.Fatalf("a visão viva não pode esconder o cache que está no kernel:\n%s", got)
	}
}

func TestPersistNeverWritesTransientDomainCacheToBootFile(t *testing.T) {
	s := NewService(&persistentExec{out: rulesetComCacheDeDominio})
	path := filepath.Join(t.TempDir(), "nftables.conf")
	s.SetConfPath(path)
	if err := s.Persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "9.9.9.9") || strings.Contains(got, "2606:4700:4700::1111") {
		t.Fatalf("arquivo de boot ressuscitaria cache DNS:\n%s", got)
	}
	if !strings.Contains(got, "map dom_wan {") || !strings.Contains(got, "ip daddr map @dom_wan") {
		t.Fatalf("persistência removeu estrutura/regra em vez de só elementos:\n%s", got)
	}
}
