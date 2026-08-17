package storage_test

import (
	"testing"
)

// Rede de segurança para o recorte da issue #26: SetHostAlias é o único jeito de
// o operador dar nome a um host do inventário e não tinha teste nenhum.

func TestSetHostAliasCreatesTheRowWhenTheHostIsUnknown(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:dd:ee:10", "notebook da recepção"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 host, veio %d", len(got))
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:10" || got[0].Alias != "notebook da recepção" {
		t.Errorf("host gravado errado: %+v", got[0])
	}
}

func TestSetHostAliasKeepsIPAndBlockedOfAKnownHost(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertHostSighting("aa:bb:cc:dd:ee:11", "192.168.3.77"); err != nil {
		t.Fatalf("UpsertHostSighting: %v", err)
	}
	if err := db.SetHostBlocked("aa:bb:cc:dd:ee:11", true); err != nil {
		t.Fatalf("SetHostBlocked: %v", err)
	}

	if err := db.SetHostAlias("aa:bb:cc:dd:ee:11", "tablet"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 host, veio %d", len(got))
	}
	h := got[0]
	if h.Alias != "tablet" {
		t.Errorf("esperava o alias novo, veio %q", h.Alias)
	}
	// O ON CONFLICT só toca o alias: renomear um host não pode desfazer o
	// bloqueio dele nem apagar o IP visto.
	if h.IP != "192.168.3.77" {
		t.Errorf("esperava o IP preservado, veio %q", h.IP)
	}
	if !h.Blocked {
		t.Error("esperava o host continuar bloqueado depois de renomear")
	}
}

func TestSetHostAliasOverwritesThePreviousAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:dd:ee:12", "nome antigo"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	if err := db.SetHostAlias("aa:bb:cc:dd:ee:12", "nome novo"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 host (upsert, não duplicata), veio %d", len(got))
	}
	if got[0].Alias != "nome novo" {
		t.Errorf("esperava o alias novo, veio %q", got[0].Alias)
	}
}
