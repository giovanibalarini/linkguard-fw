package handlers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

type domainReconcileSpy struct {
	calls int
	err   error
}

func (s *domainReconcileSpy) Reconcile(context.Context) error {
	s.calls++
	return s.err
}

func TestLinkMutationReconcilesDomainRoutingEvenWithoutNftRuntime(t *testing.T) {
	_, db := newGroupTestHandler(t)
	spy := &domainReconcileSpy{}
	h := handlers.NewLinksHandler(links.NewService(db), db, nil, nil)
	h.SetDomainRouting(spy)

	w := doJSON(t, h.Create, http.MethodPost, "/api/links",
		`{"name":"WAN 2","interface":"wan2","status":"unknown","enabled":true,"table_id":200}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("criar link = %d: %s", w.Code, w.Body.String())
	}
	if spy.calls != 1 {
		t.Fatalf("mudança de link deveria reconciliar domínio uma vez, chamadas=%d", spy.calls)
	}
}

func TestBlocklistGroupToggleReconcilesDomainRouting(t *testing.T) {
	h, db := newGroupTestHandler(t)
	spy := &domainReconcileSpy{}
	h.SetDomainRouting(spy)

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	var blocklistID string
	for _, group := range groups {
		if group.Kind == nftables.GroupKindBlocklist {
			blocklistID = group.ID
			break
		}
	}
	if blocklistID == "" {
		t.Fatal("fixture sem grupo blocklist")
	}

	w := doJSON(t, h.ToggleGroup, http.MethodPost, "/api/nftables/groups/toggle",
		`{"id":"`+blocklistID+`","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("desligar blocklist = %d: %s", w.Code, w.Body.String())
	}
	if spy.calls != 1 {
		t.Fatalf("toggle do blocklist deveria reconciliar domínio uma vez, chamadas=%d", spy.calls)
	}
}
