package firewallrules_test

import (
	"reflect"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestToStoredGroupCarriesEverySharedField(t *testing.T) {
	row := storage.FirewallGroup{
		ID: "g1", Name: "Acesso ao painel", ChainName: "grp_0123456789ab",
		Position: 7, Enabled: true,
		CondSaddr: "10.0.0.0/8", CondDaddr: "192.168.1.10",
		CondIif: "enp0s3", Fallthrough: nftables.FallthroughDrop,
		Kind: nftables.GroupKindAdmin, Scope: nftables.ScopeInput,
		ConnState: nftables.ConnStateNew,
	}
	want := nftables.StoredGroup{
		ID: "g1", Name: "Acesso ao painel", ChainName: "grp_0123456789ab",
		Position: 7, Enabled: true,
		CondSaddr: "10.0.0.0/8", CondDaddr: "192.168.1.10",
		CondIif: "enp0s3", Fallthrough: nftables.FallthroughDrop,
		Kind: nftables.GroupKindAdmin, Scope: nftables.ScopeInput,
		ConnState: nftables.ConnStateNew,
	}

	got := firewallrules.ToStoredGroup(row)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conversão incompleta:\n  obtive: %#v\n  queria: %#v", got, want)
	}
	if got.Rules != nil {
		t.Fatalf("o mapper puro não deve associar regras: %#v", got.Rules)
	}
}

func TestToStoredGroupModelsAndMappingStayInSync(t *testing.T) {
	storageType := reflect.TypeOf(storage.FirewallGroup{})
	storedType := reflect.TypeOf(nftables.StoredGroup{})
	storageOnly := map[string]bool{"CreatedAt": true, "UpdatedAt": true}
	storedOnly := map[string]bool{"Rules": true}
	row := reflect.New(storageType).Elem()

	for i := 0; i < storageType.NumField(); i++ {
		field := storageType.Field(i)
		if storageOnly[field.Name] {
			continue
		}
		peer, ok := storedType.FieldByName(field.Name)
		if !ok {
			t.Errorf("storage.FirewallGroup.%s não existe em nftables.StoredGroup", field.Name)
			continue
		}
		if peer.Type != field.Type {
			t.Errorf("campo %s tem tipos diferentes: storage=%s nftables=%s", field.Name, field.Type, peer.Type)
			continue
		}
		switch field.Type.Kind() {
		case reflect.String:
			row.Field(i).SetString("valor-" + field.Name)
		case reflect.Int:
			row.Field(i).SetInt(int64(i + 1))
		case reflect.Bool:
			row.Field(i).SetBool(true)
		default:
			t.Fatalf("campo compartilhado %s tem tipo sem fixture: %s", field.Name, field.Type)
		}
	}
	for i := 0; i < storedType.NumField(); i++ {
		field := storedType.Field(i)
		if storedOnly[field.Name] {
			continue
		}
		if _, ok := storageType.FieldByName(field.Name); !ok {
			t.Errorf("nftables.StoredGroup.%s não existe em storage.FirewallGroup", field.Name)
		}
	}

	got := reflect.ValueOf(firewallrules.ToStoredGroup(row.Interface().(storage.FirewallGroup)))
	for i := 0; i < storageType.NumField(); i++ {
		field := storageType.Field(i)
		if storageOnly[field.Name] {
			continue
		}
		gotField := got.FieldByName(field.Name)
		if !gotField.IsValid() {
			continue
		}
		if !reflect.DeepEqual(row.Field(i).Interface(), gotField.Interface()) {
			t.Errorf("campo %s não foi propagado: obtive %#v, queria %#v",
				field.Name, gotField.Interface(), row.Field(i).Interface())
		}
	}
}
