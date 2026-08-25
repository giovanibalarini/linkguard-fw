package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Alvo de regra por domínio (#123): a lista que o admin mantém.

// TestUmDominioNasceEmEnsaioMesmoQuandoAChamadaPedeAtivo prende a proteção mais
// importante desta tabela.
//
// Sair do ensaio é a ÚNICA coisa nesta capacidade que muda o que passa na rede.
// Se uma gravação de rotina — editar a observação, trocar o link, importar um
// backup — pudesse promover de carona, o produto ligaria um bloqueio que
// ninguém pediu, e o admin descobriria pelo telefone tocando.
func TestUmDominioNasceEmEnsaioMesmoQuandoAChamadaPedeAtivo(t *testing.T) {
	db := newTestDB(t)
	err := db.SaveDomainTarget(storage.DomainTarget{
		Domain: "netflix.com", Capability: storage.DomainCapBarrar,
		Stage: storage.DomainStageAtivo, // a chamada pede ativo…
	})
	if err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	lista, err := db.ListDomainTargets()
	if err != nil {
		t.Fatalf("ListDomainTargets: %v", err)
	}
	if len(lista) != 1 {
		t.Fatalf("esperava um domínio, vieram %d", len(lista))
	}
	if lista[0].Stage != storage.DomainStageEnsaio {
		t.Fatalf("…e ele nasceu %q em vez de ensaio", lista[0].Stage)
	}
}

// TestPromoverEhAUnicaPortaDeSaidaDoEnsaio.
func TestPromoverEhAUnicaPortaDeSaidaDoEnsaio(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	if err := db.PromoteDomainTarget("netflix.com", storage.DomainStageAtivo); err != nil {
		t.Fatalf("PromoteDomainTarget: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if lista[0].Stage != storage.DomainStageAtivo {
		t.Fatalf("a promoção não valeu: %q", lista[0].Stage)
	}

	// E uma gravação depois disso NÃO pode rebaixar nem manter por acidente: o
	// Save não toca no estágio de quem já existe.
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com", Note: "editado"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	lista, _ = db.ListDomainTargets()
	if lista[0].Stage != storage.DomainStageAtivo || lista[0].Note != "editado" {
		t.Fatalf("a edição mexeu no estágio: %+v", lista[0])
	}
}

// TestODominioEhUnicoNaTabela.
//
// Duas linhas para o mesmo nome deixariam "qual capacidade vale" sem resposta —
// a resposta seria a ordem do SELECT, quer dizer: um domínio que barra ou
// direciona conforme o dia.
func TestODominioEhUnicoNaTabela(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com", Capability: storage.DomainCapBarrar}); err != nil {
		t.Fatalf("primeira gravação: %v", err)
	}
	if err := db.SaveDomainTarget(storage.DomainTarget{
		Domain: "NETFLIX.COM.", Capability: storage.DomainCapDirecionar, Mark: 0x12c,
	}); err != nil {
		t.Fatalf("segunda gravação: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if len(lista) != 1 {
		t.Fatalf("o mesmo nome virou %d linhas", len(lista))
	}
	if lista[0].Capability != storage.DomainCapDirecionar || lista[0].Mark != 0x12c {
		t.Fatalf("a segunda gravação não corrigiu a primeira: %+v", lista[0])
	}
}

// TestDominioSemPontoEhRecusado — ver NormalizarDominio no domtargets: um nome
// de um rótulo só casaria com um TLD inteiro.
func TestDominioSemPontoEhRecusado(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "com"}); err == nil {
		t.Fatal("um domínio de um rótulo só foi aceito")
	}
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "   "}); err == nil {
		t.Fatal("um domínio vazio foi aceito")
	}
}

// TestApagarTiraDaLista.
func TestApagarTiraDaLista(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	if err := db.DeleteDomainTarget("netflix.com"); err != nil {
		t.Fatalf("DeleteDomainTarget: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if len(lista) != 0 {
		t.Fatalf("sobrou %d depois de apagar", len(lista))
	}
	if err := db.PromoteDomainTarget("netflix.com", storage.DomainStageAtivo); err == nil {
		t.Fatal("promover um domínio que não existe passou em silêncio")
	}
}
