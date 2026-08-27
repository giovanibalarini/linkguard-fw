package main

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestDomainRoutingProductionWiringAndBootOrder(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	required := [][]byte{
		[]byte("domainRouting := domainrouting.New(db, domSvc)"),
		[]byte("DomainRouting: domainRouting"),
		[]byte("domainRouting.Reconcile(ctx)"),
		[]byte("domainRouting.Prepare(ctx)"),
		// Sem esta, Estado.Observando responde nil em toda máquina e a tela
		// perde a única coisa que separa "ninguém acessou este nome" de "eu
		// não estou olhando o DNS". É de fiação porque o campo existir não
		// adianta nada se ninguém o liga — foi exatamente assim que o aviso
		// "o mapa está desligado" já virou código morto uma vez aqui.
		[]byte("domSvc.DefinirFonteDeObservacao("),
	}
	for _, fragment := range required {
		if !bytes.Contains(source, fragment) {
			t.Errorf("fiação de produção não contém %q", fragment)
		}
	}

	prepare := bytes.Index(source, []byte("domainRouting.Prepare(ctx)"))
	for _, prerequisite := range [][]byte{
		[]byte("nftSvc.EnsureDomainStructures(ctx)"),
		[]byte("nftSvc.FlushDomainStructures(ctx)"),
		[]byte("nftSvc.ReconcileStructuralChains(ctx"),
		[]byte("frSvc.Reconcile(ctx)"),
	} {
		position := bytes.Index(source, prerequisite)
		if position < 0 || prepare < 0 || position > prepare {
			t.Errorf("%q precisa vir antes de domainRouting.Prepare", prerequisite)
		}
	}

	if bytes.Contains(source, []byte("s.db.ListDomainTargets()")) || bytes.Contains(source, []byte("func alvosDeDominio(")) {
		t.Error("o carregamento legado por mark persistida ainda contorna o coordenador")
	}
}

func TestBuildServicesCreatesDomainRoutingCoordinator(t *testing.T) {
	s := buildTestServices(t)
	if s.domainRouting == nil {
		t.Fatal("buildServices devolveu o produto sem coordenador de domínio")
	}
	if state := s.domainRouting.State(context.Background()); state.Ready {
		t.Fatal("coordenador abriu o gate antes do provisionamento do boot")
	}
}
