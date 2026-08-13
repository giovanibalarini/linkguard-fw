package nftables

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain aponta o ConfPath padrão deste pacote para um arquivo descartável
// ANTES de qualquer teste rodar. É a rede embaixo do caminho injetável do
// Service (SetConfPath), para o caso dos Service montados por literal
// (`&Service{exec: …}`), que são a maioria aqui e não passam por NewService.
//
// O motivo é concreto, não teórico. Persist é a ÚNICA escrita em disco deste
// pacote que não passa pelo Executor — ou seja, a única que o executor falso
// dos testes não intercepta — e o arquivo que ela grava é o ruleset que o
// nftables.service carrega no boot. Rodar `go test` como root na própria
// appliance (é o mesmo binário, na mesma máquina, e diagnosticar em produção é
// coisa que se faz como root) sobrescrevia o /etc/nftables.conf de verdade com
// o dump do executor falso — `table inet linkguard {}` — e a máquina voltaria
// do próximo boot com o firewall VAZIO. Este projeto já perdeu um boot de
// produção por configuração corrompida (2026-07-24); esta é a mesma classe de
// acidente, com o agravante de ser autoinfligida por uma suíte de testes.
//
// Cada teste que se importa com o CONTEÚDO do arquivo continua apontando o
// caminho para o próprio t.TempDir() (ver persist_test.go).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "linkguard-nft-conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "não foi possível criar o diretório temporário do ConfPath: %v\n", err)
		os.Exit(1)
	}
	ConfPath = filepath.Join(dir, "nftables.conf")
	code := m.Run()
	os.RemoveAll(dir) //nolint:errcheck // limpeza de melhor esforço
	os.Exit(code)
}
