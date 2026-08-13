package handlers_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// TestMain tira do caminho, para TODO teste deste binário, o único efeito
// colateral em disco que o executor falso NÃO intercepta: o nftables.Persist,
// que grava o ruleset de BOOT da máquina.
//
// Este pacote reconcilia em quase toda mutação, e reconciliar termina em
// Persist. Sem isto, a suíte tentava escrever no /etc/nftables.conf DE VERDADE
// o dump do executor falso: numa estação de trabalho falha por permissão e
// vira só uma linha de WARN no log; rodada como root na própria appliance — o
// mesmo binário, a mesma máquina —, sobrescreve o firewall com que ela volta
// no próximo boot. Este projeto já perdeu um boot de produção por configuração
// corrompida (2026-07-24).
//
// É a mesma rede que internal/firewallrules e internal/nftables já tinham; a
// Fase C2 trouxe a janela de confirmação para cá, e com ela mais caminhos
// deste pacote que reconciliam (reverter, por exemplo).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "linkguard-handlers-conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "não foi possível criar o diretório temporário do ConfPath: %v\n", err)
		os.Exit(1)
	}
	nftables.ConfPath = filepath.Join(dir, "nftables.conf")
	code := m.Run()
	os.RemoveAll(dir) //nolint:errcheck // limpeza de melhor esforço
	os.Exit(code)
}
