package firewallrules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// TestMain tira do caminho, para TODO teste deste binário (os dois pacotes de
// teste, firewallrules e firewallrules_test), o único efeito colateral em
// disco que o executor falso não intercepta: o nftables.Persist, que grava o
// ruleset de BOOT da máquina.
//
// Quase todo teste daqui reconcilia, e reconciliar termina em Persist. Sem
// isto, a suíte tentava escrever no /etc/nftables.conf DE VERDADE o dump do
// executor falso (`table inet linkguard {}`): numa estação de trabalho falha
// por permissão e vira só uma linha de WARN no log da suíte; rodada como root
// na própria appliance — o mesmo binário, a mesma máquina —, sobrescreve o
// firewall com que ela volta no próximo boot. Este projeto já perdeu um boot
// de produção por configuração corrompida (2026-07-24).
//
// Os construtores de serviço destes testes já apontam o Service para o próprio
// t.TempDir() (SetConfPath, o caminho de verdade); isto aqui é a rede embaixo,
// para um teste futuro que monte o nftables.Service por conta própria.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "linkguard-fr-conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "não foi possível criar o diretório temporário do ConfPath: %v\n", err)
		os.Exit(1)
	}
	nftables.ConfPath = filepath.Join(dir, "nftables.conf")
	code := m.Run()
	os.RemoveAll(dir) //nolint:errcheck // limpeza de melhor esforço
	os.Exit(code)
}
