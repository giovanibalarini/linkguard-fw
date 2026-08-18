package netif

import (
	"strings"
	"testing"
)

// A validação do nome de interface é a única coisa entre o que um cliente manda
// e um CAMINHO DE ARQUIVO escrito como root.
//
// networkd.Render monta `<dir>/10-<nome>.network` por interpolação de string, e
// o mesmo nome vai para o corpo da unit do systemd-networkd. Foi este sink que o
// CodeQL apontou (go/path-injection, alertas #3 e #4).
//
// O defeito real que este arquivo fecha não era a regex estar errada: era ela
// estar DUPLICADA. internal/netif tinha a sua cópia, idêntica à de
// internal/validate, e quando a issue #61 endureceu validate.Iface para recusar
// nome feito só de pontuação, esta cópia continuou aceitando — bem no caminho
// mais perigoso dos dois. É a divergência que o comentário de internal/validate
// já descrevia como o motivo de o pacote existir (ARQ-7).

// TestValidateIfaceRecusaNomeQueNaoDaArquivoSeguro cobre a classe inteira,
// não um caso: qualquer nome que não tenha um alfanumérico é recusado.
func TestValidateIfaceRecusaNomeQueNaoDaArquivoSeguro(t *testing.T) {
	for _, nome := range []string{
		"", ".", "..", "...", "-", "_", "._-", "..-._",
		"eth0/../x",   // barra
		"eth0 extra",  // espaço
		"eth0\nMatch", // quebra de linha: injetaria diretiva na unit
		"este-nome-e-longo-demais-para-uma-interface",
	} {
		err := ValidateIface(Iface{Name: nome, AddrMode: AddrModeDHCP})
		if err == nil {
			t.Errorf("ValidateIface(%q) foi aceito — o nome vira caminho de arquivo e corpo de unit", nome)
			continue
		}
		if !strings.Contains(err.Error(), "nome de interface inválido") {
			t.Errorf("ValidateIface(%q): erro %q não identifica o campo culpado", nome, err)
		}
	}
}

// TestValidateIfaceAceitaOsNomesReais é o contraponto, e ele importa tanto
// quanto: uma validação que recusasse VLAN, bridge ou alias quebraria
// configuração legítima já gravada em campo — e o autor da próxima correção
// precisa ver que isso foi considerado.
func TestValidateIfaceAceitaOsNomesReais(t *testing.T) {
	for _, nome := range []string{
		"eth0", "enp3s0", "enp3s0.100", "br-lan", "wg_0", "lg-wan-giga", "a", "1",
	} {
		if err := ValidateIface(Iface{Name: nome, AddrMode: AddrModeDHCP}); err != nil {
			t.Errorf("ValidateIface(%q) recusou um nome legítimo: %v", nome, err)
		}
	}
}
