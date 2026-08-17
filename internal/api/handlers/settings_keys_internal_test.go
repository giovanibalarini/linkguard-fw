package handlers

import "testing"

// TestSettingsKeysMatchRestoreLiterals prende os nomes das chaves de settings
// que internal/backup repete como literais em restore.go.
//
// A repetição não dá para eliminar: são identificadores não exportados deste
// pacote, e internal/api/handlers já importa internal/backup — a importação
// inversa seria ciclo. O que dá para eliminar é a divergência silenciosa (o
// ARQ-7): se alguém renomear uma destas constantes só aqui, sem tocar em
// internal/backup/restore.go, o efeito não é um erro de compilação, é uma
// restauração que passa a se comportar errado em silêncio.
//
// netsvc_last_apply é a mais grave das quatro: é ela que faz o restore pular o
// resultado de um apply que aconteceu na máquina de ORIGEM. Divergindo, o
// painel da máquina de destino passaria a exibir um apply que nunca rodou nela.
// As outras três decidem qual blob é validado antes de ser gravado — divergindo,
// o valor entra no banco sem passar por validador nenhum, que é exatamente o
// buraco que a validação de restore existe para fechar.
func TestSettingsKeysMatchRestoreLiterals(t *testing.T) {
	// Os valores esperados são os literais escritos em
	// internal/backup/restore.go. Mudou um lado, mude o outro.
	for _, tc := range []struct{ got, want, quem string }{
		{netsvcCfgKey, "netsvc_config", "knownSettingsValidators"},
		{netsvcApplyStatusKey, "netsvc_last_apply", "machineLocalSettingKeys"},
		{ntpCfgKey, "ntp_config", "knownSettingsValidators"},
	} {
		if tc.got != tc.want {
			t.Errorf("chave = %q, esperava %q — internal/backup/restore.go repete este literal em %s e precisa mudar junto",
				tc.got, tc.want, tc.quem)
		}
	}
}
