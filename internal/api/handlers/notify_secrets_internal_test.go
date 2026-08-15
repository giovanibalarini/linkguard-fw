package handlers

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/notify"
)

// storedConfig é a configuração já gravada: a senha real do SMTP corporativo,
// que a API nunca devolve em claro (redactOut a troca pela máscara).
func storedConfig() notify.Config {
	var c notify.Config
	c.Email.Enabled = true
	c.Email.Host = "smtp.empresa.com.br"
	c.Email.Port = 587
	c.Email.Username = "backup@empresa.com.br"
	c.Email.Password = "SenhaCorporativaReal"
	c.Telegram.Token = "token-real-do-bot"
	c.Telegram.ChatID = "-100999"
	c.WhatsApp.Token = "bearer-real"
	c.WhatsApp.Phone = "5511999999999"
	return c
}

// O ataque: o cliente devolve a máscara (que foi o que ele leu) e troca o host
// para um servidor dele. Antes, mergeSecrets remontava a senha real, e o Test
// entregava a credencial via AUTH PLAIN no servidor do atacante.
func TestMergeSecretsRefusesToReuseTheSMTPPasswordOnADifferentHost(t *testing.T) {
	existing := storedConfig()

	attack := existing
	attack.Email.Host = "smtp.atacante.tld"
	attack.Email.Password = secretMask

	got, err := mergeSecrets(attack, existing)
	if err == nil {
		t.Fatal("mergeSecrets aceitou trocar o host mantendo a senha mascarada — a exfiltração continua possível")
	}
	if got.Email.Password == existing.Email.Password {
		t.Fatal("a senha real foi remontada para um host que o chamador escolheu")
	}
	if !strings.Contains(err.Error(), "SMTP") {
		t.Errorf("a mensagem de erro não diz o que houve: %q", err)
	}
}

func TestMergeSecretsRefusesADifferentUsernameOrPort(t *testing.T) {
	existing := storedConfig()

	for _, tc := range []struct {
		nome  string
		mexer func(*notify.Config)
	}{
		{"usuário", func(c *notify.Config) { c.Email.Username = "outro@empresa.com.br" }},
		{"porta", func(c *notify.Config) { c.Email.Port = 2525 }},
	} {
		t.Run(tc.nome, func(t *testing.T) {
			attack := existing
			tc.mexer(&attack)
			attack.Email.Password = secretMask

			if _, err := mergeSecrets(attack, existing); err == nil {
				t.Fatalf("trocar %s com a senha mascarada deveria ser recusado", tc.nome)
			}
		})
	}
}

// O caminho legítimo tem que continuar funcionando: salvar sem mexer no
// destino (o caso de longe mais comum — mudar o destinatário, ligar/desligar).
func TestMergeSecretsKeepsTheSecretWhenTheDestinationIsUnchanged(t *testing.T) {
	existing := storedConfig()

	edit := existing
	edit.Email.To = "noc@empresa.com.br"
	edit.Email.Password = secretMask
	edit.Telegram.Token = secretMask
	edit.WhatsApp.Token = secretMask

	got, err := mergeSecrets(edit, existing)
	if err != nil {
		t.Fatalf("edição legítima recusada: %v", err)
	}
	if got.Email.Password != existing.Email.Password {
		t.Error("a senha do SMTP não foi preservada numa edição que não mexeu no destino")
	}
	if got.Telegram.Token != existing.Telegram.Token {
		t.Error("o token do Telegram não foi preservado")
	}
	if got.WhatsApp.Token != existing.WhatsApp.Token {
		t.Error("o token do WhatsApp não foi preservado")
	}
}

// Trocar de servidor continua possível — basta mandar a senha nova em vez da
// máscara. A correção não tira capacidade, só exige o segredo do destino novo.
func TestMergeSecretsAllowsChangingHostWhenThePasswordIsProvided(t *testing.T) {
	existing := storedConfig()

	move := existing
	move.Email.Host = "smtp.novofornecedor.com.br"
	move.Email.Password = "SenhaDoFornecedorNovo"

	got, err := mergeSecrets(move, existing)
	if err != nil {
		t.Fatalf("troca legítima de servidor recusada: %v", err)
	}
	if got.Email.Password != "SenhaDoFornecedorNovo" {
		t.Errorf("a senha submetida não foi usada: %q", got.Email.Password)
	}
}

// A máscara nunca pode virar a senha gravada: seria trocar uma falha de
// segurança por um canal quebrado em silêncio.
func TestMergeSecretsNeverLetsTheMaskThroughAsAValue(t *testing.T) {
	existing := storedConfig()

	attack := existing
	attack.Email.Host = "smtp.atacante.tld"
	attack.Email.Password = secretMask

	got, err := mergeSecrets(attack, existing)
	if err == nil && got.Email.Password == secretMask {
		t.Fatal("a máscara passou como se fosse a senha — seria gravada assim")
	}
}

func TestMergeSecretsRefusesTelegramTokenOnADifferentChat(t *testing.T) {
	existing := storedConfig()

	attack := existing
	attack.Telegram.ChatID = "-100111"
	attack.Telegram.Token = secretMask

	got, err := mergeSecrets(attack, existing)
	if err == nil {
		t.Fatal("trocar o chat do Telegram mantendo o token mascarado deveria ser recusado")
	}
	if got.Telegram.Token == existing.Telegram.Token {
		t.Fatal("o token real foi remontado para um chat que o chamador escolheu")
	}
}
