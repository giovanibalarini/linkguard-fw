package alerts

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// O TÍTULO DO ALERTA NÃO PODE IR PARA O JOURNAL.
//
// Os alertas de cota por aparelho nomeiam o aparelho no título — apelido, nome
// de host, endereço IP da LAN, e o endereço físico cru quando o inventário não
// responde. Create logava o título, então cada cruzamento de cota escrevia o
// nome que o dono deu ao aparelho no journal, num caminho que podeNotificar não
// cobre e que ninguém escolheu.
//
// Não é exfiltração — o journal fica na caixa. É identidade saindo da
// jurisdição do portão por uma porta que não foi decidida, que é o que
// internal/metrics/exposicao.go existe para não deixar acontecer por acidente.
func TestOTituloDoAlertaNaoVaiParaOLog(t *testing.T) {
	db := openTestDB(t)
	s := NewService(db)

	var buf bytes.Buffer
	anterior := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(anterior) })

	const nome = "tablet da sala"
	const mac = "aa:bb:cc:dd:ee:ff"
	if err := s.Create(TypeHostQuotaExceeded, SeverityCritical,
		"Cota estourada: "+nome,
		"O aparelho "+nome+" já consumiu tudo.", mac); err != nil {
		t.Fatalf("Create: %v", err)
	}

	log := buf.String()
	if !strings.Contains(log, "alert created") {
		t.Fatalf("o log não registrou a criação do alerta: %q", log)
	}
	if strings.Contains(log, nome) {
		t.Errorf("o apelido do aparelho foi para o log: %q", log)
	}
	// A chave continua no log: é ela que permite correlacionar sem publicar o
	// nome legível, que é para a tela — autenticada.
	if !strings.Contains(log, mac) {
		t.Errorf("a chave do alerta sumiu do log e ele deixou de servir para depurar: %q", log)
	}
}
