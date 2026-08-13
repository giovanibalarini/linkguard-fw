package handlers_test

// I-1 da revisão final da Fase C2 — o arquivo de BOOT não pode receber uma
// regra que ainda não se provou boa.
//
// O /etc/nftables.conf é carregado pelo nftables.service do systemd ANTES de o
// LinkGuard subir. Persistir o ruleset vivo dentro dos 90 segundos significava
// que uma queda de energia no meio da janela fazia a máquina voltar com a regra
// não confirmada valendo — e quem a desfaria (RevertPendingOnBoot) só roda
// depois do bootstrapdeps.Ensure e só se o LinkGuard subir. Este projeto já teve
// um boot da aplicação travado por mais de 50 minutos (2026-07-24); nesse
// intervalo o operador fica sem SSH e sem painel numa máquina remota.
//
// O que estes testes exigem, e nesta ordem:
//
//   - com a janela aberta, o arquivo de boot NÃO muda um byte;
//   - confirmar grava a regra confirmada nele;
//   - reverter também grava — e o que ele passa a descrever é o estado
//     anterior, sem a regra.

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// bootFile lê o arquivo de boot da máquina de teste. Arquivo ausente é ""
// (nenhuma reconciliação persistiu ainda), nunca uma falha do teste.
func bootFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("ler o arquivo de boot %s: %v", path, err)
	}
	return string(b)
}

func TestTheBootFileNeverGetsAnUnconfirmedInputRule(t *testing.T) {
	h, db, _, _, conf := newGroupTestHandlerConf(t)

	// Uma mutação comum primeiro, para o arquivo de boot existir e ter conteúdo
	// — é assim que uma máquina em uso está quando o operador vai mexer na
	// input.
	lan := createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	antes := bootFile(t, conf)
	if !strings.Contains(antes, lan.ChainName) {
		t.Fatalf("a mutação normal tinha que ter persistido para o próximo boot; arquivo: %q", antes)
	}

	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup de escopo input: status %d, body %s", w.Code, w.Body.String())
	}
	var input string
	for _, g := range adminGroups(t, db) {
		if g.ID != lan.ID {
			input = g.ChainName
		}
	}
	if input == "" {
		t.Fatal("o grupo de escopo input não chegou ao banco")
	}

	// A asserção que importa: a máquina voltaria SEM a regra não confirmada.
	durante := bootFile(t, conf)
	if strings.Contains(durante, input) {
		t.Fatalf("o arquivo de boot recebeu a regra de escopo input NÃO confirmada (%s): uma queda de energia agora faria a máquina voltar com ela valendo, antes de o LinkGuard subir para reverter.\n%s", input, durante)
	}
	if durante != antes {
		t.Errorf("o arquivo de boot mudou durante a janela de confirmação:\nantes:  %q\ndepois: %q", antes, durante)
	}

	// E confirmar é o que o faz valer também no próximo boot.
	p := getPending(t, h)
	if p == nil {
		t.Fatal("a mudança de escopo input ficou sem janela")
	}
	c := doJSON(t, h.ConfirmPendingChange, "POST", "/api/nftables/pending/confirm", `{"id":"`+p.ID+`"}`)
	if c.Code != http.StatusOK {
		t.Fatalf("confirmar: status %d, body %s", c.Code, c.Body.String())
	}
	depois := bootFile(t, conf)
	if !strings.Contains(depois, input) {
		t.Fatalf("confirmar não gravou a regra no arquivo de boot: a alteração que o operador confirmou sumiria no próximo boot.\n%s", depois)
	}
}

// A outra saída da janela. Reverter também tem que gravar — o arquivo ficou
// congelado durante os 90 segundos, e o que ele passa a descrever é o estado
// anterior. Sem isto, toda mutação que NÃO abre janela e aconteceu no meio da
// janela (bloqueio por host, port forward, NTP) ficaria fora do arquivo de boot
// até a próxima reconciliação.
func TestRevertingWritesTheBootFileBackWithoutTheRule(t *testing.T) {
	h, db, _, fr, conf := newGroupTestHandlerConf(t)

	createGroupViaAPI(t, h, db, `{"name":"LAN","cond_saddr":"192.168.3.0/24","fallthrough":"continue"}`)
	w := doJSON(t, h.CreateGroup, "POST", "/api/nftables/groups", inputGroupBody)
	if w.Code != http.StatusOK {
		t.Fatalf("CreateGroup de escopo input: status %d, body %s", w.Code, w.Body.String())
	}
	p := getPending(t, h)
	if p == nil {
		t.Fatal("a mudança de escopo input ficou sem janela")
	}
	var input string
	for _, g := range adminGroups(t, db) {
		if g.Scope == "input" {
			input = g.ChainName
		}
	}

	// A marca é como este teste enxerga "o arquivo foi REGRAVADO" — sem ela, o
	// conteúdo de antes e o de depois coincidem (a reversão devolve a máquina ao
	// mesmo estado) e a asserção passaria com a gravação removida. Ela também é
	// fiel ao que o arquivo é durante a janela: desatualizado.
	const marca = "# marca deste teste: o arquivo de boot ficou desatualizado durante a janela\n"
	if err := os.WriteFile(conf, []byte(marca), 0o644); err != nil {
		t.Fatalf("escrever a marca no arquivo de boot: %v", err)
	}

	// O watchdog, não o handler: é o caminho que roda sem ninguém na tela.
	if err := fr.RevertPendingOnBoot(context.Background()); err != nil {
		t.Fatalf("reverter: %v", err)
	}
	depois := bootFile(t, conf)
	if strings.Contains(depois, marca) {
		t.Fatalf("a reversão não regravou o arquivo de boot: ele continuaria congelado no que havia antes da janela, sem nada do que foi feito durante ela.\n%s", depois)
	}
	if input != "" && strings.Contains(depois, input) {
		t.Errorf("o arquivo de boot ficou com a regra revertida (%s):\n%s", input, depois)
	}
}
