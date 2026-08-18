package handlers

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// A prova de acesso da issue #86, exercitada SEM montar requisição — mesma
// lição da #20: enquanto a regra vive dentro do handler, afirmar qualquer coisa
// sobre ela exige httptest, e o que interessa aqui é a decisão.

var (
	armada  = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	antes   = armada.Add(-30 * time.Second)
	depois  = armada.Add(3 * time.Second)
	mesmoTs = armada
)

func TestFreshnessConexaoNovaProva(t *testing.T) {
	got := decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: depois, JanelaArmada: armada,
	})
	if got != FreshProvado {
		t.Errorf("conexão aberta depois do arme não foi aceita como prova (%v)", got)
	}
}

// TestFreshnessConexaoAntigaERecusada é o coração da issue.
//
// É a conexão pela qual o operador aplicou a mudança. Ela responde mesmo com o
// acesso cortado, porque `ct state established` a mantém de pé — então
// confirmar por ela não prova nada.
func TestFreshnessConexaoAntigaERecusada(t *testing.T) {
	got := decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: antes, JanelaArmada: armada,
	})
	if got != FreshConexaoAntiga {
		t.Errorf("a conexão anterior ao arme passou como prova (%v) — é exatamente o buraco da #86", got)
	}
}

// TestFreshnessSemToleranciaNoEmpate: a comparação é estrita.
//
// Uma folga aqui reabriria o buraco: a conexão do operador é, tipicamente, de
// segundos antes do arme, e qualquer tolerância em segundos a deixaria passar.
func TestFreshnessSemToleranciaNoEmpate(t *testing.T) {
	got := decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: mesmoTs, JanelaArmada: armada,
	})
	if got != FreshConexaoAntiga {
		t.Errorf("conexão do MESMO instante do arme foi aceita (%v); a comparação precisa ser estrita", got)
	}
	// Um milissegundo depois já é uma conexão nova de verdade.
	if decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: armada.Add(time.Millisecond), JanelaArmada: armada,
	}) != FreshProvado {
		t.Error("1 ms depois do arme deveria contar como conexão nova")
	}
}

// TestFreshnessProxyNaoInventaGarantia.
//
// Com um intermediário, a idade da conexão é a do PROXY. Um proxy com
// keep-alive tem conexões velhas por design: deixar a checagem rodar produziria
// recusa eterna (nada nunca confirma) ou aprovação falsa (o proxy abriu uma
// nova sozinho). Os dois são garantia inventada.
func TestFreshnessProxyNaoInventaGarantia(t *testing.T) {
	// Mesmo com uma conexão que PASSARIA na checagem, o proxy manda.
	got := decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: depois, JanelaArmada: armada, Proxiado: true,
	})
	if got != FreshNaoVerificavel {
		t.Errorf("com proxy no caminho a decisão foi %v; deveria admitir que não dá para provar", got)
	}
	// E com uma que reprovaria, também: o proxy não pode virar uma recusa
	// eterna que impede o admin de confirmar qualquer coisa.
	if decideFreshness(freshnessFacts{
		TemCarimbo: true, ConexaoAceita: antes, JanelaArmada: armada, Proxiado: true,
	}) != FreshNaoVerificavel {
		t.Error("com proxy, a conexão antiga virou recusa — a janela venceria sempre")
	}
}

// TestFreshnessSemCarimboNaoAprova: se alguém tirar o ConnContext do servidor,
// a decisão tem de dizer que não sabe — nunca que está tudo bem.
func TestFreshnessSemCarimboNaoAprova(t *testing.T) {
	got := decideFreshness(freshnessFacts{TemCarimbo: false, JanelaArmada: armada})
	if got != FreshNaoVerificavel {
		t.Errorf("sem carimbo a decisão foi %v; o lado seguro é não verificável", got)
	}
}

// TestFreshnessSemJanelaNaoAprova: sem um pendente com que comparar, não há
// prova a extrair. Acontece quando o id mandado não é o do pendente atual.
func TestFreshnessSemJanelaNaoAprova(t *testing.T) {
	got := decideFreshness(freshnessFacts{TemCarimbo: true, ConexaoAceita: depois})
	if got != FreshNaoVerificavel {
		t.Errorf("sem janela armada a decisão foi %v", got)
	}
}

// ── A extração dos fatos ────────────────────────────────────────────────────

func TestFactsDetectaOsCabecalhosDeProxy(t *testing.T) {
	for _, h := range cabecalhosDeProxy {
		r := httptest.NewRequest("POST", "/api/nftables/pending/confirm", nil)
		r.Header.Set(h, "10.0.0.1")
		if !factsFromRequest(r, armada).Proxiado {
			t.Errorf("%s não foi reconhecido como proxy", h)
		}
	}
}

func TestFactsSemProxyNemCarimbo(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/nftables/pending/confirm", nil)
	f := factsFromRequest(r, armada)
	if f.Proxiado {
		t.Error("requisição limpa marcada como proxiada")
	}
	if f.TemCarimbo {
		t.Error("httptest não passa por ConnContext; não deveria ter carimbo")
	}
}

// TestFactsLeOCarimboDoConnContext fecha o circuito: o que ConnContext grava é
// o que factsFromRequest lê. Sem este teste, uma mudança na chave de contexto
// quebraria a prova em silêncio — e o sintoma seria a decisão virar "não
// verificável" para sempre, que é justamente o caso que não alarma ninguém.
func TestFactsLeOCarimboDoConnContext(t *testing.T) {
	ctx := ConnContext(context.Background(), nil)
	r := httptest.NewRequest("POST", "/api/nftables/pending/confirm", nil).WithContext(ctx)

	f := factsFromRequest(r, armada)
	if !f.TemCarimbo {
		t.Fatal("o carimbo gravado por ConnContext não foi lido por factsFromRequest")
	}
	if f.ConexaoAceita.IsZero() {
		t.Error("carimbo lido sem instante")
	}
	// E, na prática, uma conexão carimbada agora é posterior a uma janela
	// armada no passado: o caminho feliz de ponta a ponta.
	if decideFreshness(f) != FreshProvado {
		t.Error("conexão carimbada agora não provou contra uma janela antiga")
	}
}

// TestMensagensDizemOQueFazer: quem está com a janela correndo tem 90 segundos
// e não pode gastá-los decifrando o painel.
func TestMensagensDizemOQueFazer(t *testing.T) {
	if !contemTodas(mensagemDeRecusa, "aba nova", "conexão") {
		t.Errorf("a recusa não diz o que fazer: %q", mensagemDeRecusa)
	}
	if !contemTodas(mensagemNaoVerificavel, "proxy", "teste") {
		t.Errorf("o aviso do proxy não orienta: %q", mensagemNaoVerificavel)
	}
}

func contemTodas(s string, partes ...string) bool {
	for _, p := range partes {
		found := false
		for i := 0; i+len(p) <= len(s); i++ {
			if s[i:i+len(p)] == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
