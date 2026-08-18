package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A rota da postura do firewall (issues #78 e #92).
//
// O que estes testes protegem é a escolha de PADRÃO do corpo: um pedido sem
// `chain` mexe na FORWARD. É o que o admin quer dizer em quase todo caso real
// quando fala em "bloquear tudo" — blindar o acesso à própria caixa é a decisão
// rara e deliberada, e trocá-la por engano é como ele se tranca do lado de fora.

func posturaAtual(t *testing.T, h interface {
	GetInputPolicy(w http.ResponseWriter, r *http.Request)
}) (string, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.GetInputPolicy(w, httptest.NewRequest("GET", "/api/nftables/policy", nil))
	if w.Code != 200 {
		t.Fatalf("GET da postura: status %d, body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Policy  string `json:"policy"`
		Forward string `json:"forward"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("resposta ilegível: %v", err)
	}
	return resp.Policy, resp.Forward
}

func TestPosturaNasceLiberadaNasDuasChains(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)
	inp, fwd := posturaAtual(t, h)
	if inp != "accept" || fwd != "accept" {
		t.Errorf("máquina recém-instalada nasceu com input=%q forward=%q; toda base instalada roda liberada", inp, fwd)
	}
}

// TestPUTSemChainMexeNaForward é a asserção do padrão.
func TestPUTSemChainMexeNaForward(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)

	req := httptest.NewRequest("PUT", "/api/nftables/policy", strings.NewReader(`{"policy":"drop"}`))
	w := httptest.NewRecorder()
	h.SetInputPolicy(w, req)
	if w.Code != 200 {
		t.Fatalf("PUT: status %d, body %s", w.Code, w.Body.String())
	}

	inp, fwd := posturaAtual(t, h)
	if fwd != "drop" {
		t.Errorf("um PUT sem `chain` não bloqueou o que ATRAVESSA o firewall: forward=%q", fwd)
	}
	if inp != "accept" {
		t.Errorf("ele bloqueou o acesso AO firewall sem ninguém ter pedido: input=%q\n"+
			"Esse é o caminho pelo qual o operador perde o painel e o SSH de uma vez.", inp)
	}
}

func TestPUTComChainInputMexeSoNaInput(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)

	req := httptest.NewRequest("PUT", "/api/nftables/policy", strings.NewReader(`{"policy":"drop","chain":"input"}`))
	w := httptest.NewRecorder()
	h.SetInputPolicy(w, req)
	if w.Code != 200 {
		t.Fatalf("PUT: status %d, body %s", w.Code, w.Body.String())
	}

	inp, fwd := posturaAtual(t, h)
	if inp != "drop" {
		t.Errorf("input=%q, esperava drop", inp)
	}
	if fwd != "accept" {
		t.Errorf("mexer na input mudou a forward para %q: as duas posturas são independentes", fwd)
	}
}

// TestTrocaDePosturaSempreAbreJanela. As outras mutações perguntam se alcançam
// a chain input; uma troca de postura MUDA a chain inteira, e a da forward
// derruba a rede toda se estiver errada. Não existe troca que não mereça os 90
// segundos de reversão automática.
func TestTrocaDePosturaSempreAbreJanela(t *testing.T) {
	for _, caso := range []struct{ nome, corpo string }{
		{"forward para drop", `{"policy":"drop"}`},
		{"input para drop", `{"policy":"drop","chain":"input"}`},
	} {
		t.Run(caso.nome, func(t *testing.T) {
			h, _, _ := newFirewallRulesTestHandler(t)
			w := httptest.NewRecorder()
			h.SetInputPolicy(w, httptest.NewRequest("PUT", "/api/nftables/policy", strings.NewReader(caso.corpo)))
			if w.Code != 200 {
				t.Fatalf("status %d, body %s", w.Code, w.Body.String())
			}
			var resp struct {
				Pending *struct {
					Reason string `json:"reason"`
				} `json:"pending"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("resposta ilegível: %v", err)
			}
			if resp.Pending == nil {
				t.Fatalf("nenhuma janela foi armada: a troca valeria para sempre sem ninguém confirmar\n%s", w.Body.String())
			}
		})
	}
}

// TestPosturaIgualNaoAbreJanela: armar uma janela para uma troca que não muda
// nada trancaria a edição do firewall por 90 segundos à toa, e pediria ao
// operador que confirmasse um acesso que ele nunca perdeu.
func TestPosturaIgualNaoAbreJanela(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)
	w := httptest.NewRecorder()
	h.SetInputPolicy(w, httptest.NewRequest("PUT", "/api/nftables/policy", strings.NewReader(`{"policy":"accept"}`)))
	if w.Code != 200 {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "\"pending\"") {
		t.Errorf("abriu janela para uma troca que não muda nada: %s", w.Body.String())
	}
}

func TestPosturaInvalidaERecusada(t *testing.T) {
	h, _, _ := newFirewallRulesTestHandler(t)
	for _, corpo := range []string{`{"policy":"reject"}`, `{"policy":""}`, `{"policy":"DROP"}`} {
		w := httptest.NewRecorder()
		h.SetInputPolicy(w, httptest.NewRequest("PUT", "/api/nftables/policy", strings.NewReader(corpo)))
		if w.Code != 400 {
			t.Errorf("corpo %s aceito com status %d: %s", corpo, w.Code, w.Body.String())
		}
	}
	if _, fwd := posturaAtual(t, h); fwd != "accept" {
		t.Errorf("um pedido recusado mexeu na postura mesmo assim: forward=%q", fwd)
	}
}
