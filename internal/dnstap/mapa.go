package dnstap

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// O mapa endereço → nome, com prazo.
//
// POR QUE COM PRAZO, E POR QUE ISSO É A PARTE HONESTA. Um endereço de CDN é de
// um site hoje e de outro daqui a dez minutos. Um mapa sem prazo transformaria
// "este endereço FOI de exemplo.com" em "este endereço É de exemplo.com" — e a
// tela passaria a nomear destinos com confiança crescente e correção
// decrescente. O TTL da própria resposta é o único prazo que o DNS oferece, e é
// o que este mapa respeita.
//
// POR QUE EM MEMÓRIA. É cache, não registro: perder no reboot é o
// comportamento certo, porque um mapa que sobrevive ao reboot afirma coisas
// sobre endereços que ninguém mais confirmou. Quem quiser histórico de destino
// é a #115, que é outra issue e outro custo.
//
// TETO DE TAMANHO, e ele é dito na tela: um resolver movimentado vê dezenas de
// milhares de nomes por hora. Sem teto, isto é um vazamento de memória com
// nome bonito. Ao encher, o mais antigo sai — e a tela diz que o mapa está
// cheio, em vez de deixar o admin achar que o que não está lá nunca foi
// perguntado.

const (
	// MaxEntradas é o teto de endereços guardados.
	MaxEntradas = 20000

	// TTLMinimo é o piso do prazo. Provedor de CDN devolve TTL de 30 segundos,
	// e guardar por 30 segundos torna o mapa inútil para ler um fluxo que
	// aconteceu há um minuto. O piso é uma decisão de PRODUTO, não do DNS, e
	// por isso está aqui e não escondido no consumidor.
	TTLMinimo = 5 * time.Minute

	// TTLMaximo evita que um TTL absurdo de um servidor mal configurado prenda
	// um endereço no mapa por semanas.
	TTLMaximo = 24 * time.Hour
)

type entrada struct {
	nome   string
	expira time.Time
	entrou time.Time
}

// Mapa guarda endereço → nome perguntado, com prazo.
type Mapa struct {
	mu    sync.RWMutex
	itens map[netip.Addr]entrada
	agora func() time.Time
	// cheio marca que o teto já foi atingido alguma vez. A tela precisa dizer
	// isso: sem o aviso, um endereço ausente parece "nunca foi consultado"
	// quando pode ser "foi, e saiu para caber outro".
	cheio bool
}

// NovoMapa cria o mapa vazio.
func NovoMapa() *Mapa {
	return &Mapa{itens: make(map[netip.Addr]entrada), agora: time.Now}
}

// Aprender grava o que uma resposta ensinou.
func (m *Mapa) Aprender(r *Resposta) {
	if r == nil || r.Nome == "" || len(r.Enderecos) == 0 {
		return
	}
	ttl := r.TTL
	if ttl < TTLMinimo {
		ttl = TTLMinimo
	}
	if ttl > TTLMaximo {
		ttl = TTLMaximo
	}
	agora := m.agora()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range r.Enderecos {
		if len(m.itens) >= MaxEntradas {
			if _, jaTem := m.itens[a]; !jaTem {
				m.cheio = true
				m.descartarMaisAntigo()
			}
		}
		m.itens[a] = entrada{nome: r.Nome, expira: agora.Add(ttl), entrou: agora}
	}
}

// Nome devolve o nome de um endereço, e se ele é conhecido.
//
// Endereço com prazo vencido responde "não conhecido", e não o nome velho: o
// ponto do prazo é o mapa parar de afirmar o que já não pode garantir.
func (m *Mapa) Nome(a netip.Addr) (string, bool) {
	m.mu.RLock()
	e, ok := m.itens[a]
	m.mu.RUnlock()
	if !ok || m.agora().After(e.expira) {
		return "", false
	}
	return e.nome, true
}

// Estado é o que a tela precisa dizer sobre o mapa.
type Estado struct {
	Entradas int  `json:"entradas"`
	Teto     int  `json:"teto"`
	Cheio    bool `json:"cheio"`
}

// Estado devolve o tamanho e se o teto já foi atingido.
func (m *Mapa) Estado() Estado {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Estado{Entradas: len(m.itens), Teto: MaxEntradas, Cheio: m.cheio}
}

// Limpar tira as entradas vencidas. Chamada periodicamente; sem ela o mapa
// carrega para sempre o peso de nomes que já não pode afirmar.
func (m *Mapa) Limpar() int {
	agora := m.agora()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for a, e := range m.itens {
		if agora.After(e.expira) {
			delete(m.itens, a)
			n++
		}
	}
	return n
}

// descartarMaisAntigo remove a entrada mais velha. Chamada com o lock preso.
func (m *Mapa) descartarMaisAntigo() {
	var alvo netip.Addr
	var maisVelho time.Time
	for a, e := range m.itens {
		if maisVelho.IsZero() || e.entrou.Before(maisVelho) {
			alvo, maisVelho = a, e.entrou
		}
	}
	if alvo.IsValid() {
		delete(m.itens, alvo)
	}
}

// Entrada é uma linha do mapa, como a tela mostra.
type Entrada struct {
	IP   string `json:"ip"`
	Nome string `json:"nome"`
}

// Amostra devolve até n entradas vivas, para a tela mostrar o que foi aprendido.
// Ordenada por nome para a listagem ser estável entre atualizações.
func (m *Mapa) Amostra(n int) []Entrada {
	agora := m.agora()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entrada, 0, n)
	for a, e := range m.itens {
		if agora.After(e.expira) {
			continue
		}
		out = append(out, Entrada{IP: a.String(), Nome: e.nome})
		if len(out) >= n {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Nome != out[j].Nome {
			return out[i].Nome < out[j].Nome
		}
		return out[i].IP < out[j].IP
	})
	return out
}
