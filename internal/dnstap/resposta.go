package dnstap

import (
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Extração do mapa endereço → nome a partir da resposta de DNS.
//
// É AQUI QUE A ISSUE #116 SE PAGA. O produto sabia que 192.168.3.50 perguntou
// por exemplo.com e não sabia o que o unbound respondeu — então todo destino em
// toda tela era número. O registro de fluxo mostraria 142.250.x.x, e bloquear
// por domínio não teria como resolver o nome em endereços de forma confiável.
//
// O NOME QUE VALE É O PERGUNTADO, e não o último da cadeia de CNAME. Quem
// perguntou por `video.exemplo.com` e recebeu um CNAME para
// `edge-3.cdn-provedor.net` quer ler o primeiro na tela: o segundo muda a cada
// resolução, é compartilhado por milhares de sites e não diz nada a quem opera.
// Guardar o final da cadeia daria um mapa tecnicamente correto e inútil.

// Resposta é o que uma resposta de DNS ensina ao produto.
type Resposta struct {
	// Nome é o que foi PERGUNTADO, sem o ponto final.
	Nome string
	// Enderecos são os A/AAAA da resposta.
	Enderecos []netip.Addr
	// TTL é o menor TTL entre os registros — quando ele vence, o mapa não pode
	// mais afirmar nada sobre esses endereços.
	TTL time.Duration
}

// Extrair lê uma mensagem DNS em formato de fio e devolve o que ela ensina.
//
// Devolve nil quando não há o que aprender: resposta sem A/AAAA, resposta de
// erro, pergunta em vez de resposta. Nenhum dos três é falha.
func Extrair(fio []byte) (*Resposta, error) {
	var p dnsmessage.Parser
	cab, err := p.Start(fio)
	if err != nil {
		return nil, err
	}
	if !cab.Response || cab.RCode != dnsmessage.RCodeSuccess {
		return nil, nil
	}
	perguntas, err := p.AllQuestions()
	if err != nil || len(perguntas) == 0 {
		// Sem pergunta não há nome a atribuir aos endereços — e atribuir o
		// nome do primeiro registro seria inventar.
		return nil, nil
	}
	nome := trimPonto(perguntas[0].Name.String())

	respostas, err := p.AllAnswers()
	if err != nil {
		return nil, err
	}
	out := &Resposta{Nome: nome}
	for _, r := range respostas {
		var addr netip.Addr
		switch corpo := r.Body.(type) {
		case *dnsmessage.AResource:
			addr = netip.AddrFrom4(corpo.A)
		case *dnsmessage.AAAAResource:
			addr = netip.AddrFrom16(corpo.AAAA)
		default:
			// CNAME, e o resto da cadeia, são pulados de propósito: o nome que
			// vale é o perguntado. Ver o comentário no topo.
			continue
		}
		out.Enderecos = append(out.Enderecos, addr)
		ttl := time.Duration(r.Header.TTL) * time.Second
		if out.TTL == 0 || ttl < out.TTL {
			out.TTL = ttl
		}
	}
	if len(out.Enderecos) == 0 {
		return nil, nil
	}
	return out, nil
}

func trimPonto(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
