package handlers

// A prova de que o operador ainda alcança a máquina (issue #86).
//
// O QUE ESTA PEÇA CONSERTA. A janela de 90 segundos existe para provar UMA
// coisa: que o admin continua entrando depois da mudança. Se ele não confirmar,
// o LinkGuard reverte sozinho.
//
// Só que a prova não provava. Uma chain que aceita `ct state established` deixa
// a sessão JÁ ABERTA continuar funcionando — então o operador aplica o
// bloqueio, testa pela conexão que já existia, vê tudo respondendo, confirma
// tranquilo, e descobre na próxima reconexão, horas depois, com a mudança já
// persistida em /etc/nftables.conf.
//
// O código reconhece esse modo de falha e o proíbe de forma bruta: a chain
// input aceita `related` e SÓ `related` (reconcile.go:483-491), exatamente para
// a sessão antiga não sobreviver ao próprio bloqueio. O preço é que, sem
// `established`, morre todo retorno de conexão de saída — apt, updater, unbound,
// chrony. Não existe valor dessa flag em que as duas propriedades valham, e é
// por isso que a política padrão (#78) não anda.
//
// A SAÍDA. Se confirmar só é aceito por uma conexão aberta DEPOIS de a janela
// ter sido armada, então confirmar já é, por si, a prova de que conexão nova
// passa. A verificação deixa de depender de o operador testar direito.
//
// POR QUE A DECISÃO É UMA FUNÇÃO PURA. Mesma lição da issue #20: enquanto a
// regra vivia dentro do handler, afirmar qualquer coisa sobre ela exigia montar
// requisição. Aqui a regra é decideFreshness, que recebe fatos e devolve um
// veredito, e os testes exercitam os casos sem HTTP nenhum.

import (
	"context"
	"net"
	"net/http"
	"time"
)

// chaveConn é o tipo da chave de contexto. Tipo privado, e não string, para
// nenhum outro pacote conseguir sobrescrever este valor por acidente.
type chaveConn struct{}

// connInfo é o que se sabe de uma conexão TCP no instante em que ela é aceita.
type connInfo struct {
	// Aceita é quando o servidor aceitou a conexão. É o carimbo que a prova usa.
	Aceita time.Time
}

// ConnContext carimba cada conexão aceita com o instante do accept.
//
// Vai em http.Server.ConnContext (ver cmd/linkguard-fw). É o único jeito de o
// handler saber a idade da conexão que o atende: o *http.Request não carrega
// isso, e o RemoteAddr não distingue duas conexões do mesmo cliente.
func ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, chaveConn{}, connInfo{Aceita: time.Now()})
}

// FreshnessVerdict é o resultado da avaliação.
type FreshnessVerdict int

const (
	// FreshProvado: a conexão é posterior ao arme. Confirmar é, por si, a prova.
	FreshProvado FreshnessVerdict = iota
	// FreshConexaoAntiga: a conexão existia antes da janela. Recusar.
	FreshConexaoAntiga
	// FreshNaoVerificavel: há um proxy no caminho, ou o carimbo não existe. Não
	// dá para provar NEM para desmentir.
	FreshNaoVerificavel
)

// freshnessFacts são os fatos que a decisão consome. Struct explícita para o
// teste montar cada caso sem inventar uma requisição.
type freshnessFacts struct {
	// TemCarimbo diz se a conexão foi carimbada por ConnContext.
	TemCarimbo bool
	// ConexaoAceita é o instante do accept (válido só com TemCarimbo).
	ConexaoAceita time.Time
	// JanelaArmada é o created_at do pendente.
	JanelaArmada time.Time
	// Proxiado diz se a requisição chegou por um intermediário.
	Proxiado bool
}

// decideFreshness responde se esta requisição prova que conexões novas passam.
//
// A ordem das perguntas é a decisão, e cada uma tem motivo:
//
//  1. PROXY PRIMEIRO. Com um intermediário no caminho, a idade da conexão é a
//     do proxy, não a do admin, e um proxy com keep-alive tem conexões velhas
//     por design. Deixar a checagem rodar aí produziria uma recusa eterna (a
//     conexão do proxy é sempre anterior) ou uma aprovação falsa (o proxy abriu
//     uma nova por conta própria, sem o admin ter passado por nada). Nos dois
//     casos o resultado seria uma garantia inventada, pior do que admitir que
//     não dá para provar.
//
//  2. SEM CARIMBO é não verificável, nunca "aprovado". Acontece em teste, e
//     aconteceria se alguém removesse o ConnContext do servidor. O lado seguro
//     de um mecanismo que existe para não trancar ninguém é dizer que não sabe,
//     em vez de dizer que está tudo bem.
//
//  3. E a comparação é ESTRITA (After), sem tolerância. Uma folga de alguns
//     segundos aqui reabriria exatamente o buraco que a função fecha: a conexão
//     do operador é, tipicamente, de segundos antes do arme.
func decideFreshness(f freshnessFacts) FreshnessVerdict {
	if f.Proxiado {
		return FreshNaoVerificavel
	}
	if !f.TemCarimbo || f.JanelaArmada.IsZero() {
		return FreshNaoVerificavel
	}
	if f.ConexaoAceita.After(f.JanelaArmada) {
		return FreshProvado
	}
	return FreshConexaoAntiga
}

// cabecalhosDeProxy são os que denunciam um intermediário. A lista é
// deliberadamente generosa: um falso "há proxy" custa uma mensagem pedindo
// atenção do operador; um falso "não há proxy" custa uma garantia inventada.
var cabecalhosDeProxy = []string{
	"X-Forwarded-For", "X-Real-IP", "Forwarded",
	"X-Forwarded-Host", "X-Forwarded-Proto",
}

// factsFromRequest extrai os fatos de uma requisição de verdade.
func factsFromRequest(r *http.Request, janelaArmada time.Time) freshnessFacts {
	f := freshnessFacts{JanelaArmada: janelaArmada}

	for _, h := range cabecalhosDeProxy {
		if r.Header.Get(h) != "" {
			f.Proxiado = true
			break
		}
	}

	if info, ok := r.Context().Value(chaveConn{}).(connInfo); ok {
		f.TemCarimbo = true
		f.ConexaoAceita = info.Aceita
	}
	return f
}

// mensagemDeRecusa é o texto que o operador lê quando a conexão é antiga.
//
// Ele diz O QUE FAZER, e não só o que aconteceu: quem está com a janela
// correndo tem 90 segundos e não pode gastá-los descobrindo o que o painel quis
// dizer. E explica o porquê em uma linha, porque a recusa parece arbitrária
// para quem acabou de ver o painel responder.
const mensagemDeRecusa = "esta aba está usando a conexão que já existia antes da mudança, " +
	"e por isso ela responderia mesmo se o acesso tivesse sido cortado. " +
	"Abra o painel numa aba nova (ou recarregue com Ctrl+Shift+R) e confirme por lá: " +
	"conseguir carregar já é a prova de que o acesso continua de pé."

// mensagemNaoVerificavel é o texto do caminho do proxy.
//
// Ele NÃO recusa, e isso é uma escolha: com um proxy reverso na frente, exigir
// a prova tornaria a confirmação impossível e a janela sempre venceria. O
// firewall reverteria toda mudança legítima de um administrador que só fez
// colocar um nginx na frente do painel. O que se faz em vez disso é dizer, na
// resposta e na auditoria, que a prova não foi obtida.
const mensagemNaoVerificavel = "não foi possível verificar se esta conexão é nova (há um proxy no caminho). " +
	"Antes de confirmar, teste o acesso de um lugar que não passe pelo proxy, " +
	"um SSH novo por exemplo."
