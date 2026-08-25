package nftables

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("endereço inválido no teste: %s", s)
	}
	return a
}

// TestRenovarExigeApagarAntes prende a medição que decidiu a forma do lote.
//
// Medido no nft da máquina de teste:
//
//	add element ... { 1.2.3.4 timeout 1800s : 0x12c }  → aceito, sem erro
//	expires antes: 29m54s   expires depois: 29m54s     → NÃO RENOVOU
//	delete + add na mesma transação → expires 29m59s   → renovou
//
// Um `add` sobre elemento existente é aceito em silêncio e não mexe no prazo.
// Sem o `delete` junto, "renovação" seria um comando que não faz nada e o
// endereço sairia no meio do uso — a falha mais cara, porque parece funcionar.
func TestRenovarExigeApagarAntes(t *testing.T) {
	a := addr(t, "142.250.219.14")
	l := Lote{
		RemoverBloq:   []netip.Addr{a},
		AdicionarBloq: []Entrada{{Addr: a, Prazo: 30 * time.Minute}},
	}
	script := montarLote(l, true)
	linhas := strings.Split(strings.TrimSpace(script), "\n")
	if len(linhas) != 2 {
		t.Fatalf("uma renovação são duas linhas, vieram %d:\n%s", len(linhas), script)
	}
	if !strings.HasPrefix(linhas[0], "delete element") {
		t.Errorf("a remoção não veio primeiro: %q", linhas[0])
	}
	if !strings.HasPrefix(linhas[1], "add element") {
		t.Errorf("a adição não veio depois: %q", linhas[1])
	}
}

// TestOReenvioSemRemocoesExisteEEhSoOsAdds prende a outra medição.
//
//	delete element ... { 9.9.9.9 }   ← ausente
//	add    element ... { 5.6.7.8 ... }
//	→ Error: Could not process rule: No such file or directory
//	→ 5.6.7.8 NÃO entrou
//
// Um `delete` de elemento ausente derruba o lote INTEIRO. Como o kernel pode
// expirar um elemento entre o feeder decidir renovar e o arquivo chegar, o
// reenvio só com os `add` não é paranoia: é o único jeito de o endereço entrar.
func TestOReenvioSemRemocoesExisteEEhSoOsAdds(t *testing.T) {
	l := Lote{
		RemoverBloq:   []netip.Addr{addr(t, "9.9.9.9")},
		AdicionarBloq: []Entrada{{Addr: addr(t, "5.6.7.8"), Prazo: 30 * time.Minute}},
	}
	soAdds := montarLote(l, false)
	if strings.Contains(soAdds, "delete") {
		t.Errorf("o reenvio ainda traz remoção:\n%s", soAdds)
	}
	if !strings.Contains(soAdds, "5.6.7.8") {
		t.Errorf("o reenvio perdeu a adição que precisava entrar:\n%s", soAdds)
	}
}

// TestOPrazoEhGrampeadoOndeViraComando: o TTL vem de uma resposta de DNS, que é
// um número escolhido por um terceiro. O grampo fica no lugar onde o valor vira
// comando, e não só na boa vontade do chamador.
func TestOPrazoEhGrampeadoOndeViraComando(t *testing.T) {
	casos := []struct {
		nome  string
		prazo time.Duration
		quer  string
	}{
		{"TTL de CDN, abaixo do piso", 30 * time.Second, "timeout 600s"},
		{"TTL absurdo, acima do teto", 72 * time.Hour, "timeout 3600s"},
		{"TTL no meio, respeitado", 20 * time.Minute, "timeout 1200s"},
		{"TTL zero", 0, "timeout 600s"},
	}
	for _, c := range casos {
		script := montarLote(Lote{
			AdicionarBloq: []Entrada{{Addr: addr(t, "1.2.3.4"), Prazo: c.prazo}},
		}, false)
		if !strings.Contains(script, c.quer) {
			t.Errorf("%s: esperava %q, veio %q", c.nome, c.quer, strings.TrimSpace(script))
		}
	}
}

// TestOMapLevaMarcaEOsSetsNao: o map de direcionamento é o único que carrega
// marca. Escrever marca num set de bloqueio faria o nft recusar o lote inteiro
// — e como o lote é uma transação, levaria junto tudo o que ia com ele.
func TestOMapLevaMarcaEOsSetsNao(t *testing.T) {
	l := Lote{
		AdicionarBloq:  []Entrada{{Addr: addr(t, "1.2.3.4"), Prazo: time.Hour}},
		AdicionarBloq6: []Entrada{{Addr: addr(t, "2800:3f0::200e"), Prazo: time.Hour}},
		AdicionarWan:   []Entrada{{Addr: addr(t, "5.6.7.8"), Prazo: time.Hour, Marca: 0x12c}},
	}
	for _, linha := range strings.Split(strings.TrimSpace(montarLote(l, false)), "\n") {
		temMarca := strings.Contains(linha, ": 0x")
		ehMap := strings.Contains(linha, " "+DomWanMap+" ")
		if ehMap != temMarca {
			t.Errorf("marca no lugar errado: %q", linha)
		}
	}
}

// TestLoteVazioNaoGeraComando: o caminho mais comum do feeder é "nada mudou", e
// ele não pode custar um fork. Um domínio popular com TTL de 30s e vinte
// clientes geraria dezenas de forks por minuto se toda resposta virasse lote.
func TestLoteVazioNaoGeraComando(t *testing.T) {
	if !(Lote{}).Vazio() {
		t.Error("lote sem nada não se declarou vazio")
	}
	l := Lote{AdicionarBloq: []Entrada{{Addr: addr(t, "1.2.3.4"), Prazo: time.Hour}}}
	if l.Vazio() {
		t.Error("lote com uma adição se declarou vazio")
	}
}

// TestEnderecoInvalidoNaoViraComando: o endereço vem de uma resposta de DNS
// parseada. Um netip.Addr zero interpolado no argv viraria uma linha sem
// endereço, e o nft recusaria o lote inteiro — levando junto o que era válido.
func TestEnderecoInvalidoNaoViraComando(t *testing.T) {
	l := Lote{
		RemoverBloq:   []netip.Addr{{}},
		AdicionarBloq: []Entrada{{Prazo: time.Hour}, {Addr: addr(t, "1.2.3.4"), Prazo: time.Hour}},
	}
	script := montarLote(l, true)
	if n := len(strings.Split(strings.TrimSpace(script), "\n")); n != 1 {
		t.Fatalf("esperava só a linha do endereço válido, vieram %d:\n%s", n, script)
	}
	if !strings.Contains(script, "1.2.3.4") {
		t.Errorf("o endereço válido não sobreviveu:\n%s", script)
	}
}

// TestAsDeclaracoesNaoTemDynamicNemInterval: `dynamic` é para set que o KERNEL
// alimenta (abusers, contabilidade); aqui quem escreve é o userspace. E
// `interval` abriria a porta para alguém achar que dá para listar uma faixa,
// quando o DNS devolve endereço.
func TestAsDeclaracoesNaoTemDynamicNemInterval(t *testing.T) {
	for _, spec := range []string{domBlockedSpec, domBlocked6Spec, domWanSpec} {
		for _, proibido := range []string{"dynamic", "interval"} {
			if strings.Contains(spec, proibido) {
				t.Errorf("a declaração %q não devia ter %q", spec, proibido)
			}
		}
		if !strings.Contains(spec, "size ") {
			t.Errorf("declaração sem teto de tamanho: %q — set alimentado por DNS sem teto é vazamento", spec)
		}
		if !strings.Contains(spec, "flags timeout") {
			t.Errorf("declaração sem prazo: %q — endereço de CDN muda de dono", spec)
		}
	}
}

// TestALeituraDeVoltaExtraiOEnderecoDeSetEDeMap.
//
// Sem a leitura de volta, este arquivo é escrita-só e a tela teria de contar o
// índice em memória do alimentador — que é um espelho, e espelho atrasa: o
// elemento pode ter expirado sozinho, o lote pode ter falhado, alguém pode ter
// dado flush por fora. Quem responde "quantos endereços estão barrados agora" é
// quem barra.
//
// O map é o caso que quebra um parser ingênuo: cada item termina em ` : 0x12c`,
// e o endereço é o PRIMEIRO campo, nunca o último.
func TestALeituraDeVoltaExtraiOEnderecoDeSetEDeMap(t *testing.T) {
	saidaSet := `table inet linkguard {
	set dom_blocked {
		type ipv4_addr
		flags timeout
		timeout 1h
		size 8192
		elements = { 142.250.219.14 timeout 1h expires 59m28s,
			     1.1.1.1 timeout 1h expires 30m }
	}
}`
	got, _ := enderecosNft(saidaSet)
	if len(got) != 2 || got[0].String() != "142.250.219.14" || got[1].String() != "1.1.1.1" {
		t.Fatalf("set lido errado: %v", got)
	}

	saidaMap := `table inet linkguard {
	map dom_wan {
		type ipv4_addr : mark
		elements = { 8.8.8.8 timeout 1h expires 59m : 0x12c }
	}
}`
	got, _ = enderecosNft(saidaMap)
	if len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("map lido errado: %v", got)
	}
}

// TestEstruturaVaziaOuAusenteLeComoVazia, e não como erro.
//
// Estrutura ausente é o estado de toda caixa entre o upgrade e a primeira
// reconciliação. Um erro aqui viraria faixa vermelha na tela por causa de uma
// caixa que está bem.
func TestEstruturaVaziaOuAusenteLeComoVazia(t *testing.T) {
	vazio, ilegiveis := enderecosNft("table inet linkguard {\n\tset dom_blocked {\n\t\ttype ipv4_addr\n\t}\n}")
	if len(vazio) != 0 || ilegiveis != 0 {
		t.Fatalf("set vazio virou %v (%d ilegíveis)", vazio, ilegiveis)
	}
	nada, ilegiveis := enderecosNft("")
	if len(nada) != 0 || ilegiveis != 0 {
		t.Fatalf("saída vazia virou %v (%d ilegíveis)", nada, ilegiveis)
	}
}

// TestOReenvioNaoRepeteOAddDaRenovacao.
//
// Renovar é delete+add na MESMA transação. Quando a transação cai, o reenvio
// entra sem os delete — e repetir ali o add da renovação é emitir exatamente o
// comando que a medição do topo deste arquivo declarou inútil: add sobre
// elemento existente é aceito em silêncio e NÃO mexe no prazo.
//
// Sem esta poda, o reenvio gasta um fork para produzir a ilusão de ter
// renovado, AplicarLote devolve nil, e o índice do chamador passa a acreditar
// num prazo que o kernel não concedeu — voltando a mexer naquele endereço só
// depois de ele já ter vencido lá dentro.
func TestOReenvioNaoRepeteOAddDaRenovacao(t *testing.T) {
	renovado := addr(t, "142.250.219.14")
	novo := addr(t, "5.6.7.8")
	l := Lote{
		RemoverBloq: []netip.Addr{renovado},
		AdicionarBloq: []Entrada{
			{Addr: renovado, Prazo: 30 * time.Minute},
			{Addr: novo, Prazo: 30 * time.Minute},
		},
	}
	soAdds := montarLote(l, false)
	if strings.Contains(soAdds, renovado.String()) {
		t.Errorf("o reenvio repetiu o add da renovação, que não renova nada:\n%s", soAdds)
	}
	if !strings.Contains(soAdds, novo.String()) {
		t.Errorf("o reenvio perdeu a adição que precisava entrar:\n%s", soAdds)
	}
}

// TestOReenvioDizOQueFicouParaTras.
//
// O reenvio é um caminho que devolve nil sem ter feito o que foi pedido. Sem
// ResultadoLote o chamador não tem como saber disso, e as duas metades que
// ficaram para trás são as caras: a renovação que não renovou (o índice acha
// que renovou) e a remoção que não saiu (o kernel continua barrando por até uma
// hora um domínio que a tela já mostra desligado).
func TestOReenvioDizOQueFicouParaTras(t *testing.T) {
	renovado := addr(t, "142.250.219.14")
	saindo := addr(t, "9.9.9.9")
	l := Lote{
		RemoverBloq:   []netip.Addr{renovado, saindo},
		AdicionarBloq: []Entrada{{Addr: renovado, Prazo: 30 * time.Minute}},
		RemoverWan:    []netip.Addr{addr(t, "1.2.3.4")},
	}
	renovacoes := renovacoesDoLote(l)
	if len(renovacoes) != 1 || renovacoes[0] != renovado {
		t.Fatalf("as renovações do lote saíram erradas: %v", renovacoes)
	}
	perdidas := remocoesDoLote(l)
	if len(perdidas) != 2 {
		t.Fatalf("as remoções de verdade saíram erradas: %v", perdidas)
	}
	for _, a := range perdidas {
		if a == renovado {
			t.Errorf("a metade de uma renovação foi contada como remoção perdida: %v", a)
		}
	}
}

// execDom responde por estrutura: uma pode estar ausente, outra pode falhar de
// verdade, e as duas coisas NÃO podem ler igual.
type execDom struct {
	saida map[string]string
	erro  map[string]error
}

func (e *execDom) Execute(context.Context, string, ...string) (string, error) {
	return "", nil
}

func (e *execDom) ExecuteRead(_ context.Context, _ string, args ...string) (string, error) {
	nome := args[len(args)-1]
	return e.saida[nome], e.erro[nome]
}

func (e *execDom) IsDryRun() bool { return false }

func (e *execDom) WriteFile(string, []byte, os.FileMode) error { return nil }

// TestFalhaDeLeituraNaoLeComoEstruturaVazia.
//
// Este é o defeito que a revisão achou: DomElementos engolia TODO erro do nft
// com um continue, justificado por "estrutura ausente não é erro". Só que o
// executor devolve erro genérico também para nft fora do PATH, falta de
// CAP_NET_ADMIN, prazo estourado e ctx cancelado — e todos liam como
// "a estrutura está vazia".
//
// O que sai disso é uma tela dizendo que nada está bloqueado durante uma falha
// de leitura, que é a mentira mais cara que esta tela pode contar, porque o
// operador age em cima dela. Ausente continua sendo vazia; o resto é erro.
func TestFalhaDeLeituraNaoLeComoEstruturaVazia(t *testing.T) {
	e := &execDom{
		saida: map[string]string{
			DomWanMap: "table inet linkguard {\n\tmap dom_wan {\n\t\telements = { 8.8.8.8 timeout 1h : 0x12c }\n\t}\n}",
		},
		erro: map[string]error{
			DomBlockedSet:  errors.New("command failed: Error: No such file or directory"),
			DomBlockedSet6: errors.New("command failed: Operation not permitted"),
		},
	}
	k, err := NewService(e).DomElementos(context.Background())
	if err == nil {
		t.Fatal("a leitura falhou de verdade e DomElementos disse que estava tudo bem")
	}
	if !k.LidoBloq {
		t.Error("estrutura AUSENTE virou falha de leitura — é o estado de toda caixa antes do boot")
	}
	if k.LidoBloq6 {
		t.Error("a estrutura que o kernel recusou ler foi marcada como lida")
	}
	if !k.LidoWan || len(k.Wan) != 1 {
		t.Errorf("a estrutura que respondeu não foi aproveitada: lido=%v wan=%v", k.LidoWan, k.Wan)
	}
	if k.Tudo() {
		t.Error("Tudo() disse que as três foram lidas com uma delas fora")
	}
}

// TestItemIlegivelEhContadoENaoSomeEmSilencio.
//
// enderecosNft descarta o que não parseia, e isso continua certo: uma linha
// estranha na saída do nft não pode virar tela quebrada. O que não pode é o
// descarte ser invisível — len(k.Bloq) é apresentado como a verdade do kernel,
// e um total redondo com um buraco dentro é um número que parece exato e não é.
func TestItemIlegivelEhContadoENaoSomeEmSilencio(t *testing.T) {
	saida := "table inet linkguard {\n\tset dom_blocked {\n\t\telements = { 1.1.1.1 timeout 1h, nao-e-endereco timeout 1h, 8.8.8.8 timeout 1h }\n\t}\n}"
	got, ilegiveis := enderecosNft(saida)
	if len(got) != 2 {
		t.Fatalf("os endereços legíveis se perderam: %v", got)
	}
	if ilegiveis != 1 {
		t.Fatalf("o item ilegível não foi contado: %d", ilegiveis)
	}
}
