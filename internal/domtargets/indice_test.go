package domtargets

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

func end(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("endereço inválido no teste: %s", s)
	}
	return a
}

// relogio é um agora() controlado — envelhecer um prazo com time.Sleep faria o
// teste da renovação levar minutos.
type relogio struct{ t time.Time }

func (r *relogio) agora() time.Time      { return r.t }
func (r *relogio) andar(d time.Duration) { r.t = r.t.Add(d) }

func novoRelogio() *relogio {
	return &relogio{t: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
}

func indiceCom(t *testing.T, rel *relogio, alvos ...Alvo) *Indice {
	t.Helper()
	var agora func() time.Time
	if rel != nil {
		agora = rel.agora
	}
	i := NovoIndice(agora)
	i.DefinirAlvos(alvos)
	return i
}

// TestSufixoNaoCasaNomeQueApenasTerminaIgual prende o defeito de casar com
// strings.HasSuffix cru.
//
// `evilnetflix.com` termina em `netflix.com`. Um casamento por sufixo de
// STRING trataria como Netflix um domínio que qualquer um registra em cinco
// minutos — e no direcionamento isso é mandar o tráfego de um site hostil pela
// WAN que o admin reservou para o serviço legítimo.
func TestSufixoNaoCasaNomeQueApenasTerminaIgual(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "netflix.com", Estagio: Ativo})
	if _, ok := i.Casar("evilnetflix.com"); ok {
		t.Fatal("evilnetflix.com casou com netflix.com")
	}
	if _, ok := i.Casar("netflixcom.br"); ok {
		t.Fatal("netflixcom.br casou com netflix.com")
	}
}

// TestSufixoCasaOProprioDominioEOsSubdominios é o outro lado: exigir fronteira
// de rótulo não pode passar do ponto e deixar o nome listado de fora.
func TestSufixoCasaOProprioDominioEOsSubdominios(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "netflix.com", Estagio: Ativo})
	for _, nome := range []string{"netflix.com", "www.netflix.com", "a.b.netflix.com", "WWW.NETFLIX.COM", "www.netflix.com."} {
		if _, ok := i.Casar(nome); !ok {
			t.Errorf("%q não casou com netflix.com", nome)
		}
	}
}

// TestOMaisEspecificoGanha prende a regra que decide entre duas entradas que
// cobrem o mesmo nome. Sem ela, qual das duas vale dependeria da ordem de
// iteração de um mapa — e o domínio trocaria de tratamento sozinho.
func TestOMaisEspecificoGanha(t *testing.T) {
	i := indiceCom(t, nil,
		Alvo{Dominio: "netflix.com", Capacidade: Barrar, Estagio: Ativo},
		Alvo{Dominio: "assistir.netflix.com", Capacidade: Direcionar, Marca: 0x12c, Estagio: Ativo},
	)
	a, ok := i.Casar("assistir.netflix.com")
	if !ok || a.Dominio != "assistir.netflix.com" || a.Capacidade != Direcionar {
		t.Fatalf("o mais específico não ganhou: %+v ok=%v", a, ok)
	}
	b, _ := i.Casar("outro.netflix.com")
	if b.Dominio != "netflix.com" {
		t.Fatalf("o menos específico não cobriu o resto: %+v", b)
	}
}

// TestDominioDeUmRotuloSoEhRecusado prende o alcance de um erro de digitação.
//
// Como o casamento é por sufixo em fronteira de rótulo, listar `com` casaria
// com a internet inteira — e barrar `com` é derrubar a rede do cliente com um
// campo de três letras.
func TestDominioDeUmRotuloSoEhRecusado(t *testing.T) {
	for _, d := range []string{"com", "localhost", "", ".", "  ", "*.exemplo.com", "exemplo com", "exemplo..com"} {
		if _, ok := NormalizarDominio(d); ok {
			t.Errorf("%q foi aceito como domínio", d)
		}
	}
	if d, ok := NormalizarDominio("  WWW.Exemplo.COM.  "); !ok || d != "www.exemplo.com" {
		t.Errorf("normalização errada: %q ok=%v", d, ok)
	}
}

// TestEnderecoQueNaoPodeVirarRegraNuncaEhAceito é o teste mais importante do
// pacote.
//
// O endereço vem de uma resposta de DNS, quer dizer: de um servidor escolhido
// por quem registrou o nome. Sem este filtro, o admin lista um domínio, o dono
// dele responde 192.168.0.1, e o firewall do cliente passa a barrar a própria
// LAN a mando de um terceiro. As formas embutidas (v4 dentro de v6, 6to4,
// Teredo, NAT64) estão aqui porque são exatamente o jeito de contrabandear um
// endereço de LAN por baixo de um filtro que só olha v4.
func TestEnderecoQueNaoPodeVirarRegraNuncaEhAceito(t *testing.T) {
	proibidos := []string{
		"192.168.0.1", "10.0.0.1", "172.16.0.1", // RFC1918
		"127.0.0.1", "169.254.1.1", "0.0.0.0", // loopback, link-local, indefinido
		"100.64.0.1",             // CGNAT
		"224.0.0.1", "239.1.2.3", // multicast
		"255.255.255.255", "240.0.0.1", // reservado
		"0.1.2.3", "192.0.2.5", "198.51.100.7", "203.0.113.9", "198.18.0.1",
		"::1", "fd00::1", "fe80::1", "::",
		"ff02::1",            // multicast v6
		"::ffff:192.168.0.1", // v4 embutido em v6
		"2002:c0a8:0001::1",  // 6to4 carregando 192.168.0.1
		"2001:0:1:2:3:4:5:6", // Teredo
		"64:ff9b::c0a8:1",    // NAT64 carregando 192.168.0.1
		"2001:db8::1",        // documentação
	}
	for _, s := range proibidos {
		if Utilizavel(end(t, s)) {
			t.Errorf("%s foi aceito e não podia", s)
		}
	}
	if Utilizavel(netip.Addr{}) {
		t.Error("o endereço zero foi aceito")
	}
	for _, s := range []string{"8.8.8.8", "142.250.219.14", "2606:4700::1111", "2a00:1450:4001::200e"} {
		if !Utilizavel(end(t, s)) {
			t.Errorf("%s foi recusado e é um endereço público legítimo", s)
		}
	}
}

// TestEnderecoRecusadoNaoViraEscritaEApareceNoContador prende as duas metades:
// ele não vai para o kernel, E o admin consegue ver que aconteceu. Recusa
// silenciosa vira "por que este domínio não bloqueia?" sem resposta.
func TestEnderecoRecusadoNaoViraEscritaEApareceNoContador(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "hostil.com", Estagio: Ativo})
	aj := i.Aprender("hostil.com", []netip.Addr{
		end(t, "192.168.3.1"), end(t, "8.8.8.8"), end(t, "224.0.0.1"),
	}, time.Minute)
	es := aj.Escritas
	if len(es) != 1 || es[0].Addr != end(t, "8.8.8.8") {
		t.Fatalf("escreveu o que não podia: %+v", es)
	}
	c := i.Contadores()
	if c.Recusados != 2 || c.Recusados4 != 2 {
		t.Fatalf("os recusados não apareceram no contador: %+v", c)
	}
}

// TestDominioEmEnsaioNaoEscreveNoKernel prende a promessa do estágio.
//
// Ensaio é o que separa "listei para ver o que acontece" de "liguei um
// bloqueio". Se ensaio escrevesse, o admin descobriria o alcance de um domínio
// de CDN pelo telefone tocando, que é exatamente o que ele existe para evitar.
func TestDominioEmEnsaioNaoEscreveNoKernel(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "cdn-de-tudo.net", Capacidade: Barrar, Estagio: Ensaio})
	aj := i.Aprender("www.cdn-de-tudo.net", []netip.Addr{end(t, "8.8.8.8")}, time.Hour)
	if !aj.Vazio() {
		t.Fatalf("um domínio em ensaio produziu escrita: %+v", aj)
	}
	if n, _ := i.Rotatividade("cdn-de-tudo.net"); n != 1 {
		t.Fatalf("o ensaio deixou de aprender: rotatividade=%d", n)
	}
}

// TestDominioSemEstagioNasceEmEnsaio prende o lado seguro do valor em branco.
// Uma linha vinda de um backup antigo, sem a coluna, não pode chegar ligada.
func TestDominioSemEstagioNasceEmEnsaio(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "exemplo.com"})
	a, _ := i.Casar("exemplo.com")
	if a.Estagio != Ensaio {
		t.Fatalf("nasceu fora do ensaio: %q", a.Estagio)
	}
	if aj := i.Aprender("exemplo.com", []netip.Addr{end(t, "8.8.8.8")}, time.Hour); !aj.Vazio() {
		t.Fatalf("escreveu sem estágio definido: %+v", aj)
	}
}

// TestReensinarEnderecoFrescoNaoGeraComando prende a decisão de 1/3.
//
// Sem ela, cada resposta repetida vira um delete+add: um domínio popular com
// TTL de 30 segundos e vinte clientes na rede geraria dezenas de forks de nft
// por minuto para não mudar nada — e cada fork é uma transação netlink na
// tabela que decide o tráfego da caixa.
func TestReensinarEnderecoFrescoNaoGeraComando(t *testing.T) {
	rel := novoRelogio()
	i := indiceCom(t, rel, Alvo{Dominio: "popular.com", Estagio: Ativo})
	a := []netip.Addr{end(t, "8.8.8.8")}

	if aj := i.Aprender("popular.com", a, 30*time.Second); len(aj.Escritas) != 1 {
		t.Fatalf("a primeira vez tinha de escrever: %+v", aj)
	}
	// O prazo concedido é o piso, 10 minutos. Vinte reensinos nos primeiros
	// seis minutos não podem produzir um comando sequer.
	for n := 0; n < 20; n++ {
		rel.andar(18 * time.Second)
		if aj := i.Aprender("popular.com", a, 30*time.Second); !aj.Vazio() {
			t.Fatalf("reensino %d gerou comando com %v de prazo restante", n, nftables.DomTTLPiso)
		}
	}
	if c := i.Contadores(); c.SemComando != 20 {
		t.Fatalf("a economia não foi contada: %+v", c)
	}
}

// TestRenovaSoQuandoRestaMenosDeUmTerco, e renova com Substituir.
//
// O Substituir é o que vira `delete` antes do `add`. Medido no nft da caixa: um
// `add` sobre elemento existente é aceito em silêncio e NÃO mexe no prazo — sem
// o delete junto, "renovar" seria um comando que não faz nada e o endereço
// sairia no meio do uso.
func TestRenovaSoQuandoRestaMenosDeUmTerco(t *testing.T) {
	rel := novoRelogio()
	i := indiceCom(t, rel, Alvo{Dominio: "exemplo.com", Estagio: Ativo})
	a := []netip.Addr{end(t, "8.8.8.8")}
	i.Aprender("exemplo.com", a, time.Hour) // prazo concedido: 1h (o teto)

	rel.andar(39 * time.Minute) // restam 21 min, mais de 1/3 de 60
	if aj := i.Aprender("exemplo.com", a, time.Hour); !aj.Vazio() {
		t.Fatalf("renovou cedo demais: %+v", aj)
	}
	rel.andar(2 * time.Minute) // restam 19 min, menos de 1/3
	es := i.Aprender("exemplo.com", a, time.Hour).Escritas
	if len(es) != 1 {
		t.Fatalf("não renovou quando devia: %+v", es)
	}
	if !es[0].Substituir {
		t.Fatal("a renovação saiu sem Substituir — viraria um add que o nft aceita e ignora")
	}
}

// TestPrazoEhGrampeadoEntrePisoETeto prende que o TTL escolhido por um
// TERCEIRO não chega cru no kernel.
func TestPrazoEhGrampeadoEntrePisoETeto(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "exemplo.com", Estagio: Ativo})
	es := i.Aprender("exemplo.com", []netip.Addr{end(t, "8.8.8.8")}, 30*time.Second).Escritas
	if es[0].Prazo != nftables.DomTTLPiso {
		t.Errorf("TTL curto não subiu ao piso: %v", es[0].Prazo)
	}
	es = i.Aprender("exemplo.com", []netip.Addr{end(t, "1.1.1.1")}, 30*24*time.Hour).Escritas
	if es[0].Prazo != nftables.DomTTLTeto {
		t.Errorf("TTL absurdo não desceu ao teto: %v", es[0].Prazo)
	}
}

// TestRefcountMantemEnderecoEnquantoOutroDominioReivindica.
//
// Dois domínios listados podem ser servidos pelo mesmo endereço. Tirar um da
// lista e levar o endereço junto DESBLOQUEARIA o outro em silêncio — a tela
// continuaria mostrando o segundo como barrado e ele deixaria de barrar.
func TestRefcountMantemEnderecoEnquantoOutroDominioReivindica(t *testing.T) {
	i := indiceCom(t, nil,
		Alvo{Dominio: "um.com", Capacidade: Barrar, Estagio: Ativo},
		Alvo{Dominio: "dois.com", Capacidade: Barrar, Estagio: Ativo},
	)
	compartilhado := []netip.Addr{end(t, "8.8.8.8")}
	i.Aprender("um.com", compartilhado, time.Hour)
	if aj := i.Aprender("dois.com", compartilhado, time.Hour); !aj.Vazio() {
		t.Fatalf("o segundo dono gerou comando à toa: %+v", aj)
	}

	// Sai o primeiro domínio; o endereço continua reivindicado pelo segundo.
	aj := i.DefinirAlvos([]Alvo{{Dominio: "dois.com", Capacidade: Barrar, Estagio: Ativo}})
	if len(aj.Remocoes) != 0 {
		t.Fatalf("o endereço saiu com um dono ainda reivindicando: %+v", aj.Remocoes)
	}
	// Agora sai o segundo, e aí sim o endereço tem de sair do kernel.
	aj = i.DefinirAlvos(nil)
	if len(aj.Remocoes) != 1 || aj.Remocoes[0].Addr != end(t, "8.8.8.8") {
		t.Fatalf("o último dono saiu e o endereço ficou: %+v", aj.Remocoes)
	}
}

// TestBaixarParaEnsaioTiraOsEnderecosDoKernelNaHora.
//
// Deixar para o vencimento manteria até uma hora de bloqueio depois de o admin
// ter desligado o bloqueio — com a tela já dizendo que está desligado, que é o
// pior tipo de defeito de firewall.
func TestBaixarParaEnsaioTiraOsEnderecosDoKernelNaHora(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ativo})
	i.Aprender("exemplo.com", []netip.Addr{end(t, "8.8.8.8")}, time.Hour)

	aj := i.DefinirAlvos([]Alvo{{Dominio: "exemplo.com", Capacidade: Barrar, Estagio: Ensaio}})
	if len(aj.Remocoes) != 1 || aj.Remocoes[0].Capacidade != Barrar {
		t.Fatalf("baixar para ensaio não tirou o endereço: %+v", aj)
	}
}

// TestBarrarGanhaDeDirecionarNoMesmoEndereco.
//
// Bloquear é uma promessa de negação; direcionar é uma preferência de saída. Se
// o mesmo endereço serve um nome barrado e um direcionado, honrar o
// direcionamento seria desbloquear em silêncio o que o admin mandou bloquear.
func TestBarrarGanhaDeDirecionarNoMesmoEndereco(t *testing.T) {
	i := indiceCom(t, nil,
		Alvo{Dominio: "rota.com", Capacidade: Direcionar, Marca: 0x12c, Estagio: Ativo},
		Alvo{Dominio: "barrado.com", Capacidade: Barrar, Estagio: Ativo},
	)
	a := []netip.Addr{end(t, "8.8.8.8")}
	if aj := i.Aprender("rota.com", a, time.Hour); aj.Escritas[0].Capacidade != Direcionar {
		t.Fatalf("o primeiro dono não direcionou: %+v", aj)
	}
	aj := i.Aprender("barrado.com", a, time.Hour)
	if len(aj.Escritas) != 1 || aj.Escritas[0].Capacidade != Barrar {
		t.Fatalf("barrar não ganhou de direcionar: %+v", aj)
	}
	if aj.Escritas[0].Substituir {
		t.Fatal("a troca de estrutura saiu com Substituir — apagaria do set errado")
	}
	// E a metade que falta: ele TEM de sair do map de direcionamento, senão
	// fica barrado e direcionado ao mesmo tempo até vencer sozinho.
	if len(aj.Remocoes) != 1 || aj.Remocoes[0].Capacidade != Direcionar {
		t.Fatalf("a troca não tirou o endereço da estrutura antiga: %+v", aj.Remocoes)
	}
}

// TestTetoPorDominioApareceNoContador.
//
// Um domínio que bate no teto não está sendo bloqueado de verdade — ele tem
// mais endereços do que cabe. O que o admin precisa é do contador, não de um
// set cheio que bloqueia metade e parece funcionar.
func TestTetoPorDominioApareceNoContador(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "cdn.com", Estagio: Ativo})
	for n := 0; n < MaxPorDominio+5; n++ {
		a := netip.AddrFrom4([4]byte{8, 0, byte(n >> 8), byte(n%250 + 1)})
		i.Aprender("cdn.com", []netip.Addr{a}, time.Hour)
	}
	c := i.Contadores()
	if c.Novos != MaxPorDominio {
		t.Fatalf("entrou endereço acima do teto do domínio: novos=%d", c.Novos)
	}
	if c.EstouroPorDominio != 5 {
		t.Fatalf("o estouro por domínio não apareceu: %+v", c)
	}
}

// TestTetoGlobalApareceNoContador prende o teto que impede o índice de passar
// do `size` das estruturas do kernel — onde a recusa viria do nft, no meio de
// um lote, derrubando junto os endereços que caberiam.
func TestTetoGlobalApareceNoContador(t *testing.T) {
	var alvos []Alvo
	nDominios := MaxEnderecos/MaxPorDominio + 1
	for d := 0; d < nDominios; d++ {
		alvos = append(alvos, Alvo{Dominio: fmt.Sprintf("d%d.com", d), Estagio: Ativo})
	}
	i := indiceCom(t, nil, alvos...)

	n := 0
	for d := 0; d < nDominios; d++ {
		for k := 0; k < MaxPorDominio; k++ {
			a := netip.AddrFrom4([4]byte{8, byte(n >> 16), byte(n >> 8), byte(n)})
			i.Aprender(fmt.Sprintf("d%d.com", d), []netip.Addr{a}, time.Hour)
			n++
		}
	}
	c := i.Contadores()
	if c.Novos != MaxEnderecos {
		t.Fatalf("o índice passou do teto global: novos=%d", c.Novos)
	}
	if c.EstouroGlobal == 0 {
		t.Fatal("o estouro global não apareceu no contador")
	}
}

// TestRotatividadeContaDistintosInclusiveEmEnsaio.
//
// A rotatividade é o número que diz se casar por domínio faz sentido para
// aquele nome: 3 é um servidor, 300 é uma CDN que serve outros mil sites. Ela
// TEM de ser contada em ensaio — é exatamente o que o ensaio existe para
// mostrar antes de o admin promover.
func TestRotatividadeContaDistintosInclusiveEmEnsaio(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "cdn.com", Estagio: Ensaio})
	for n := 0; n < 10; n++ {
		a := netip.AddrFrom4([4]byte{8, 1, 0, byte(n + 1)})
		i.Aprender("cdn.com", []netip.Addr{a}, time.Minute)
	}
	// Repetir o mesmo endereço não conta duas vezes.
	i.Aprender("cdn.com", []netip.Addr{netip.AddrFrom4([4]byte{8, 1, 0, 1})}, time.Minute)
	n, truncada := i.Rotatividade("cdn.com")
	if n != 10 || truncada {
		t.Fatalf("rotatividade errada: %d truncada=%v", n, truncada)
	}
}

// TestRotatividadeTruncadaAvisaEmVezDeMentirUmNumeroParado.
//
// Sem o aviso, um domínio que estourou o teto de lembrança mostraria para
// sempre o mesmo número, e o admin leria "estabilizou" onde o certo é "não sei
// mais contar" — que é a leitura oposta.
func TestRotatividadeTruncadaAvisaEmVezDeMentirUmNumeroParado(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "cdn.com", Estagio: Ensaio})
	for n := 0; n < MaxRotatividadeLembrada+10; n++ {
		a := netip.AddrFrom4([4]byte{8, byte(n >> 8), byte(n), 1})
		i.Aprender("cdn.com", []netip.Addr{a}, time.Minute)
	}
	n, truncada := i.Rotatividade("cdn.com")
	if n != MaxRotatividadeLembrada || !truncada {
		t.Fatalf("a truncagem não foi avisada: %d truncada=%v", n, truncada)
	}
}

// TestPodarNaoEsqueceAntesDaFolga prende a corrida entre dois relógios.
//
// O prazo do kernel começa a correr quando o `nft -f` chega — uma janela de
// coalescência e um fork depois de o índice ter marcado o vencimento. Se o
// índice esquecesse no instante exato, o reensino seguinte sairia como `add`
// sem `delete`, que o nft aceita EM SILÊNCIO e não renova: o endereço sairia do
// set no meio do uso, com tudo parecendo ter funcionado.
func TestPodarNaoEsqueceAntesDaFolga(t *testing.T) {
	rel := novoRelogio()
	i := indiceCom(t, rel, Alvo{Dominio: "exemplo.com", Estagio: Ativo})
	a := []netip.Addr{end(t, "8.8.8.8")}
	i.Aprender("exemplo.com", a, nftables.DomTTLPiso)

	rel.andar(nftables.DomTTLPiso + FolgaDePoda/2)
	if n := i.Podar(); n != 0 {
		t.Fatalf("podou dentro da folga: %d", n)
	}
	es := i.Aprender("exemplo.com", a, nftables.DomTTLPiso).Escritas
	if len(es) != 1 || !es[0].Substituir {
		t.Fatalf("o reensino dentro da folga não saiu como renovação: %+v", es)
	}

	// Passada a folga com o prazo vencido, o índice esquece — senão o refcount
	// e os tetos cresceriam guardando o que o kernel já não tem.
	rel.andar(nftables.DomTTLPiso + 2*FolgaDePoda)
	if n := i.Podar(); n != 1 {
		t.Fatalf("não podou o que já venceu: %d", n)
	}
	if len(i.ends) != 0 || len(i.porDominio) != 0 {
		t.Fatalf("a poda deixou sujeira: ends=%d porDominio=%v", len(i.ends), i.porDominio)
	}
}

// TestReivindicantesCreditaOKernelEContaOrfaos.
//
// É o que deixa a tela dizer "netflix.com: 12 barrados agora" com o 12 vindo do
// kernel. E o que o kernel tem e ninguém reivindica precisa APARECER: é um
// bloqueio valendo sem dono, sobra de um flush perdido ou de um reinício.
func TestReivindicantesCreditaOKernelEContaOrfaos(t *testing.T) {
	i := indiceCom(t, nil, Alvo{Dominio: "exemplo.com", Estagio: Ativo})
	i.Aprender("exemplo.com", []netip.Addr{end(t, "8.8.8.8"), end(t, "1.1.1.1")}, time.Hour)

	porDominio, orfaos := i.Reivindicantes([]netip.Addr{
		end(t, "8.8.8.8"), end(t, "1.1.1.1"), end(t, "9.9.9.9"),
	})
	if porDominio["exemplo.com"] != 2 {
		t.Fatalf("crédito errado: %v", porDominio)
	}
	if orfaos != 1 {
		t.Fatalf("o órfão não apareceu: %d", orfaos)
	}
}
