package dnstap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Os três formatos que a #116 obriga o produto a entender — Frame Streams,
// protobuf e o formato de fio do DNS — testados contra bytes de verdade,
// montados aqui do zero.

func quadroDados(b []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b)))
	buf.Write(b)
	return buf.Bytes()
}

func quadroControle(tipo uint32) []byte {
	var corpo bytes.Buffer
	binary.Write(&corpo, binary.BigEndian, tipo)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0)) // escape
	binary.Write(&buf, binary.BigEndian, uint32(corpo.Len()))
	buf.Write(corpo.Bytes())
	return buf.Bytes()
}

func TestFrameStreamPulaControleEEntregaDados(t *testing.T) {
	var fluxo bytes.Buffer
	fluxo.Write(quadroControle(controlStart))
	fluxo.Write(quadroDados([]byte("primeiro")))
	fluxo.Write(quadroDados([]byte("segundo")))
	fluxo.Write(quadroControle(controlStop))

	fr := NewReader(&fluxo)
	for _, quer := range []string{"primeiro", "segundo"} {
		got, err := fr.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if string(got) != quer {
			t.Errorf("veio %q, queria %q", got, quer)
		}
	}
	if _, err := fr.Next(); err == nil {
		t.Error("o quadro STOP devia encerrar a leitura")
	}
}

func TestFrameStreamRecusaQuadroAbsurdo(t *testing.T) {
	// Socket corrompido não pode virar alocação de gigabytes.
	var fluxo bytes.Buffer
	binary.Write(&fluxo, binary.BigEndian, uint32(maxFrame+1))
	if _, err := NewReader(&fluxo).Next(); err == nil {
		t.Error("quadro acima do teto foi aceito")
	}
}

// protoBytes monta um campo protobuf do tipo bytes.
func protoBytes(numero uint64, v []byte) []byte {
	var b []byte
	b = binary.AppendUvarint(b, numero<<3|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func protoVarint(numero, v uint64) []byte {
	var b []byte
	b = binary.AppendUvarint(b, numero<<3|0)
	return binary.AppendUvarint(b, v)
}

func TestProtobufAchaARespostaEPulaOResto(t *testing.T) {
	// Mensagem com campos ANTES e DEPOIS do que interessa, dos quatro tipos de
	// fio: pular errado é como um scanner destes se perde em silêncio.
	interna := bytes.Join([][]byte{
		protoVarint(campoMessageType, tipoClientResponse),
		protoBytes(2, []byte("ruído")),
		protoBytes(campoResponseMessage, []byte("FIO-DNS")),
		protoVarint(99, 12345),
	}, nil)
	quadro := bytes.Join([][]byte{
		protoBytes(1, []byte("identidade")),
		protoBytes(campoDnstapMessage, interna),
	}, nil)

	got, err := RespostaDNS(quadro)
	if err != nil {
		t.Fatalf("RespostaDNS: %v", err)
	}
	if string(got) != "FIO-DNS" {
		t.Errorf("veio %q", got)
	}
}

func TestPerguntaNaoEhResposta(t *testing.T) {
	// Metade do tráfego do dnstap é pergunta. Não é falha, é o que não interessa.
	interna := bytes.Join([][]byte{
		protoVarint(campoMessageType, 1), // CLIENT_QUERY
		protoBytes(campoResponseMessage, []byte("nao-devia-sair")),
	}, nil)
	got, err := RespostaDNS(protoBytes(campoDnstapMessage, interna))
	if err != nil {
		t.Fatalf("RespostaDNS: %v", err)
	}
	if got != nil {
		t.Errorf("pergunta tratada como resposta: %q", got)
	}
}

// respostaDNS monta uma resposta de verdade em formato de fio.
func respostaDNS(t *testing.T, nome string, ips []string, cname string, ttl uint32) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess})
	b.EnableCompression()
	n := dnsmessage.MustNewName(nome)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if cname != "" {
		b.CNAMEResource(
			dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(cname)})
	}
	for _, ip := range ips {
		a := netip.MustParseAddr(ip)
		alvo := n
		if cname != "" {
			alvo = dnsmessage.MustNewName(cname)
		}
		b.AResource(
			dnsmessage.ResourceHeader{Name: alvo, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.AResource{A: a.As4()})
	}
	fio, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return fio
}

func TestONomeQueValeEhOPerguntado(t *testing.T) {
	// A ASSERÇÃO DE PRODUTO DESTE PACOTE. Quem perguntou por video.exemplo.com
	// e recebeu CNAME para edge-3.cdn.net quer ler o PRIMEIRO na tela: o
	// segundo muda a cada resolução, é compartilhado por milhares de sites e
	// não diz nada a quem opera. Guardar o fim da cadeia daria um mapa
	// tecnicamente correto e inútil.
	fio := respostaDNS(t, "video.exemplo.com.", []string{"142.250.1.1"}, "edge-3.cdn.net.", 300)
	r, err := Extrair(fio)
	if err != nil {
		t.Fatalf("Extrair: %v", err)
	}
	if r == nil {
		t.Fatal("resposta com A não ensinou nada")
	}
	if r.Nome != "video.exemplo.com" {
		t.Errorf("guardou %q; o nome que vale é o perguntado", r.Nome)
	}
	if len(r.Enderecos) != 1 || r.Enderecos[0].String() != "142.250.1.1" {
		t.Errorf("endereços: %v", r.Enderecos)
	}
}

func TestRespostaSemEnderecoNaoEnsinaNada(t *testing.T) {
	fio := respostaDNS(t, "sem-a.exemplo.com.", nil, "so-cname.exemplo.com.", 60)
	r, err := Extrair(fio)
	if err != nil {
		t.Fatalf("Extrair: %v", err)
	}
	if r != nil {
		t.Errorf("resposta só com CNAME virou entrada no mapa: %+v", r)
	}
}

func TestMapaEsqueceQuandoOPrazoVence(t *testing.T) {
	// O PONTO DO PRAZO. Endereço de CDN é de um site hoje e de outro daqui a
	// dez minutos. Um mapa sem prazo transforma "este endereço FOI de X" em
	// "este endereço É de X" — confiança crescente, correção decrescente.
	m := NovoMapa()
	agora := time.Now()
	m.agora = func() time.Time { return agora }

	m.Aprender(&Resposta{Nome: "exemplo.com", Enderecos: []netip.Addr{netip.MustParseAddr("1.2.3.4")}, TTL: time.Minute})
	if n, ok := m.Nome(netip.MustParseAddr("1.2.3.4")); !ok || n != "exemplo.com" {
		t.Fatalf("não aprendeu: %q %v", n, ok)
	}

	// O piso de 5 min vale sobre o TTL de 1 min: aos 4 minutos ainda sabe.
	agora = agora.Add(4 * time.Minute)
	if _, ok := m.Nome(netip.MustParseAddr("1.2.3.4")); !ok {
		t.Error("esqueceu antes do piso de TTL")
	}
	agora = agora.Add(2 * time.Minute)
	if n, ok := m.Nome(netip.MustParseAddr("1.2.3.4")); ok {
		t.Errorf("continuou afirmando %q depois do prazo", n)
	}
}

func TestMapaDizQuandoEncheEmVezDeSumirEmSilencio(t *testing.T) {
	// Sem o aviso, um endereço ausente parece "nunca foi consultado" quando
	// pode ser "foi, e saiu para caber outro".
	m := NovoMapa()
	if e := m.Estado(); e.Cheio {
		t.Error("mapa vazio já se diz cheio")
	}
	for i := 0; i < MaxEntradas+10; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		m.Aprender(&Resposta{Nome: "x.exemplo.com", Enderecos: []netip.Addr{a}, TTL: time.Hour})
	}
	e := m.Estado()
	if !e.Cheio {
		t.Error("o mapa encheu e não diz isso: a tela mentiria por omissão")
	}
	if e.Entradas > MaxEntradas {
		t.Errorf("passou do teto: %d", e.Entradas)
	}
}

// conexaoFalsa é um io.ReadWriter: o leitor consome o que o "remetente"
// escreveu, e o que a gente responde fica registrado.
type conexaoFalsa struct {
	entrada  *bytes.Buffer
	resposta bytes.Buffer
}

func (c *conexaoFalsa) Read(p []byte) (int, error)  { return c.entrada.Read(p) }
func (c *conexaoFalsa) Write(p []byte) (int, error) { return c.resposta.Write(p) }

// TestREADYEhRespondidoComACCEPT é a regressão do defeito que segurou a #116 por
// quatro validações.
//
// Em modo BIDIRECIONAL — que é o que o unbound usa — o remetente manda READY e
// FICA ESPERANDO um ACCEPT. Sem a resposta ele nunca envia dado nenhum, e nunca
// reclama: do ponto de vista dele a conversa apenas não começou.
//
// O sintoma medido na VM era o pior possível: socket conectado, unbound
// registrando "dnstap Message/CLIENT_RESPONSE enabled", consultas resolvendo, e
// o mapa vazio. Tudo verde dos dois lados.
func TestREADYEhRespondidoComACCEPT(t *testing.T) {
	// O READY do remetente carrega os tipos de conteúdo que ele sabe enviar.
	campos := []byte("\x00\x00\x00\x01\x00\x00\x00\x15protobuf:dnstap.Dnstap")
	var corpo bytes.Buffer
	binary.Write(&corpo, binary.BigEndian, uint32(controlReady))
	corpo.Write(campos)

	var fluxo bytes.Buffer
	binary.Write(&fluxo, binary.BigEndian, uint32(0)) // escape
	binary.Write(&fluxo, binary.BigEndian, uint32(corpo.Len()))
	fluxo.Write(corpo.Bytes())
	fluxo.Write(quadroControle(controlStart))
	fluxo.Write(quadroDados([]byte("carga")))

	c := &conexaoFalsa{entrada: &fluxo}
	fr := NewReader(c)

	got, err := fr.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(got) != "carga" {
		t.Errorf("dado veio %q", got)
	}

	// A resposta tem de ser um quadro de controle ACCEPT.
	resp := c.resposta.Bytes()
	if len(resp) < 12 {
		t.Fatalf("nada foi respondido ao READY (%d bytes): o remetente esperaria para sempre", len(resp))
	}
	if escape := binary.BigEndian.Uint32(resp[0:4]); escape != 0 {
		t.Errorf("a resposta não começa com o escape de controle: %d", escape)
	}
	if tipo := binary.BigEndian.Uint32(resp[8:12]); tipo != controlAccept {
		t.Errorf("respondeu tipo %d, queria ACCEPT (%d)", tipo, controlAccept)
	}
	// E ecoa os tipos de conteúdo que o remetente ofereceu: confirmar o que ele
	// propôs evita a gente ter de conhecer a lista dele.
	if !bytes.Contains(resp, []byte("protobuf:dnstap.Dnstap")) {
		t.Error("o ACCEPT não ecoou o tipo de conteúdo oferecido")
	}
}

func TestSemEscritorOModoUnidirecionalContinuaFuncionando(t *testing.T) {
	// NewReader aceita io.Reader para os testes usarem um buffer. Sem escritor,
	// a resposta é pulada e o fluxo unidirecional segue — não pode virar erro.
	var fluxo bytes.Buffer
	fluxo.Write(quadroControle(controlStart))
	fluxo.Write(quadroDados([]byte("unidirecional")))
	got, err := NewReader(&fluxo).Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(got) != "unidirecional" {
		t.Errorf("veio %q", got)
	}
}

// quadroRealDoUnbound é um quadro dnstap capturado do unbound 1.22 rodando na
// VM de validação, respondendo uma consulta A por debian.org. Está aqui inteiro,
// em bytes, porque foi exatamente aqui que o produto errou: o filtro de tipo de
// mensagem usava 5 (CLIENT_QUERY) achando que era CLIENT_RESPONSE, e um teste
// que MONTA o quadro com a mesma constante que testa concorda com qualquer
// número. Um quadro de verdade não concorda.
const quadroRealDoUnbound = "72810108061001180122047f0000012a047f00000130b980033835" +
	"6097c6a6d4066db01d1301725c1234818000010004000000000664656269616e036f726700" +
	"00010001c00c0001000100000126000497658284c00c000100010000012600049765c284c0" +
	"0c0001000100000126000497654284c00c00010001000001260004976502847801"

func TestQuadroRealDoUnboundChegaAoMapa(t *testing.T) {
	quadro := make([]byte, hex.DecodedLen(len(quadroRealDoUnbound)))
	if _, err := hex.Decode(quadro, []byte(quadroRealDoUnbound)); err != nil {
		t.Fatalf("hex: %v", err)
	}

	fio, err := RespostaDNS(quadro)
	if err != nil {
		t.Fatalf("RespostaDNS: %v", err)
	}
	if fio == nil {
		t.Fatal("o quadro real foi descartado como se não fosse resposta")
	}

	r, err := Extrair(fio)
	if err != nil {
		t.Fatalf("Extrair: %v", err)
	}
	if r == nil {
		t.Fatal("nada aprendido de uma resposta com quatro registros A")
	}
	if r.Nome != "debian.org" {
		t.Errorf("nome %q, esperado debian.org", r.Nome)
	}
	querido := map[string]bool{
		"151.101.130.132": true, "151.101.194.132": true,
		"151.101.66.132": true, "151.101.2.132": true,
	}
	if len(r.Enderecos) != len(querido) {
		t.Fatalf("vieram %d endereços: %v", len(r.Enderecos), r.Enderecos)
	}
	for _, a := range r.Enderecos {
		if !querido[a.String()] {
			t.Errorf("endereço inesperado %s", a)
		}
	}
	if r.TTL != 294*time.Second {
		t.Errorf("TTL %v, esperado 294s (o menor dos quatro registros)", r.TTL)
	}
}

func TestClientQueryNaoEhClientResponse(t *testing.T) {
	// Os números estão literais de propósito, e é o par vizinho que o teste
	// trava: 5 é CLIENT_QUERY e 6 é CLIENT_RESPONSE, 3 é RESOLVER_QUERY e 4 é
	// RESOLVER_RESPONSE. Trocar um pelo outro faz o coletor descartar tudo em
	// silêncio, que foi o que aconteceu.
	for _, c := range []struct {
		nome   string
		tipo   uint64
		aceita bool
	}{
		{"AUTH_QUERY", 1, false},
		{"AUTH_RESPONSE", 2, false},
		{"RESOLVER_QUERY", 3, false},
		{"RESOLVER_RESPONSE", 4, true},
		{"CLIENT_QUERY", 5, false},
		{"CLIENT_RESPONSE", 6, true},
	} {
		interna := bytes.Join([][]byte{
			protoVarint(campoMessageType, c.tipo),
			protoBytes(campoResponseMessage, []byte("FIO")),
		}, nil)
		got, err := RespostaDNS(protoBytes(campoDnstapMessage, interna))
		if err != nil {
			t.Fatalf("%s: %v", c.nome, err)
		}
		if (got != nil) != c.aceita {
			t.Errorf("%s (tipo %d): aceito=%v, esperado=%v", c.nome, c.tipo, got != nil, c.aceita)
		}
	}
}
