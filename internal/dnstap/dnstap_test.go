package dnstap

import (
	"bytes"
	"encoding/binary"
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
