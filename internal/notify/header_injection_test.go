package notify

import (
	"mime"
	"strings"
	"testing"
)

// go/email-injection (alerta #2 do CodeQL): cinco valores eram interpolados em
// cabeçalhos RFC822 por fmt.Sprintf, sem nenhum tratamento.
//
// Um "\r\n" em qualquer um deles encerra o cabeçalho, e o servidor SMTP lê o
// que vem depois como diretiva nova — um "Bcc:" mandando cópia para um
// terceiro, ou uma linha em branco que empurra o resto da notificação para o
// corpo, escondendo-a de quem lê o assunto.

func TestEncodeSubjectNeutralizaQuebraDeLinha(t *testing.T) {
	got := encodeSubject("Alerta\r\nBcc: atacante@exemplo.tld")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("o assunto codificado ainda tem quebra de linha: %q", got)
	}
	// O conteúdo não some — ele vira texto codificado, decodificável por quem
	// recebe. Apagá-lo esconderia do operador o que alguém tentou fazer.
	dec, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil {
		t.Fatalf("o assunto não é RFC 2047 válido: %v", err)
	}
	if !strings.Contains(dec, "Bcc: atacante@exemplo.tld") || !strings.Contains(dec, "Alerta") {
		t.Errorf("o texto se perdeu na codificação: %q", dec)
	}
}

// TestEncodeSubjectCodificaAcento cobre um defeito que existia desde sempre e
// não tinha nada a ver com injeção: o assunto ia CRU no cabeçalho, então
// "Configuração inválida" viajava como UTF-8 puro num campo que a RFC 5322
// define como US-ASCII.
func TestEncodeSubjectCodificaAcento(t *testing.T) {
	got := encodeSubject("Configuração inválida")
	for _, r := range got {
		if r > 127 {
			t.Fatalf("sobrou byte não-ASCII no cabeçalho: %q", got)
		}
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil {
		t.Fatalf("não decodifica: %v", err)
	}
	if dec != "Configuração inválida" {
		t.Errorf("ida e volta perdeu o texto: %q", dec)
	}
}

func TestEncodeSubjectDeixaASCIIIntacto(t *testing.T) {
	// Assunto que já é ASCII não é codificado à toa — quem lê o log do servidor
	// SMTP continua vendo o texto.
	if got := encodeSubject("WAN1 caiu"); got != "WAN1 caiu" {
		t.Errorf("assunto ASCII foi codificado sem precisar: %q", got)
	}
}

func TestHeaderAddressCanonizaEValida(t *testing.T) {
	if got := headerAddress("admin@empresa.com.br"); !strings.Contains(got, "admin@empresa.com.br") {
		t.Errorf("endereço válido foi alterado: %q", got)
	}
	// Endereço com tentativa de injeção não parseia; sobra o texto sem os bytes
	// que quebram cabeçalho.
	got := headerAddress("a@b.tld\r\nBcc: c@d.tld")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("quebra de linha sobreviveu no endereço: %q", got)
	}
}

func TestHeaderAddressListPreservaVarios(t *testing.T) {
	got := headerAddressList("a@x.tld, b@y.tld")
	if !strings.Contains(got, "a@x.tld") || !strings.Contains(got, "b@y.tld") {
		t.Errorf("a lista perdeu destinatário: %q", got)
	}
	if strings.ContainsAny(headerAddressList("a@x.tld\r\nBcc: z@z.tld"), "\r\n") {
		t.Error("quebra de linha sobreviveu na lista")
	}
}

// TestBuildMultipartMessageNaoQuebraComCabecalhoMalicioso: aqui a injeção tem
// um agravante — a linha seguinte ao Subject declara o boundary do multipart, e
// quebrá-la desmonta o anexo inteiro.
func TestBuildMultipartMessageNaoQuebraComCabecalhoMalicioso(t *testing.T) {
	msg, err := buildMultipartMessage(
		"de@x.tld", "para@x.tld",
		"Backup\r\nContent-Type: text/plain",
		"corpo", []byte("conteudo"), "backup.enc")
	if err != nil {
		t.Fatalf("buildMultipartMessage: %v", err)
	}
	cabecalho, _, ok := strings.Cut(string(msg), "\r\n\r\n")
	if !ok {
		t.Fatal("mensagem sem separação entre cabeçalho e corpo")
	}
	// A conta é por LINHA, e não por ocorrência da string.
	//
	// A primeira versão deste teste usava strings.Count e ficou vermelha com a
	// correção funcionando: o "Content-Type: text/plain" passou a aparecer
	// DENTRO da linha do Subject, como texto — que é exatamente o desfecho
	// desejado. O que caracteriza injeção é uma LINHA NOVA começando com um
	// nome de cabeçalho, não a presença do texto em algum lugar.
	linhasCT := 0
	for _, l := range strings.Split(cabecalho, "\r\n") {
		if strings.HasPrefix(l, "Content-Type:") {
			linhasCT++
		}
	}
	if linhasCT != 1 {
		t.Errorf("esperava exatamente 1 linha de Content-Type, achei %d:\n%s", linhasCT, cabecalho)
	}
	// E o texto malicioso continua visível, absorvido pelo assunto.
	// O assunto agora vem codificado; decodificado, ele contém a tentativa
	// inteira como TEXTO — visível para quem recebe, inofensiva no cabeçalho.
	for _, l := range strings.Split(cabecalho, "\r\n") {
		if !strings.HasPrefix(l, "Subject: ") {
			continue
		}
		dec, err := new(mime.WordDecoder).DecodeHeader(strings.TrimPrefix(l, "Subject: "))
		if err != nil {
			t.Fatalf("assunto não decodifica: %v", err)
		}
		if !strings.Contains(dec, "Content-Type: text/plain") {
			t.Errorf("o assunto não absorveu a tentativa de injeção: %q", dec)
		}
	}
	if !strings.Contains(cabecalho, "multipart/mixed") {
		t.Errorf("o Content-Type do multipart se perdeu:\n%s", cabecalho)
	}
}

// TestCorpoDoEmailMantemQuebraDeLinha é o contraponto que impede a correção de
// ser aplicada larga demais: o corpo vem DEPOIS da linha em branco, onde quebra
// de linha é o formato — sanitizá-lo destruiria a legibilidade de um erro de
// várias linhas, que é o conteúdo mais comum de uma notificação.
func TestCorpoDoEmailMantemQuebraDeLinha(t *testing.T) {
	msg, err := buildMultipartMessage("de@x", "para@x", "assunto",
		"linha 1\nlinha 2\nlinha 3", []byte("x"), "a.bin")
	if err != nil {
		t.Fatalf("buildMultipartMessage: %v", err)
	}
	if !strings.Contains(string(msg), "linha 1\nlinha 2") {
		t.Error("o corpo perdeu as quebras de linha — um erro de várias linhas ficaria ilegível")
	}
}

// go/request-forgery (alerta #1): a URL do webhook virava requisição sem
// nenhuma conferência de esquema.
//
// O que esta checagem NÃO é: defesa contra SSRF. Quem grava a URL é um admin
// com system.write, e mandar notificação para onde ele escolher é o propósito
// do campo — inclusive para um servidor da própria LAN, que é o caso mais
// comum. O teste abaixo prova justamente que esse caso continua passando.
func TestWebhookURLAceitaDestinoInternoDeProposito(t *testing.T) {
	for _, u := range []string{
		"http://192.168.3.10:8080/hook",
		"https://alertas.empresa.local/webhook",
		"http://localhost:9000/x",
	} {
		if _, err := checkWebhookURL(u); err != nil {
			t.Errorf("checkWebhookURL(%q) recusou um destino legítimo: %v", u, err)
		}
	}
}

// O que ela fecha: esquemas que não são requisição de rede. Um
// "file:///etc/linkguard-fw/secret.key" faria o processo ler um arquivo local
// COMO ROOT e devolver o conteúdo no teste de notificação que o painel exibe.
func TestWebhookURLRecusaEsquemaQueNaoEHTTP(t *testing.T) {
	for _, u := range []string{
		"file:///etc/linkguard-fw/secret.key",
		"file:///etc/shadow",
		"gopher://interno:70/",
		"ftp://arquivo.local/x",
		"",
		"nao-e-url",
		"http://",
	} {
		if _, err := checkWebhookURL(u); err == nil {
			t.Errorf("checkWebhookURL(%q) foi aceito", u)
		}
	}
}

// A mensagem tem de dizer o que arrumar: quem lê é o admin corrigindo a própria
// configuração, e "URL inválida" não ajuda.
func TestWebhookURLDizOEsquemaRecusado(t *testing.T) {
	_, err := checkWebhookURL("file:///etc/shadow")
	if err == nil {
		t.Fatal("esperava recusa")
	}
	if !strings.Contains(err.Error(), "file") || !strings.Contains(err.Error(), "http://") {
		t.Errorf("a mensagem não nomeia o esquema recusado nem o esperado: %v", err)
	}
}
