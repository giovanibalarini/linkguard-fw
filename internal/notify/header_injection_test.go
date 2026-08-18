package notify

import (
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

func TestHeaderSafeNeutralizaQuebraDeLinha(t *testing.T) {
	entrada := "Alerta\r\nBcc: atacante@exemplo.tld"
	got := headerSafe(entrada)

	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("headerSafe deixou passar quebra de linha: %q", got)
	}
	// O texto NÃO some — ele fica visível, na mesma linha. Apagar o conteúdo
	// esconderia do operador o que alguém tentou fazer.
	if !strings.Contains(got, "Bcc: atacante@exemplo.tld") {
		t.Errorf("o conteúdo suspeito deveria continuar legível, veio %q", got)
	}
	if !strings.Contains(got, "Alerta") {
		t.Errorf("o texto legítimo foi perdido: %q", got)
	}
}

func TestHeaderSafePreservaTextoNormal(t *testing.T) {
	// Acentuação e pontuação passam intactas: a correção é sobre os três bytes
	// que terminam um cabeçalho, não sobre o idioma.
	for _, s := range []string{
		"WAN1 caiu", "Configuração inválida", "admin@empresa.com.br",
		"[CRITICAL] disco cheio — 95%",
	} {
		if got := headerSafe(s); got != s {
			t.Errorf("headerSafe(%q) alterou texto legítimo: %q", s, got)
		}
	}
}

func TestHeaderSafeCortaNUL(t *testing.T) {
	if got := headerSafe("a\x00b"); strings.ContainsRune(got, 0) {
		t.Errorf("NUL sobreviveu: %q", got)
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
	if !strings.Contains(cabecalho, "Subject: Backup  Content-Type: text/plain") {
		t.Errorf("o assunto não absorveu a tentativa de injeção:\n%s", cabecalho)
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
		if err := checkWebhookURL(u); err != nil {
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
		if err := checkWebhookURL(u); err == nil {
			t.Errorf("checkWebhookURL(%q) foi aceito", u)
		}
	}
}

// A mensagem tem de dizer o que arrumar: quem lê é o admin corrigindo a própria
// configuração, e "URL inválida" não ajuda.
func TestWebhookURLDizOEsquemaRecusado(t *testing.T) {
	err := checkWebhookURL("file:///etc/shadow")
	if err == nil {
		t.Fatal("esperava recusa")
	}
	if !strings.Contains(err.Error(), "file") || !strings.Contains(err.Error(), "http://") {
		t.Errorf("a mensagem não nomeia o esquema recusado nem o esperado: %v", err)
	}
}
