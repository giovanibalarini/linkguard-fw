package dnstap

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Leitor de Frame Streams, o transporte que o unbound usa para entregar dnstap.
//
// POR QUE ESCRITO À MÃO. O formato é pequeno e fechado (RFC-menos, mas
// especificado em fstrm): um quadro é um comprimento de 4 bytes big-endian
// seguido do conteúdo, e comprimento zero anuncia um quadro de CONTROLE. São
// cerca de cem linhas, testáveis contra bytes reais.
//
// A alternativa era trazer github.com/dnstap/golang-dnstap e a árvore de
// dependências dele para dentro de um firewall. Este produto tem uma lista de
// dependências deliberadamente curta e já escreve os próprios parsers para
// `ip neigh`, `nft list set` e a saída do tcpdump — um a mais, do mesmo
// tamanho, é mais barato de auditar do que uma dependência a mais de cadeia
// desconhecida.
//
// O HANDSHAKE BIDIRECIONAL ESTÁ AQUI, E A PRIMEIRA VERSÃO NÃO TINHA — foi um
// comentário meu deduzido em vez de medido, e custou uma validação inteira.
//
// Eu tinha escrito: "o unbound é o CLIENTE que conecta e escreve; a gente só lê,
// implementar o handshake seria código para um caminho que este produto nunca
// percorre". Errado. Medido na VM: o socket conectava, o unbound registrava
// "attempting to connect to dnstap socket" e "dnstap Message/CLIENT_RESPONSE
// enabled", as consultas resolviam — e NENHUM byte de dado chegava.
//
// O motivo é o protocolo: em modo bidirecional o remetente manda READY e FICA
// ESPERANDO um ACCEPT. Sem a resposta, ele nunca envia dado nenhum, e nunca
// reclama — porque do ponto de vista dele a conversa apenas não começou.
//
// O sintoma era o pior possível: tudo verde dos dois lados e um mapa vazio.

const (
	// controlAccept e os outros são os tipos de quadro de controle do fstrm.
	controlAccept = 0x01
	controlStart  = 0x02
	controlStop   = 0x03
	controlReady  = 0x04
	controlFinish = 0x05

	// maxFrame é o teto de um quadro de dados. Uma resposta de DNS não passa
	// de 64 KiB por definição do próprio protocolo; o teto existe para um
	// socket corrompido não virar uma alocação de gigabytes.
	maxFrame = 1 << 16
)

// Reader lê quadros de dados de uma conexão Frame Streams.
type Reader struct {
	r       io.Reader
	iniciou bool
}

// NewReader cria o leitor.
func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Next devolve o próximo quadro de DADOS, tratando os de controle pelo caminho.
//
// Devolve io.EOF quando o remetente encerra (quadro FINISH ou fim da conexão),
// que é o encerramento normal — o unbound fecha e reconecta ao recarregar.
func (fr *Reader) Next() ([]byte, error) {
	for {
		var tam uint32
		if err := binary.Read(fr.r, binary.BigEndian, &tam); err != nil {
			return nil, err
		}
		if tam != 0 {
			if tam > maxFrame {
				return nil, fmt.Errorf("quadro de %d bytes acima do teto de %d", tam, maxFrame)
			}
			buf := make([]byte, tam)
			if _, err := io.ReadFull(fr.r, buf); err != nil {
				return nil, err
			}
			return buf, nil
		}
		// Comprimento zero: o que vem a seguir é um quadro de controle, com o
		// próprio comprimento.
		tipo, corpo, err := fr.lerControle()
		if err != nil {
			return nil, err
		}
		switch tipo {
		case controlReady:
			// A RESPOSTA QUE FAZ O DADO FLUIR. O remetente espera o ACCEPT
			// antes de mandar qualquer coisa; sem ele, silêncio para sempre.
			//
			// O ACCEPT devolve os tipos de conteúdo que a gente aceita. Devolver
			// exatamente o que ele ofereceu é o caminho certo: ele propôs
			// "protobuf:dnstap.Dnstap", a gente confirma o mesmo, e nenhum dos
			// dois precisa conhecer a lista do outro.
			if err := fr.responder(controlAccept, corpo); err != nil {
				return nil, err
			}
			fr.iniciou = true
		case controlStart, controlAccept:
			fr.iniciou = true
		case controlStop:
			// Encerramento limpo: confirma com FINISH para o remetente não ficar
			// esperando, e encerra.
			_ = fr.responder(controlFinish, nil)
			return nil, io.EOF
		case controlFinish:
			return nil, io.EOF
		}
	}
}

// lerControle consome um quadro de controle e devolve o tipo e os campos dele.
//
// Os campos são devolvidos crus porque o ACCEPT os ecoa de volta: o remetente
// propõe os tipos de conteúdo que sabe enviar, e confirmar exatamente o que ele
// propôs evita a gente ter de conhecer a lista dele.
func (fr *Reader) lerControle() (uint32, []byte, error) {
	var tam uint32
	if err := binary.Read(fr.r, binary.BigEndian, &tam); err != nil {
		return 0, nil, err
	}
	if tam > maxFrame {
		return 0, nil, fmt.Errorf("quadro de controle de %d bytes acima do teto", tam)
	}
	buf := make([]byte, tam)
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		return 0, nil, err
	}
	if len(buf) < 4 {
		return 0, nil, fmt.Errorf("quadro de controle truncado (%d bytes)", len(buf))
	}
	return binary.BigEndian.Uint32(buf[:4]), buf[4:], nil
}

// responder escreve um quadro de controle de volta ao remetente.
//
// Só faz sentido quando o leitor foi construído sobre algo que também escreve —
// que é o caso do socket. NewReader aceita io.Reader para os testes poderem usar
// um buffer; sem escritor, a resposta é silenciosamente pulada e o modo
// unidirecional continua funcionando.
func (fr *Reader) responder(tipo uint32, campos []byte) error {
	w, ok := fr.r.(io.Writer)
	if !ok {
		return nil
	}
	corpo := make([]byte, 4, 4+len(campos))
	binary.BigEndian.PutUint32(corpo, tipo)
	corpo = append(corpo, campos...)

	var quadro []byte
	quadro = binary.BigEndian.AppendUint32(quadro, 0) // escape de controle
	quadro = binary.BigEndian.AppendUint32(quadro, uint32(len(corpo)))
	quadro = append(quadro, corpo...)
	_, err := w.Write(quadro)
	return err
}
