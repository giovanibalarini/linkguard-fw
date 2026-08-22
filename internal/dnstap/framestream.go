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
// O QUE NÃO ESTÁ AQUI: o lado bidirecional do protocolo (READY/ACCEPT/FINISH
// negociado nos dois sentidos). O unbound é o CLIENTE que conecta e escreve; a
// gente é o coletor que só lê. Implementar o handshake completo seria escrever
// código para um caminho que este produto nunca percorre.

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
		tipo, err := fr.lerControle()
		if err != nil {
			return nil, err
		}
		switch tipo {
		case controlStart, controlReady, controlAccept:
			fr.iniciou = true
		case controlStop, controlFinish:
			return nil, io.EOF
		}
	}
}

// lerControle consome um quadro de controle e devolve o tipo dele.
func (fr *Reader) lerControle() (uint32, error) {
	var tam uint32
	if err := binary.Read(fr.r, binary.BigEndian, &tam); err != nil {
		return 0, err
	}
	if tam > maxFrame {
		return 0, fmt.Errorf("quadro de controle de %d bytes acima do teto", tam)
	}
	buf := make([]byte, tam)
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, fmt.Errorf("quadro de controle truncado (%d bytes)", len(buf))
	}
	return binary.BigEndian.Uint32(buf[:4]), nil
}
