package dnstap

import (
	"encoding/binary"
	"fmt"
)

// Leitura dos poucos campos de protobuf que interessam num quadro dnstap.
//
// POR QUE NÃO O PROTOBUF GERADO. O esquema do dnstap tem dezenas de campos; a
// gente precisa de DOIS: a mensagem embutida e, dentro dela, os bytes da
// RESPOSTA em formato de fio do DNS. Ler dois campos por número, pulando o
// resto, é um scanner de sessenta linhas — e não obriga o produto a carregar um
// compilador de esquema, um gerador e a árvore de dependências deles.
//
// O formato é estável e simples: cada campo é uma varint de chave (número do
// campo << 3 | tipo de fio) seguida do valor. Os quatro tipos de fio que
// existem estão todos tratados abaixo, inclusive os que a gente só quer PULAR —
// pular errado é como um scanner deste tipo se perde em silêncio.
//
// Campos do dnstap que importam (dnstap.proto, estável desde 2014):
//
//	Dnstap.message  = 14 (mensagem embutida)
//	Message.type    = 1  (varint; 6 = CLIENT_RESPONSE, 4 = RESOLVER_RESPONSE)
//	Message.response_message = 14 (bytes, mensagem DNS em formato de fio)
//
// O enum do dnstap começa em AUTH_QUERY = 1 e alterna pergunta/resposta, então
// toda RESPOSTA tem número par. Já erramos isto: filtrávamos 5 e 3, que são
// CLIENT_QUERY e RESOLVER_QUERY — perguntas, que não carregam resposta
// nenhuma. O coletor recebia todo o tráfego do unbound e descartava tudo, em
// silêncio, e o mapa ficava vazio sem um único erro no log. O teste não pegou
// porque montava o quadro com a mesma constante que testava; hoje há um quadro
// real do unbound preso no teste, e é ele que ancora o número.
const (
	campoDnstapMessage   = 14
	campoMessageType     = 1
	campoResponseMessage = 14
	tipoClientResponse   = 6
	tipoResolverResponse = 4
)

// RespostaDNS extrai de um quadro dnstap os bytes da resposta em formato de
// fio, e diz se o quadro é mesmo uma resposta.
//
// Quadro que não é resposta (pergunta do cliente, pergunta ao upstream) devolve
// nil sem erro: não é falha, é a metade do tráfego que não interessa.
func RespostaDNS(quadro []byte) ([]byte, error) {
	msg, err := campoBytes(quadro, campoDnstapMessage)
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, nil
	}
	tipo, temTipo, err := campoVarint(msg, campoMessageType)
	if err != nil {
		return nil, err
	}
	if !temTipo || (tipo != tipoClientResponse && tipo != tipoResolverResponse) {
		return nil, nil
	}
	return campoBytes(msg, campoResponseMessage)
}

// campoBytes devolve o valor do primeiro campo `numero` do tipo bytes.
func campoBytes(b []byte, numero uint64) ([]byte, error) {
	return varrer(b, numero, 2)
}

// campoVarint devolve o valor do primeiro campo `numero` do tipo varint.
func campoVarint(b []byte, numero uint64) (uint64, bool, error) {
	v, err := varrerVarint(b, numero)
	if err != nil || v == nil {
		return 0, false, err
	}
	return *v, true, nil
}

// varrer percorre a mensagem procurando um campo, pulando corretamente todos os
// outros. Pular errado é como um scanner destes se perde em silêncio.
func varrer(b []byte, numero uint64, tipoFioQuerido int) ([]byte, error) {
	for i := 0; i < len(b); {
		chave, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, fmt.Errorf("chave de campo inválida na posição %d", i)
		}
		i += n
		num, tipoFio := chave>>3, int(chave&0x7)
		switch tipoFio {
		case 0: // varint
			_, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("varint inválida na posição %d", i)
			}
			i += n
		case 1: // 64 bits
			if i+8 > len(b) {
				return nil, fmt.Errorf("campo de 64 bits truncado")
			}
			i += 8
		case 2: // bytes
			tam, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("comprimento inválido na posição %d", i)
			}
			i += n
			if uint64(i)+tam > uint64(len(b)) {
				return nil, fmt.Errorf("campo de bytes truncado")
			}
			if num == numero && tipoFioQuerido == 2 {
				return b[i : uint64(i)+tam], nil
			}
			i += int(tam)
		case 5: // 32 bits
			if i+4 > len(b) {
				return nil, fmt.Errorf("campo de 32 bits truncado")
			}
			i += 4
		default:
			return nil, fmt.Errorf("tipo de fio %d desconhecido", tipoFio)
		}
	}
	return nil, nil
}

// varrerVarint é a irmã de varrer para campos numéricos.
func varrerVarint(b []byte, numero uint64) (*uint64, error) {
	for i := 0; i < len(b); {
		chave, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, fmt.Errorf("chave de campo inválida na posição %d", i)
		}
		i += n
		num, tipoFio := chave>>3, int(chave&0x7)
		switch tipoFio {
		case 0:
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("varint inválida na posição %d", i)
			}
			i += n
			if num == numero {
				vv := v
				return &vv, nil
			}
		case 1:
			if i+8 > len(b) {
				return nil, fmt.Errorf("campo de 64 bits truncado")
			}
			i += 8
		case 2:
			tam, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("comprimento inválido na posição %d", i)
			}
			i += n
			if uint64(i)+tam > uint64(len(b)) {
				return nil, fmt.Errorf("campo de bytes truncado")
			}
			i += int(tam)
		case 5:
			if i+4 > len(b) {
				return nil, fmt.Errorf("campo de 32 bits truncado")
			}
			i += 4
		default:
			return nil, fmt.Errorf("tipo de fio %d desconhecido", tipoFio)
		}
	}
	return nil, nil
}
