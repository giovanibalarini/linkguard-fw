package links

import (
	"fmt"
	"sort"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// Identidade de caminho de volta de uma WAN (issue #120).
//
// ESTE ARQUIVO EXISTE PARA A DERIVAÇÃO MORAR NUM LUGAR SÓ. Duas partes do
// produto precisam concordar sobre qual marca pertence a qual WAN: o nftables,
// que grava a marca na conexão, e o iproute2, que decide a rota a partir dela.
// Se cada uma derivasse a marca por conta própria, bastaria uma mudar de
// critério para a marcação passar a apontar para uma tabela que não existe — e
// o sintoma seria "a resposta some", não "a configuração divergiu".
//
// A MARCA É O table_id. Não é economia de código: a tabela de rota por link já
// existe desde sempre (storage.Link.TableID, atribuído a partir de 100) e é a
// que o failover mantém. Usar o mesmo número dos dois lados torna impossível
// marcar com um valor que não tem tabela correspondente.
type WANPath struct {
	Interface string
	Gateway   string
	Mark      uint32
	Table     string
}

// MarkHex é a marca no formato que o nft e o `ip rule` imprimem.
func (w WANPath) MarkHex() string { return fmt.Sprintf("0x%x", w.Mark) }

// WANPaths devolve o caminho de volta de cada link habilitado que tenha
// interface e tabela.
//
// Link sem table_id fica de fora em vez de receber uma marca inventada: marcar
// uma conexão com um número que não tem tabela faria a `ip rule` cair na main —
// exatamente o comportamento errado que esta feature existe para corrigir,
// agora com uma camada a mais de indireção escondendo o motivo.
func WANPaths(todos []storage.Link) []WANPath {
	out := make([]WANPath, 0, len(todos))
	for _, l := range todos {
		if !l.Enabled || l.Interface == "" || l.TableID <= 0 {
			continue
		}
		out = append(out, WANPath{
			Interface: l.Interface,
			Gateway:   l.Gateway,
			Mark:      uint32(l.TableID),
			Table:     fmt.Sprintf("%d", l.TableID),
		})
	}
	// Ordem estável por interface: as chains do nft são reescritas a partir
	// desta lista, e ordem variável faria o ruleset vivo diferir a cada boot
	// sem nenhuma mudança real.
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}
