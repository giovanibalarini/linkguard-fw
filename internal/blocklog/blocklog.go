// Package blocklog lê, do journal do kernel, o que o firewall descartou
// (issue #122).
//
// POR QUE O JOURNAL. Quem escreve é o kernel, pela regra de `log prefix` que
// internal/nftables põe ao lado de cada bloqueio administrativo. Não há
// arquivo próprio nem banco: o registro já existe, com rotação e limite de
// tamanho resolvidos pelo journald, e duplicá-lo num arquivo do produto seria
// assumir a responsabilidade de rotacionar sem ganhar nada.
//
// O FORMATO É DO KERNEL, e não escolha nossa: uma linha de chaves `CHAVE=valor`
// depois do prefixo. Este pacote traduz isso para o que a tela mostra, e
// descarta o resto — MAC, TTL, janela TCP e afins não ajudam a responder "por
// que isso não passou?" e só encompridariam a linha.
package blocklog

import (
	"context"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/firewall"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// Entry é um descarte, reduzido ao que responde a pergunta do admin.
type Entry struct {
	Time  string `json:"time"`
	Kind  string `json:"kind"` // host | dest
	In    string `json:"in"`
	Out   string `json:"out"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	SPort string `json:"sport"`
	DPort string `json:"dport"`
}

// Service lê o journal do kernel.
type Service struct {
	exec firewall.Executor
}

// NewService cria o serviço.
func NewService(exec firewall.Executor) *Service { return &Service{exec: exec} }

// Recent devolve até limit descartes, do mais recente para o mais antigo,
// opcionalmente filtrados por um pedaço de endereço.
//
// Lê mais linhas do que o pedido porque o journal do kernel intercala tudo o
// mais que o kernel diz — a filtragem pelo prefixo acontece aqui, não lá.
func (s *Service) Recent(ctx context.Context, limit int, filtro string) ([]Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	linhas := strconv.Itoa(limit * 20)
	out, err := s.exec.ExecuteRead(ctx, "journalctl", "-k", "-n", linhas, "--no-pager", "-o", "short-iso")
	if err != nil {
		return nil, err
	}
	return Parse(out, limit, filtro), nil
}

// Parse extrai os descartes de uma saída de journal. Exportada para o teste
// exercitar o formato real sem precisar de um kernel que esteja bloqueando
// alguma coisa.
func Parse(saida string, limit int, filtro string) []Entry {
	filtro = strings.ToLower(strings.TrimSpace(filtro))
	prefixos := map[string]string{
		nftables.BlockLogPrefixHost: "host",
		nftables.BlockLogPrefixDest: "dest",
	}

	var out []Entry
	linhas := strings.Split(saida, "\n")
	// De trás para frente: o journal vem do mais antigo para o mais recente, e
	// a tela quer o contrário. Inverter aqui evita carregar tudo para depois
	// ordenar.
	for i := len(linhas) - 1; i >= 0 && len(out) < limit; i-- {
		linha := linhas[i]
		var kind string
		var resto string
		for p, k := range prefixos {
			if idx := strings.Index(linha, p); idx >= 0 {
				kind, resto = k, linha[idx+len(p):]
				break
			}
		}
		if kind == "" {
			continue
		}
		e := entryDe(resto)
		e.Kind = kind
		e.Time = horaDe(linha)
		if filtro != "" && !casaFiltro(e, filtro) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// entryDe lê os pares CHAVE=valor que o kernel escreve.
func entryDe(resto string) Entry {
	var e Entry
	for _, campo := range strings.Fields(resto) {
		chave, valor, ok := strings.Cut(campo, "=")
		if !ok {
			continue
		}
		switch chave {
		case "IN":
			e.In = valor
		case "OUT":
			e.Out = valor
		case "SRC":
			e.Src = valor
		case "DST":
			e.Dst = valor
		case "PROTO":
			e.Proto = valor
		case "SPT":
			e.SPort = valor
		case "DPT":
			e.DPort = valor
		}
	}
	return e
}

// horaDe extrai o carimbo do começo da linha do journal (formato short-iso:
// "2026-08-20T15:04:05-0300 host kernel: ..."). Devolve só a hora, que é o que
// a tela mostra — a data já está implícita na janela consultada.
func horaDe(linha string) string {
	campo := strings.Fields(linha)
	if len(campo) == 0 {
		return ""
	}
	ts := campo[0]
	if i := strings.Index(ts, "T"); i >= 0 && len(ts) >= i+9 {
		return ts[i+1 : i+9]
	}
	return ts
}

func casaFiltro(e Entry, filtro string) bool {
	for _, v := range []string{e.Src, e.Dst, e.In, e.Out, e.Proto, e.DPort} {
		if strings.Contains(strings.ToLower(v), filtro) {
			return true
		}
	}
	return false
}
