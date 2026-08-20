package blocklog

import (
	"strings"
	"testing"
)

// Linhas no formato que o kernel realmente escreve (nftables `log prefix` no
// Debian 13), com os campos que ele emite e na ordem em que emite.
const journalReal = `2026-08-20T15:04:01-0300 govfw kernel: Initializing cgroup subsys cpuset
2026-08-20T15:04:02-0300 govfw kernel: lg:blk:host IN=br10 OUT=lg-wan-giga MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=192.168.3.50 DST=142.250.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=12345 DF PROTO=TCP SPT=44210 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0
2026-08-20T15:04:03-0300 govfw kernel: audit: type=1400 apparmor="DENIED"
2026-08-20T15:04:04-0300 govfw kernel: lg:blk:dest IN=br10 OUT=lg-wan-vivo MAC=aa:bb SRC=192.168.3.51 DST=198.51.100.9 LEN=44 TTL=63 PROTO=UDP SPT=51000 DPT=53 LEN=24`

func TestParseSoPegaOQueOProdutoEscreveu(t *testing.T) {
	// O journal do kernel intercala tudo o mais que o kernel diz. Sem o
	// prefixo como filtro, a tela de bloqueios mostraria mensagem de cgroup e
	// de AppArmor como se fossem tráfego barrado.
	got := Parse(journalReal, 100, "")
	if len(got) != 2 {
		t.Fatalf("queria 2 descartes, veio %d: %+v", len(got), got)
	}
}

func TestParseLeOsCamposQueRespondemAPergunta(t *testing.T) {
	got := Parse(journalReal, 100, "")
	// Ordem: do mais recente para o mais antigo.
	dest := got[0]
	if dest.Kind != "dest" || dest.Src != "192.168.3.51" || dest.Dst != "198.51.100.9" {
		t.Errorf("descarte por destino: %+v", dest)
	}
	if dest.Proto != "UDP" || dest.DPort != "53" {
		t.Errorf("protocolo/porta: %+v", dest)
	}
	host := got[1]
	if host.Kind != "host" || host.Src != "192.168.3.50" || host.DPort != "443" {
		t.Errorf("descarte por host: %+v", host)
	}
	if host.In != "br10" || host.Out != "lg-wan-giga" {
		t.Errorf("interfaces: %+v", host)
	}
	if host.Time != "15:04:02" {
		t.Errorf("hora = %q, queria 15:04:02", host.Time)
	}
}

func TestParseDoMaisRecenteParaOMaisAntigo(t *testing.T) {
	// A tela mostra o que acabou de acontecer no topo: é a pergunta que o
	// admin está fazendo agora.
	got := Parse(journalReal, 100, "")
	if got[0].Time < got[1].Time {
		t.Errorf("ordem invertida: %v vem antes de %v", got[0].Time, got[1].Time)
	}
}

func TestParseRespeitaOLimite(t *testing.T) {
	got := Parse(journalReal, 1, "")
	if len(got) != 1 {
		t.Errorf("limite ignorado: %d entradas", len(got))
	}
	// E o que sobra é o mais recente, não o primeiro que apareceu no arquivo.
	if got[0].Kind != "dest" {
		t.Errorf("o limite cortou o lado errado: %+v", got[0])
	}
}

func TestParseFiltra(t *testing.T) {
	casos := map[string]int{
		"192.168.3.50": 1, // por origem
		"198.51.100.9": 1, // por destino
		"udp":          1, // por protocolo, sem diferenciar maiúscula
		"lg-wan":       2, // por interface de saída
		"nao-existe":   0,
	}
	for filtro, querido := range casos {
		if got := Parse(journalReal, 100, filtro); len(got) != querido {
			t.Errorf("filtro %q: %d entradas, queria %d", filtro, len(got), querido)
		}
	}
}

func TestParseVazioNaoQuebra(t *testing.T) {
	if got := Parse("", 100, ""); len(got) != 0 {
		t.Errorf("saída vazia devolveu %+v", got)
	}
	if got := Parse("linha solta sem nada", 100, ""); len(got) != 0 {
		t.Errorf("lixo virou entrada: %+v", got)
	}
}

func TestParseLinhaTruncadaNaoInventaCampo(t *testing.T) {
	// Journal com linha cortada (rotação no meio) não pode virar entrada com
	// origem vazia parecendo tráfego real.
	linha := "2026-08-20T15:04:02-0300 govfw kernel: lg:blk:host IN=br10 OUT="
	got := Parse(linha, 100, "")
	if len(got) != 1 {
		t.Fatalf("queria 1 entrada, veio %d", len(got))
	}
	if got[0].Src != "" || got[0].Dst != "" {
		t.Errorf("campos inventados: %+v", got[0])
	}
	if !strings.Contains(got[0].Time, "15:04:02") {
		t.Errorf("hora perdida: %+v", got[0])
	}
}
