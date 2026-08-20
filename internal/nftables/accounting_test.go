package nftables

import (
	"context"
	"os"
	"strings"
	"testing"
)

// A saída usada aqui é a do nft 1.1.3 rodando no Debian 13 — a mesma versão da
// VM de validação e da máquina de produção. O formato é o contrato de que a
// leitura depende.

const setComElementos = `table inet linkguard {
	set acct_up {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		counter
		timeout 1d
		elements = { 192.168.3.50 counter packets 4 bytes 440 expires 59m59s988ms,
			     192.168.3.51 counter packets 1204 bytes 1548221 expires 23h58m }
	}
}`

const setVazio = `table inet linkguard {
	set acct_up {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		counter
		timeout 1d
	}
}`

func TestParseCounterSet(t *testing.T) {
	got := parseCounterSet(setComElementos)
	if len(got) != 2 {
		t.Fatalf("queria 2 elementos, veio %d: %+v", len(got), got)
	}
	if c := got["192.168.3.50"]; c.packets != 4 || c.bytes != 440 {
		t.Errorf("primeiro elemento: %+v", c)
	}
	// O segundo vem depois de uma quebra de linha e de indentação — o formato
	// que o nft usa quando o set tem mais de um elemento.
	if c := got["192.168.3.51"]; c.packets != 1204 || c.bytes != 1548221 {
		t.Errorf("elemento em linha continuada: %+v", c)
	}
}

func TestParseCounterSetVazioNaoEhErro(t *testing.T) {
	// Set sem `elements =` é o estado normal logo depois do boot. Mapa vazio é
	// a resposta certa; o que não pode acontecer é isso virar erro (o painel
	// diria "falhou" quando a verdade é "ninguém trafegou ainda").
	if got := parseCounterSet(setVazio); len(got) != 0 {
		t.Errorf("set vazio devolveu %+v", got)
	}
}

func TestParseCounterSetIgnoraOQueNaoEhElemento(t *testing.T) {
	// A palavra "counter" aparece na declaração do set, sem endereço na
	// frente. Casar com ela produziria um host fantasma.
	if got := parseCounterSet(setVazio + "\ncounter packets 9 bytes 9\n"); len(got) != 0 {
		t.Errorf("casou com algo que não é elemento: %+v", got)
	}
}

func TestAcctChainRules(t *testing.T) {
	regras := acctChainRules([]string{"wan1", "wan2"})
	if len(regras) != 2 {
		t.Fatalf("queria 2 regras, veio %d", len(regras))
	}
	up := strings.Join(regras[0], " ")
	down := strings.Join(regras[1], " ")
	if up != `iifname != { "wan1", "wan2" } update @acct_up { ip saddr }` {
		t.Errorf("regra de upload: %q", up)
	}
	if down != `oifname != { "wan1", "wan2" } update @acct_down { ip daddr }` {
		t.Errorf("regra de download: %q", down)
	}
}

func TestAcctChainRulesEscapaONomeDaInterface(t *testing.T) {
	// O nome vai para dentro de um argv do nft. Aspas são obrigatórias — sem
	// elas um nome com hífen ou ponto quebra a regra inteira, e a chain fica
	// sem contabilidade nenhuma.
	regras := acctChainRules([]string{"enp5s0.100"})
	if !strings.Contains(strings.Join(regras[0], " "), `{ "enp5s0.100" }`) {
		t.Errorf("nome não veio entre aspas: %v", regras[0])
	}
}

// execFalso registra os comandos e devolve saídas roteirizadas.
type execFalso struct {
	comandos []string
	saidas   map[string]string
	erros    map[string]error
	dryRun   bool
}

func (e *execFalso) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	e.comandos = append(e.comandos, full)
	for chave, err := range e.erros {
		if strings.Contains(full, chave) {
			return "", err
		}
	}
	return "", nil
}

func (e *execFalso) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	e.comandos = append(e.comandos, full)
	for chave, saida := range e.saidas {
		if strings.Contains(full, chave) {
			return saida, nil
		}
	}
	return "", nil
}

func (e *execFalso) IsDryRun() bool { return e.dryRun }

func (e *execFalso) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestEnsureAccountingSemWANNaoTocaEmNada(t *testing.T) {
	// Sem saber quais interfaces são WAN, contar tudo encheria o set com
	// endereços da internet. Não agir é a resposta certa — a mesma decisão do
	// ReconcileMasquerade diante de fonte vazia.
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureAccounting(context.Background(), nil); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	for _, c := range ex.comandos {
		if strings.Contains(c, "nft") {
			t.Errorf("executou nft sem WAN configurada: %q", c)
		}
	}
}

func TestEnsureAccountingDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureAccounting(context.Background(), []string{"wan1"}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}

func TestHostCountersJuntaOsDoisSentidos(t *testing.T) {
	ex := &execFalso{saidas: map[string]string{
		"list set inet linkguard acct_up": `elements = { 192.168.3.50 counter packets 10 bytes 1000 expires 1d }`,
		"list set inet linkguard acct_down": `elements = { 192.168.3.50 counter packets 20 bytes 5000 expires 1d,
			     192.168.3.99 counter packets 3 bytes 300 expires 1d }`,
	}}
	s := &Service{exec: ex}
	got, err := s.HostCounters(context.Background())
	if err != nil {
		t.Fatalf("HostCounters: %v", err)
	}
	h := got["192.168.3.50"]
	if h.TxBytes != 1000 || h.RxBytes != 5000 {
		t.Errorf("host com os dois sentidos: %+v", h)
	}
	// Host que só aparece no download tem de existir mesmo assim, com upload
	// zero — é o caso de quem só recebe.
	so := got["192.168.3.99"]
	if so.RxBytes != 300 || so.TxBytes != 0 {
		t.Errorf("host só de download: %+v", so)
	}
}
