package nftables

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A saída usada aqui é a do nft 1.1.3 rodando no Debian 13 — a mesma versão da
// VM de validação e da máquina de produção. O formato é o contrato de que a
// leitura depende.

const setDeFluxosComElementos = `table inet linkguard_flows {
	set flows {
		type ipv4_addr . ipv4_addr . inet_service
		size 8192
		flags dynamic,timeout
		counter
		timeout 1h
		elements = { 192.168.3.50 . 142.250.219.14 . 443 counter packets 12 bytes 3456 expires 59m58s,
			     192.168.3.50 . 8.8.8.8 . 53 counter packets 2 bytes 120 expires 59m,
			     192.168.3.77 . 140.82.121.4 . 443 counter packets 900 bytes 1548221 expires 12m3s }
	}
}`

const setDeFluxosVazio = `table inet linkguard_flows {
	set flows {
		type ipv4_addr . ipv4_addr . inet_service
		size 8192
		flags dynamic,timeout
		counter
		timeout 15m
	}
}`

func TestParseFlowSetLeATuplaInteiraIncluindoALinhaContinuada(t *testing.T) {
	// O defeito que este teste prende: o nft quebra a linha entre elementos e
	// indenta a continuação. Uma regex que exija tudo numa linha só lê a
	// PRIMEIRA conversa e joga o resto fora — e a tela mostra um host que falou
	// com um destino só, com cara de completa.
	snap := parseFlowSet(setDeFluxosComElementos)
	if len(snap.Fluxos) != 3 {
		t.Fatalf("queria 3 tuplas, veio %d: %+v", len(snap.Fluxos), snap.Fluxos)
	}
	f := snap.Fluxos[0]
	if f.Origem != "192.168.3.50" || f.Destino != "142.250.219.14" || f.Porta != 443 {
		t.Errorf("primeira tupla: %+v", f)
	}
	if f.Pacotes != 12 || f.Bytes != 3456 {
		t.Errorf("contador da primeira tupla: %+v", f)
	}
	ultima := snap.Fluxos[2]
	if ultima.Origem != "192.168.3.77" || ultima.Bytes != 1548221 {
		t.Errorf("tupla em linha continuada: %+v", ultima)
	}
}

func TestParseFlowSetVazioNaoViraErro(t *testing.T) {
	// Set sem a linha de elementos é o estado normal logo depois do boot.
	// Lista vazia é a resposta certa; o que não pode é isso virar tupla
	// fantasma vinda da declaração do set.
	snap := parseFlowSet(setDeFluxosVazio)
	if len(snap.Fluxos) != 0 {
		t.Errorf("set vazio devolveu %+v", snap.Fluxos)
	}
	if snap.Cheio {
		t.Errorf("set vazio marcado como cheio")
	}
}

func TestParseFlowSetNaoInventaTuplaAPartirDaDeclaracao(t *testing.T) {
	// A linha de tipo do set tem a mesma forma da chave (endereço . endereço .
	// serviço) sem número nenhum, e a linha de tamanho tem um número solto.
	// Casar com qualquer uma delas produziria uma conversa que nunca existiu —
	// e uma conversa inventada num registro de quem-falou-com-quem é a pior
	// mentira que esta tela pode contar.
	entrada := setDeFluxosVazio + "\ncounter packets 9 bytes 9\n"
	if snap := parseFlowSet(entrada); len(snap.Fluxos) != 0 {
		t.Errorf("casou com algo que não é elemento: %+v", snap.Fluxos)
	}
}

func TestParseFlowSetLeJanelaETetoDoKernelNaoDoBanco(t *testing.T) {
	// O defeito: a tela dizer "última hora" porque é isso que está salvo no
	// banco, enquanto o kernel está aplicando 15 minutos porque a tabela ainda
	// não foi recriada. Janela e teto têm de sair da MESMA leitura de onde saem
	// as tuplas.
	if got := parseFlowSet(setDeFluxosComElementos); got.JanelaMinutos != 60 || got.Teto != 8192 {
		t.Errorf("janela/teto: %d min, teto %d", got.JanelaMinutos, got.Teto)
	}
	if got := parseFlowSet(setDeFluxosVazio); got.JanelaMinutos != 15 {
		t.Errorf("janela do set de 15 min veio %d", got.JanelaMinutos)
	}
}

func TestParseFlowSetMarcaCheioContraOTetoDoKernel(t *testing.T) {
	// O defeito: o admin baixa o teto, a tabela ainda não foi recriada, e a
	// tela compara a contagem com o teto do BANCO — dizendo que há folga
	// enquanto o set real já recusa tupla nova. Quem diagnostica conclui que o
	// host não falou com ninguém.
	pequeno := strings.Replace(setDeFluxosComElementos, "size 8192", "size 3", 1)
	if snap := parseFlowSet(pequeno); !snap.Cheio {
		t.Errorf("3 tuplas num set de teto 3 não foram marcadas como cheio: %+v", snap)
	}
	if snap := parseFlowSet(setDeFluxosComElementos); snap.Cheio {
		t.Errorf("3 tuplas num set de teto 8192 foram marcadas como cheio")
	}
}

func TestParseFlowSetDescartaPortaForaDaFaixa(t *testing.T) {
	// 99999 não cabe em 16 bits. Guardar isso truncado viraria uma porta que
	// ninguém usou; guardar como zero viraria uma conversa que não existiu.
	entrada := strings.Replace(setDeFluxosComElementos, ". 443 counter packets 12", ". 99999 counter packets 12", 1)
	snap := parseFlowSet(entrada)
	for _, f := range snap.Fluxos {
		if f.Porta == 0 {
			t.Errorf("porta inválida virou porta 0: %+v", f)
		}
	}
	if len(snap.Fluxos) != 2 {
		t.Errorf("queria 2 tuplas válidas, veio %d", len(snap.Fluxos))
	}
}

func TestMinutosDeNftEntendeAsUnidadesQueOKernelImprime(t *testing.T) {
	// time.ParseDuration recusa a unidade de dia, que é exatamente o que o nft
	// imprime na configuração de janela mais longa que o produto aceita (1440
	// min). Usar aquela função deixaria a tela sem saber a janela justamente
	// onde ela mais importa.
	casos := map[string]int{
		"1h":    60,
		"15m":   15,
		"1h30m": 90,
		"1d":    1440,
		"2d12h": 3600,
		"30s":   1,
		"600":   10,
		"":      0,
	}
	for entrada, querido := range casos {
		if got := minutosDeNft(entrada); got != querido {
			t.Errorf("minutosDeNft(%q) = %d, queria %d", entrada, got, querido)
		}
	}
}

func TestFlowsChainRulesEscopaPeloQueNaoEhWAN(t *testing.T) {
	// O defeito que este escopo evita: sem o "iifname !=", o tráfego de
	// ENTRADA cria uma tupla para CADA endereço da internet que responde, e um
	// set de 8192 elementos enche em minutos — a medição some e a memória do
	// kernel vai junto.
	regras := flowsChainRules([]string{"wan1", "wan2"})
	if len(regras) != 1 {
		t.Fatalf("queria 1 regra, veio %d", len(regras))
	}
	regra := strings.Join(regras[0], " ")
	querido := "iifname != { \"wan1\", \"wan2\" } meta l4proto { tcp, udp } " +
		"update @flows { ip saddr . ip daddr . th dport }"
	if regra != querido {
		t.Errorf("regra de fluxo:\n veio: %s\nqueria: %s", regra, querido)
	}
}

func TestFlowsChainRulesEscapaONomeDaInterface(t *testing.T) {
	// O nome vai para dentro de um argv do nft. Sem aspas, um nome com ponto
	// (enp5s0.100, uma VLAN) quebra a regra inteira — e a chain fica sem regra
	// nenhuma, com a tela mostrando "ninguém falou com ninguém".
	regras := flowsChainRules([]string{"enp5s0.100"})
	if !strings.Contains(strings.Join(regras[0], " "), "{ \"enp5s0.100\" }") {
		t.Errorf("nome não veio entre aspas: %v", regras[0])
	}
}

func TestFlowsSetSpecSaiComOTetoEAJanelaEscolhidos(t *testing.T) {
	spec := flowsSetSpec(FlowsConfig{JanelaMinutos: 30, Teto: 2048})
	if !strings.Contains(spec, "size 2048") || !strings.Contains(spec, "timeout 30m") {
		t.Errorf("spec: %s", spec)
	}
	// A chave TEM de ser a tupla de três. Uma chave de uma dimensão só é
	// exatamente o que a contabilidade da #112 já tem — e é o que faz a
	// pergunta "com quem" não ter resposta.
	if !strings.Contains(spec, "type ipv4_addr . ipv4_addr . inet_service") {
		t.Errorf("a chave do set perdeu uma dimensão: %s", spec)
	}
}

func TestNormalizeFlowsConfigNaoDeixaUmZeroVirarSpecDeSet(t *testing.T) {
	// O defeito: um valor ausente (JSON de outra versão, linha de settings
	// escrita à mão) vira "size 0" e o kernel passa a guardar nada. A tela
	// mostraria uma rede inteira em silêncio, sem erro em lugar nenhum.
	got := NormalizeFlowsConfig(FlowsConfig{})
	if got.JanelaMinutos != FlowsJanelaPadrao || got.Teto != FlowsTetoPadrao {
		t.Errorf("config vazia não caiu no padrão: %+v", got)
	}
	if got := NormalizeFlowsConfig(FlowsConfig{JanelaMinutos: -5, Teto: -1}); got.Teto != FlowsTetoPadrao {
		t.Errorf("negativo não caiu no padrão: %+v", got)
	}
	if got := NormalizeFlowsConfig(FlowsConfig{JanelaMinutos: 999999, Teto: 999999}); got.Teto != FlowsTetoMaximo || got.JanelaMinutos != FlowsJanelaMaxima {
		t.Errorf("valor absurdo não foi limitado: %+v", got)
	}
	if got := NormalizeFlowsConfig(FlowsConfig{JanelaMinutos: 1, Teto: 10}); got.JanelaMinutos != FlowsJanelaMinima || got.Teto != FlowsTetoMinimo {
		t.Errorf("valor abaixo do mínimo não foi elevado: %+v", got)
	}
}

// nomeiaTabelaDoFirewall diz se um comando emitido tocou a tabela do firewall.
//
// Compara TOKEN A TOKEN, e não com strings.Contains: o nome da tabela de fluxos
// começa com o nome da tabela do firewall, então um Contains casaria sempre e o
// teste passaria sem nunca ter olhado nada — o pior tipo de teste que existe.
func nomeiaTabelaDoFirewall(comando string) bool {
	for _, tok := range strings.Fields(comando) {
		if tok == Table {
			return true
		}
	}
	return false
}

func TestEnsureFlowsNaoEncostaNaTabelaDoFirewall(t *testing.T) {
	// ESTE É O TESTE QUE PROTEGE A CAIXA NO BOOT.
	//
	// Persist despeja o "nft list table" da tabela do firewall — elementos e
	// contadores inclusive — no /etc/nftables.conf, que o nftables.service
	// recarrega ANTES de o LinkGuard subir. Um set de fluxo dentro daquela
	// tabela faria esse arquivo crescer com o tráfego da rede e ressuscitaria
	// conversas velhas no boot. Se alguém "simplificar" juntando as duas
	// tabelas, é aqui que a suíte grita.
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureFlows(context.Background(), []string{"wan1"}, FlowsConfig{Ligado: true}); err != nil {
		t.Fatalf("EnsureFlows: %v", err)
	}
	if len(ex.comandos) == 0 {
		t.Fatal("não executou nada")
	}
	for _, c := range ex.comandos {
		if nomeiaTabelaDoFirewall(c) {
			t.Errorf("o registro de conversa tocou a tabela do firewall: %q", c)
		}
	}
}

func TestEnsureFlowsNaoGravaOArquivoDeBoot(t *testing.T) {
	// A outra metade da mesma proteção: mesmo sem nomear a tabela, uma chamada
	// a Persist enfiada aqui por engano gravaria o /etc/nftables.conf a cada
	// mudança de link. O arquivo simplesmente não pode existir depois disto.
	dir := t.TempDir()
	conf := filepath.Join(dir, "nftables.conf")
	ex := &execFalso{}
	s := &Service{exec: ex}
	s.SetConfPath(conf)

	if err := s.EnsureFlows(context.Background(), []string{"wan1"}, FlowsConfig{Ligado: true}); err != nil {
		t.Fatalf("EnsureFlows: %v", err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Errorf("o registro de conversa gravou o arquivo de boot (%v)", err)
	}
}

func TestEnsureFlowsPoeAChainDepoisDaFiltragem(t *testing.T) {
	// Chain de contabilidade com prioridade MENOR que a da filtragem passaria a
	// contar o que foi BLOQUEADO como se tivesse passado — e, pior, uma regra
	// de contabilidade dentro das chains de filtro entraria acima dos jumps dos
	// grupos e afrouxaria o firewall de quem já o usa (ver survival.go).
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureFlows(context.Background(), []string{"wan1"}, FlowsConfig{Ligado: true}); err != nil {
		t.Fatalf("EnsureFlows: %v", err)
	}
	var achou bool
	for _, c := range ex.comandos {
		if strings.Contains(c, "add chain") {
			achou = true
			if !strings.Contains(c, "hook forward") || !strings.Contains(c, "priority filter + 15") {
				t.Errorf("chain fora do lugar: %q", c)
			}
			if !strings.Contains(c, "policy accept") {
				t.Errorf("chain de medição com política que descarta pacote: %q", c)
			}
		}
	}
	if !achou {
		t.Error("nenhuma chain foi criada")
	}
}

func TestEnsureFlowsSemWANNaoTocaEmNada(t *testing.T) {
	// Sem saber quais interfaces são WAN não dá para distinguir host local de
	// endereço da internet, e a regra sem escopo encheria o set com o tráfego
	// de entrada. Mesma decisão de EnsureAccounting: não agir.
	ex := &execFalso{}
	s := &Service{exec: ex}
	if err := s.EnsureFlows(context.Background(), nil, FlowsConfig{Ligado: true}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("executou sem WAN configurada: %v", ex.comandos)
	}
}

func TestEnsureFlowsDryRunNaoExecuta(t *testing.T) {
	ex := &execFalso{dryRun: true}
	s := &Service{exec: ex}
	if err := s.EnsureFlows(context.Background(), []string{"wan1"}, FlowsConfig{Ligado: true}); err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(ex.comandos) != 0 {
		t.Errorf("dry-run executou: %v", ex.comandos)
	}
}

func TestDisableFlowsComTabelaAusenteNaoEhFalha(t *testing.T) {
	// O caminho NORMAL de uma caixa com a feature desligada é este: o boot
	// manda apagar o que nunca existiu. Tratar isso como erro encheria o
	// journal de falha que não houve, e o operador aprenderia a ignorar o
	// journal — que é como uma falha de verdade passa despercebida.
	ex := &execFalso{erros: map[string]error{
		"delete table": errors.New("Error: No such file or directory"),
	}}
	s := &Service{exec: ex}
	if err := s.DisableFlows(context.Background()); err != nil {
		t.Errorf("tabela ausente virou erro: %v", err)
	}
}

func TestDisableFlowsPropagaFalhaDeVerdade(t *testing.T) {
	// O outro lado: engolir TODA falha esconderia uma tabela que continua no
	// kernel registrando conversas depois de o admin ter desligado o registro.
	ex := &execFalso{erros: map[string]error{
		"delete table": errors.New("Error: Operation not permitted"),
	}}
	s := &Service{exec: ex}
	if err := s.DisableFlows(context.Background()); err == nil {
		t.Error("falha real foi engolida")
	}
}

func TestFlowsPropagaErroDeLeitura(t *testing.T) {
	// Lista vazia é indistinguível de "ninguém falou com ninguém". Um erro
	// de leitura virando lista vazia é a tela afirmando silêncio numa rede que
	// pode estar em plena atividade.
	ex := &execFalsoQueFalhaNaLeitura{}
	s := &Service{exec: ex}
	if _, err := s.Flows(context.Background()); err == nil {
		t.Error("erro de leitura virou resposta vazia")
	}
}

// execFalsoQueFalhaNaLeitura existe porque o execFalso do accounting_test nunca
// devolve erro em ExecuteRead — e é justamente o caminho de erro da leitura que
// precisa ser provado aqui.
type execFalsoQueFalhaNaLeitura struct{ execFalso }

func (e *execFalsoQueFalhaNaLeitura) ExecuteRead(context.Context, string, ...string) (string, error) {
	return "", errors.New("Error: No such file or directory")
}
