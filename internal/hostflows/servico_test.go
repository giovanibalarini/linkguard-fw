package hostflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/dnstap"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// ─── dublês ──────────────────────────────────────────────────────────────────

type fwFalso struct {
	snap       nftables.FlowSnapshot
	erroLer    error
	erroApagar error
	leituras   int
	chamadas   []string
}

func (f *fwFalso) EnsureFlows(_ context.Context, wans []string, _ nftables.FlowsConfig) error {
	f.chamadas = append(f.chamadas, "ensure:"+strings.Join(wans, ","))
	return nil
}

func (f *fwFalso) DisableFlows(context.Context) error {
	f.chamadas = append(f.chamadas, "disable")
	return f.erroApagar
}

func (f *fwFalso) Flows(context.Context) (nftables.FlowSnapshot, error) {
	f.leituras++
	if f.erroLer != nil {
		return nftables.FlowSnapshot{}, f.erroLer
	}
	return f.snap, nil
}

type bancoFalso struct {
	valores map[string]string
	erroLer error
}

func (b *bancoFalso) GetSetting(k string) (string, error) {
	if b.erroLer != nil {
		return "", b.erroLer
	}
	return b.valores[k], nil
}

func (b *bancoFalso) SetSetting(k, v string) error {
	if b.valores == nil {
		b.valores = map[string]string{}
	}
	b.valores[k] = v
	return nil
}

type nomesFalsos map[string]string

func (n nomesFalsos) Nome(a netip.Addr) (string, bool) {
	nome, ok := n[a.String()]
	return nome, ok
}

func (n nomesFalsos) Estado() dnstap.Estado {
	return dnstap.Estado{Entradas: len(n), Teto: dnstap.MaxEntradas}
}

// nomesCheios é o mapa que JÁ despejou entrada por teto — o estado que faz um
// destino sem nome significar "foi consultado e saiu", não "nunca foi visto".
type nomesCheios map[string]string

func (n nomesCheios) Nome(a netip.Addr) (string, bool) {
	nome, ok := n[a.String()]
	return nome, ok
}

func (n nomesCheios) Estado() dnstap.Estado {
	return dnstap.Estado{Entradas: len(n), Teto: dnstap.MaxEntradas, Cheio: true}
}

// coletorLigado / coletorDesligado são o segundo argumento de SetNomes.
func coletorLigado() bool    { return true }
func coletorDesligado() bool { return false }

// bancoLigado devolve um banco com o registro ligado na janela e teto pedidos.
func bancoLigado(janela, teto int) *bancoFalso {
	bruto, err := json.Marshal(nftables.FlowsConfig{Ligado: true, JanelaMinutos: janela, Teto: teto})
	if err != nil {
		panic(err)
	}
	return &bancoFalso{valores: map[string]string{ConfigSettingKey: string(bruto)}}
}

// ─── agregação, pura ─────────────────────────────────────────────────────────

var amostra = []nftables.Flow{
	{Origem: "192.168.3.50", Destino: "8.8.8.8", Porta: 53, Pacotes: 2, Bytes: 120},
	{Origem: "192.168.3.50", Destino: "142.250.219.14", Porta: 443, Pacotes: 12, Bytes: 3456},
	{Origem: "192.168.3.77", Destino: "140.82.121.4", Porta: 443, Pacotes: 900, Bytes: 1548221},
}

func TestAgregarFiltraPeloHostPedido(t *testing.T) {
	linhas, total, _ := agregar(amostra, "192.168.3.50", 0)
	if total != 2 || len(linhas) != 2 {
		t.Fatalf("queria 2 conversas do host, veio %d (total %d)", len(linhas), total)
	}
	for _, l := range linhas {
		if l.Origem != "192.168.3.50" {
			t.Errorf("vazou conversa de outro host: %+v", l)
		}
	}
}

func TestAgregarSemHostDevolveARedeInteira(t *testing.T) {
	// A visão de rede é legítima — é ela que responde quem encheu o link
	// dentro da janela. O que não pode é ela sumir por o filtro estar vazio.
	if _, total, _ := agregar(amostra, "", 0); total != 3 {
		t.Errorf("host vazio devolveu %d conversas, queria 3", total)
	}
}

func TestAgregarNaoApresentaOCorteComoListaCompleta(t *testing.T) {
	// O DEFEITO: a tela mostra 1 destino porque o limite é 1, e o admin conclui
	// que o host falou com um destino só. TotalConversas é o que permite a tela
	// dizer "1 de 2" — sem ele, o corte vira uma afirmação falsa.
	linhas, total, _ := agregar(amostra, "192.168.3.50", 1)
	if len(linhas) != 1 {
		t.Fatalf("o limite não cortou: %d linhas", len(linhas))
	}
	if total != 2 {
		t.Errorf("o total foi contado DEPOIS do corte: %d, queria 2", total)
	}
}

func TestAgregarSomaOTotalDeBytesAntesDoCorte(t *testing.T) {
	// Mesmo defeito na outra coluna: um total somado só sobre as linhas que
	// sobraram diria que o host consumiu 3456 bytes quando consumiu 3576.
	_, _, bytes := agregar(amostra, "192.168.3.50", 1)
	if bytes != 3576 {
		t.Errorf("total de bytes: %d, queria 3576", bytes)
	}
}

func TestAgregarOrdenaPorVolumeComDesempateEstavel(t *testing.T) {
	// Sem o desempate, duas conversas de mesmo volume trocam de lugar a cada
	// leitura e a tela pisca sozinha na frente de quem está diagnosticando.
	empate := []nftables.Flow{
		{Origem: "192.168.3.9", Destino: "10.0.0.2", Porta: 443, Bytes: 100},
		{Origem: "192.168.3.9", Destino: "10.0.0.1", Porta: 443, Bytes: 100},
		{Origem: "192.168.3.9", Destino: "10.0.0.1", Porta: 80, Bytes: 100},
		{Origem: "192.168.3.9", Destino: "10.0.0.3", Porta: 443, Bytes: 900},
	}
	querido := []string{"10.0.0.3:443", "10.0.0.1:80", "10.0.0.1:443", "10.0.0.2:443"}
	for i := 0; i < 5; i++ {
		linhas, _, _ := agregar(empate, "", 0)
		for j, l := range linhas {
			got := fmt.Sprintf("%s:%d", l.Destino, l.Porta)
			if got != querido[j] {
				t.Fatalf("volta %d, posição %d: veio %s, queria %s", i, j, got, querido[j])
			}
		}
	}
}

func TestAgregarNaoAceitaLimiteAbsurdo(t *testing.T) {
	// Limite sem teto deixa uma requisição autenticada só mandar o servidor
	// serializar o set inteiro — o mesmo motivo do clampLimit dos handlers.
	muitos := make([]nftables.Flow, LimiteMaximo+10)
	for i := range muitos {
		muitos[i] = nftables.Flow{Origem: "192.168.3.1", Destino: "10.0.0.1", Porta: uint16(i % 65535)}
	}
	if linhas, _, _ := agregar(muitos, "", 100000); len(linhas) != LimiteMaximo {
		t.Errorf("limite absurdo devolveu %d linhas", len(linhas))
	}
}

// ─── configuração ────────────────────────────────────────────────────────────

func TestConfigChaveAusenteEhDesligado(t *testing.T) {
	// Estado de toda máquina anterior a esta entrega. Ligar um registro de
	// quem-falou-com-quem sozinho, no upgrade, seria decidir pelo cliente.
	s := NovoServico(&fwFalso{}, &bancoFalso{})
	cfg, err := s.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.Ligado {
		t.Error("registro nasceu ligado")
	}
	if cfg.JanelaMinutos != nftables.FlowsJanelaPadrao || cfg.Teto != nftables.FlowsTetoPadrao {
		t.Errorf("config ausente não caiu no padrão: %+v", cfg)
	}
}

func TestConfigErroDeBancoNaoViraDesligado(t *testing.T) {
	// O DEFEITO: um SELECT que falhou vira "o admin não ligou", e a
	// reconciliação do boot derruba a tabela de uma caixa cuja feature está
	// ligada — apagando a janela por causa de um erro de banco, em silêncio.
	s := NovoServico(&fwFalso{}, &bancoFalso{erroLer: errors.New("banco travado")})
	if _, err := s.Config(); err == nil {
		t.Error("erro de banco foi engolido")
	}
}

func TestReconciliarComErroDeBancoNaoDerrubaATabela(t *testing.T) {
	fw := &fwFalso{}
	s := NovoServico(fw, &bancoFalso{erroLer: errors.New("banco travado")})
	if err := s.Reconciliar(context.Background(), []string{"wan1"}); err == nil {
		t.Error("erro de banco foi engolido")
	}
	for _, c := range fw.chamadas {
		if c == "disable" {
			t.Error("um erro de leitura apagou a janela inteira")
		}
	}
}

func TestReconciliarDesligadoDerrubaATabela(t *testing.T) {
	// Desligado tem de significar desligado NO KERNEL: sem isto a base chain
	// continuaria no hook forward de uma caixa cujo admin desligou o registro,
	// cobrando custo por pacote e guardando conversa que ninguém pediu.
	fw := &fwFalso{}
	s := NovoServico(fw, &bancoFalso{})
	if err := s.Reconciliar(context.Background(), []string{"wan1"}); err != nil {
		t.Fatalf("Reconciliar: %v", err)
	}
	if len(fw.chamadas) != 1 || fw.chamadas[0] != "disable" {
		t.Errorf("chamadas: %v", fw.chamadas)
	}
}

func TestSalvarConfigDerrubaATabelaAntesDeRecriar(t *testing.T) {
	// O DEFEITO QUE ISTO PRENDE: o add-set do nft é idempotente e IGNORA a spec
	// quando o set já existe. Sem o delete antes, mudar a janela de 60 para 15
	// minutos grava 15 no banco e deixa o kernel com 60 — a tela passa a rotular
	// como "últimos 15 minutos" um dado de uma hora.
	fw := &fwFalso{}
	s := NovoServico(fw, &bancoFalso{})
	cfg := nftables.FlowsConfig{Ligado: true, JanelaMinutos: 15, Teto: 2048}
	if err := s.SalvarConfig(context.Background(), cfg, []string{"wan1"}); err != nil {
		t.Fatalf("SalvarConfig: %v", err)
	}
	if len(fw.chamadas) != 2 || fw.chamadas[0] != "disable" || fw.chamadas[1] != "ensure:wan1" {
		t.Errorf("ordem das chamadas: %v", fw.chamadas)
	}
}

func TestSalvarConfigDesligadoNaoRecriaAEstrutura(t *testing.T) {
	fw := &fwFalso{}
	s := NovoServico(fw, &bancoFalso{})
	if err := s.SalvarConfig(context.Background(), nftables.FlowsConfig{}, []string{"wan1"}); err != nil {
		t.Fatalf("SalvarConfig: %v", err)
	}
	for _, c := range fw.chamadas {
		if strings.HasPrefix(c, "ensure") {
			t.Errorf("desligar recriou a estrutura: %v", fw.chamadas)
		}
	}
}

// ─── consulta, cache e nomes ─────────────────────────────────────────────────

func instantaneoDeTeste() nftables.FlowSnapshot {
	return nftables.FlowSnapshot{Fluxos: amostra, JanelaMinutos: 60, Teto: 8192}
}

func TestConsultarDesligadoNaoSeDisfarcaDeSilencio(t *testing.T) {
	// O DEFEITO: com o registro desligado, a tela recebe uma lista vazia e diz
	// "este host não falou com ninguém" — que é uma afirmação sobre a rede,
	// não sobre o produto. O campo Ligado é o que separa as duas.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, &bancoFalso{})
	r, err := s.Consultar(context.Background(), "192.168.3.50", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if r.Ligado {
		t.Error("respondeu ligado com o registro desligado")
	}
	if fw.leituras != 0 {
		t.Error("leu o kernel com a feature desligada")
	}
}

func TestConsultarUsaAJanelaDoKernelNaoADoBanco(t *testing.T) {
	// O admin salvou 15 minutos, mas a tabela ainda não foi recriada e o kernel
	// aplica 60. Rotular a tela com o valor do banco afirmaria que aquelas
	// conversas são dos últimos 15 minutos.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(15, 2048))
	r, err := s.Consultar(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if r.JanelaMinutos != 60 {
		t.Errorf("janela veio do banco (%d) em vez do kernel (60)", r.JanelaMinutos)
	}
}

func TestConsultarPropagaFalhaDeLeituraEmVezDeMostrarSilencio(t *testing.T) {
	fw := &fwFalso{erroLer: errors.New("nft indisponível")}
	s := NovoServico(fw, bancoLigado(60, 8192))
	if _, err := s.Consultar(context.Background(), "", 0); err == nil {
		t.Error("falha de leitura virou tela vazia")
	}
}

func TestConsultasSeguidasNaoViramUmNftPorSegundo(t *testing.T) {
	// Um list-set de milhares de elementos a cada repolling do navegador é CPU
	// e latência de painel numa appliance de 2 GB.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	relogio := time.Now()
	s.agora = func() time.Time { return relogio }

	for i := 0; i < 5; i++ {
		if _, err := s.Consultar(context.Background(), "", 0); err != nil {
			t.Fatalf("Consultar: %v", err)
		}
	}
	if fw.leituras != 1 {
		t.Errorf("5 consultas dentro da validade viraram %d leituras do kernel", fw.leituras)
	}
}

func TestCacheNaoCongelaNumeroVelhoDepoisDeVencer(t *testing.T) {
	// O DEFEITO, e é o pior desta tela: o tráfego para, o kernel expira as
	// tuplas, e o painel continua mostrando as conversas da última leitura. Um
	// painel que congela o último valor conhecido é a definição de mentir na
	// tela — e é justamente o que a janela rolante existe para não fazer.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	relogio := time.Now()
	s.agora = func() time.Time { return relogio }

	if r, _ := s.Consultar(context.Background(), "", 0); r.TotalConversas != 3 {
		t.Fatalf("primeira leitura: %d conversas", r.TotalConversas)
	}

	// O kernel esvaziou o set; o relógio passou da validade.
	fw.snap = nftables.FlowSnapshot{Fluxos: []nftables.Flow{}, JanelaMinutos: 60, Teto: 8192}
	relogio = relogio.Add(ValidadeDoCache + time.Second)

	r, err := s.Consultar(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if r.TotalConversas != 0 {
		t.Errorf("a tela continuou mostrando %d conversas velhas", r.TotalConversas)
	}
}

func TestSalvarConfigDescartaOCacheDoSetAntigo(t *testing.T) {
	// Sem isto, por até ValidadeDoCache a tela mostraria as conversas de um set
	// que acabou de ser derrubado, já com o rótulo da janela nova.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, &bancoFalso{valores: map[string]string{}})
	if err := s.SalvarConfig(context.Background(),
		nftables.FlowsConfig{Ligado: true, JanelaMinutos: 60, Teto: 8192}, []string{"wan1"}); err != nil {
		t.Fatalf("SalvarConfig: %v", err)
	}
	if _, err := s.Consultar(context.Background(), "", 0); err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	antes := fw.leituras
	if err := s.SalvarConfig(context.Background(),
		nftables.FlowsConfig{Ligado: true, JanelaMinutos: 15, Teto: 2048}, []string{"wan1"}); err != nil {
		t.Fatalf("SalvarConfig: %v", err)
	}
	if _, err := s.Consultar(context.Background(), "", 0); err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if fw.leituras != antes+1 {
		t.Errorf("a consulta depois de salvar veio do cache velho (leituras: %d -> %d)", antes, fw.leituras)
	}
}

func TestNomeDoDestinoSaiDoMapaENuncaEhInventado(t *testing.T) {
	// Endereço que o mapa não conhece fica SEM nome, e a tela mostra o endereço
	// cru. Inventar (o último nome que aquele endereço teve, por exemplo) é o
	// que o TTL do mapa da #116 existe para impedir: endereço de CDN é de um
	// site hoje e de outro daqui a dez minutos.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	s.SetNomes(nomesFalsos{"8.8.8.8": "dns.google"}, coletorLigado)

	r, err := s.Consultar(context.Background(), "192.168.3.50", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if !r.NomesLigados {
		t.Error("mapa ligado e a resposta diz que não")
	}
	var comNome, semNome int
	for _, c := range r.Conversas {
		switch c.Destino {
		case "8.8.8.8":
			if c.Nome != "dns.google" {
				t.Errorf("destino conhecido veio sem nome: %+v", c)
			}
			comNome++
		default:
			if c.Nome != "" {
				t.Errorf("destino desconhecido ganhou nome inventado: %+v", c)
			}
			semNome++
		}
	}
	if comNome != 1 || semNome != 1 {
		t.Errorf("conversas: %+v", r.Conversas)
	}
}

func TestSemMapaDeNomesARespostaDizQueNaoEstaOlhando(t *testing.T) {
	// O DEFEITO: coluna de nomes vazia parece "nenhum destino tem nome"
	// quando a verdade é "o produto não está olhando o DNS". São
	// diagnósticos opostos.
	fw := &fwFalso{snap: instantaneoDeTeste()}
	s := NovoServico(fw, bancoLigado(60, 8192))
	r, err := s.Consultar(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if r.NomesLigados {
		t.Error("sem mapa e a resposta diz que os nomes estão ligados")
	}
}

func TestConsultarRepassaOTetoBatido(t *testing.T) {
	// Conversa que não coube no set some da tela. Sem este aviso, a ausência
	// parece "não aconteceu".
	fw := &fwFalso{snap: nftables.FlowSnapshot{Fluxos: amostra, JanelaMinutos: 60, Teto: 3, Cheio: true}}
	s := NovoServico(fw, bancoLigado(60, 8192))
	r, err := s.Consultar(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("Consultar: %v", err)
	}
	if !r.Cheio || r.Teto != 3 {
		t.Errorf("medição cheia não chegou à tela: %+v", r)
	}
}
