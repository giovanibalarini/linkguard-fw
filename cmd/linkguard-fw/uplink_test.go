package main

import (
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/platform"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// instantaneoDaOCI é a VM real: UMA VNIC, IMDS confirmado, a placa anunciando
// 9000 e o caminho externo aceitando 1500. Os números vieram de uma instância de
// verdade — ver internal/platform/detect.go.
func instantaneoDaOCI() platform.Snapshot {
	fatos := platform.Facts{
		Kind:       platform.KindOCI,
		Confidence: platform.ConfidenceAuthoritative,
		Net: platform.NetFacts{
			PrimaryInterface: "ens3",
			LinkMTU:          9000,
			PathMTU:          1500,
			PathMTUSource:    platform.PathMTUSourcePlatform,
		},
		OCI: &platform.OCIFacts{
			MaxVNICAttachments: 1,
			VNICs:              []platform.OCIVNIC{{SubnetCIDR: "10.0.0.0/24"}},
		},
	}
	return platform.Snapshot{
		Format:       platform.SnapshotFormat,
		Facts:        fatos,
		Capabilities: platform.DeriveCapabilities(fatos),
	}
}

// cadastrarLink grava um link como a tela o grava: habilitado, com interface e
// com TableID, que é o que links.Service.Create SEMPRE atribui.
func cadastrarLink(t *testing.T, db *storage.DB, nome, iface string, tableID int) {
	t.Helper()
	if err := db.CreateLink(&storage.Link{
		Name:      nome,
		Interface: iface,
		Gateway:   "10.0.0.1",
		Enabled:   true,
		TableID:   tableID,
	}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
}

// TestNumaOCIDeUmaVNICOUplinkSaiDaPlataformaSemTocarATabelaDeLinks é o cenário
// que este incremento existe para fazer funcionar: a VM de nuvem recém-criada,
// banco vazio, ninguém abriu tela nenhuma.
//
// Antes disto a lista de WANs saía vazia, ReconcileMasquerade se recusava a
// agir — corretamente — e a máquina não tinha saída para a Internet.
func TestNumaOCIDeUmaVNICOUplinkSaiDaPlataformaSemTocarATabelaDeLinks(t *testing.T) {
	db := bancoDeTeste(t)
	plat := instantaneoDaOCI()

	u := uplinkEfetivo(db, plat)
	if u.Interface != "ens3" {
		t.Fatalf("o uplink implícito não foi derivado: %+v", u)
	}
	if !u.Implicito {
		t.Error("o uplink veio marcado como cadastrado, e ninguém cadastrou nada")
	}
	// A MTU DO CAMINHO, não a da placa. 9000 aqui seria o defeito que o ajuste
	// de MSS existe para não cometer.
	if u.PathMTU != 1500 {
		t.Errorf("PathMTU = %d, esperado 1500 (a placa anuncia 9000; o caminho não)", u.PathMTU)
	}

	wans, err := wansEfetivas(db, plat)
	if err != nil {
		t.Fatalf("wansEfetivas: %v", err)
	}
	if len(wans) != 1 || wans[0] != "ens3" {
		t.Fatalf("a lista efetiva de WANs tinha de ser [ens3], obtive %v", wans)
	}

	// E A TABELA `links` CONTINUA VAZIA. É a metade do contrato que nenhum
	// teste de firewall pega: um atalho que "só cadastrasse o link sozinho"
	// passaria em tudo acima e ligaria o maquinário multi-WAN inteiro.
	ls, err := db.GetLinks()
	if err != nil {
		t.Fatalf("GetLinks: %v", err)
	}
	if len(ls) != 0 {
		t.Fatalf("o uplink implícito criou %d linha(s) na tabela de links", len(ls))
	}
}

// TestOUplinkImplicitoNaoProduzTableIDNemCaminhoDeVolta prende a armadilha por
// onde este incremento quase passou.
//
// links.Service.Create SEMPRE atribui TableID >= 100, e links.WANPaths devolve
// caminho para todo link com TableID > 0. Dali saem `ip rule fwmark`, tabela de
// policy routing, marca de conexão por link, rota de retorno, monitor e
// failover — tudo inútil ou ativamente errado numa máquina de UMA VNIC, onde a
// rota default é do DHCP da fabric e não existe segunda tabela a consultar.
//
// Sem linha em `links`, WANPaths não tem de onde tirar nada, e nada disso liga.
// Não por uma guarda nova: por construção.
func TestOUplinkImplicitoNaoProduzTableIDNemCaminhoDeVolta(t *testing.T) {
	db := bancoDeTeste(t)
	plat := instantaneoDaOCI()

	if u := uplinkEfetivo(db, plat); u.Interface == "" {
		t.Fatal("o uplink implícito não foi derivado; o resto deste teste não diria nada")
	}

	ls, err := db.GetLinks()
	if err != nil {
		t.Fatalf("GetLinks: %v", err)
	}
	caminhos := links.WANPaths(ls)
	if len(caminhos) != 0 {
		t.Fatalf("o uplink implícito produziu %d caminho(s) de policy routing: %+v", len(caminhos), caminhos)
	}
	if marcas := connMarksDe(caminhos); len(marcas) != 0 {
		t.Errorf("o uplink implícito produziu marcas de conexão por link: %+v", marcas)
	}
	if rotas := replyRoutesDe(caminhos); len(rotas) != 0 {
		t.Errorf("o uplink implícito produziu rotas de retorno: %+v", rotas)
	}
}

// TestOCadastroVenceOUplinkDaPlataforma: o admin é a autoridade. Um link
// habilitado com interface é decisão explícita, e o implícito não pode competir
// com ela nem somar-se a ela — somar significaria mascarar por duas interfaces
// numa máquina que tem uma.
func TestOCadastroVenceOUplinkDaPlataforma(t *testing.T) {
	db := bancoDeTeste(t)
	plat := instantaneoDaOCI()
	cadastrarLink(t, db, "Link do admin", "ens5", 100)

	if u := uplinkEfetivo(db, plat); u != (Uplink{}) {
		t.Errorf("o implícito sobreviveu ao cadastro: %+v", u)
	}
	wans, err := wansEfetivas(db, plat)
	if err != nil {
		t.Fatalf("wansEfetivas: %v", err)
	}
	if len(wans) != 1 || wans[0] != "ens5" {
		t.Fatalf("as WANs efetivas tinham de ser só a cadastrada, obtive %v", wans)
	}

	// E não há uplink IMPLÍCITO nenhum: é isso, e só isso, que o cadastro
	// desliga. A MTU do caminho NÃO vem daqui — ver o teste seguinte, e o
	// comentário do PathMTU em main.go.
	if mtu := uplinkEfetivo(db, plat).PathMTU; mtu != 0 {
		t.Errorf("o PathMTU do implícito vazou para uma máquina com link cadastrado: %d", mtu)
	}
}

// TestCadastrarOLinkNaNuvemNaoApagaAMTUDoCaminho é a regressão que o primeiro
// desenho desta entrega tinha, e ela é o BLOQUEANTE do incremento inteiro.
//
// A fiação original derivava o PathMTU de uplinkEfetivo, que devolve zero-value
// assim que existe um link cadastrado. O raciocínio era "o implícito sai de
// cena e o `rt mtu` volta" — e ele é FALSO em hairpin: `rt mtu` mora no ramo
// PerLink(), que é !hairpin, isto é, inalcançável numa VM de VNIC única. O que
// voltava não era o `rt mtu`: era a chain de ajuste VAZIA.
//
// O efeito prático, na máquina real: o bastion da OCI TEM o link cadastrado à
// mão — foi assim que ele passou a sair para a Internet antes desta entrega —,
// então era exatamente ali, e só ali, que o ajuste de MSS não seria escrito.
// Ping e DNS funcionam, `docker pull` e `apt` penduram, e nada falha.
//
// A MTU do caminho é um fato da REDE. Ninguém a muda digitando "ens3" num
// formulário.
func TestCadastrarOLinkNaNuvemNaoApagaAMTUDoCaminho(t *testing.T) {
	db := bancoDeTeste(t)
	plat := instantaneoDaOCI()
	// Exatamente o que o dono fez no bastion: cadastrar a própria placa.
	cadastrarLink(t, db, "WAN", "ens3", 100)

	// A MESMA construção que o SetZoneFactsSource de main.go monta.
	fatos := nftables.ZoneFacts{
		Hairpin:   !plat.Capable().RoutedTransit,
		LocalNets: redesLocais(db, plat),
		PathMTU:   uplinkDaPlataforma(plat).PathMTU,
	}
	if !fatos.Hairpin {
		t.Fatal("o cenário perdeu o sentido: uma VNIC só tem de produzir hairpin")
	}
	if fatos.PathMTU != 1500 {
		t.Fatalf("PathMTU = %d com o link cadastrado; a plataforma mediu 1500, e cadastrar um link "+
			"não muda o que o caminho suporta. Em hairpin isto NÃO cai no `rt mtu`: deixa a "+
			"chain de ajuste de MSS vazia e o `docker pull` pendura", fatos.PathMTU)
	}

	wans, err := wansEfetivas(db, plat)
	if err != nil {
		t.Fatalf("wansEfetivas: %v", err)
	}
	z := nftables.NewZone(wans, fatos.LocalNets, fatos.Hairpin, fatos.PathMTU)
	if z.PathMTU() != 1500 {
		t.Errorf("a zona recebeu PathMTU = %d; o ajuste de MSS não tem número para usar", z.PathMTU())
	}
	if z.PerLink() {
		t.Fatal("a zona deixou de ser hairpin: o teste pararia de cobrir o ramo que importa")
	}
}

// TestUmaCaixaOnPremSemLinkCadastradoNaoGanhaUplinkImplicito é A PROPRIEDADE
// QUE PROTEGE A PRODUÇÃO, e a razão de a guarda ser estreita.
//
// Numa Debian on-prem recém-instalada, Facts.Net.PrimaryInterface ESTÁ
// preenchido — é uma eleição: a rota default, ou a primeira placa que não é de
// sistema — e pode perfeitamente apontar para a interface da LAN. Derivar o
// uplink dali poria masquerade na placa de DENTRO: NAT para o lado errado numa
// caixa que hoje, corretamente, não faz NAT nenhum.
func TestUmaCaixaOnPremSemLinkCadastradoNaoGanhaUplinkImplicito(t *testing.T) {
	db := bancoDeTeste(t)
	fatos := platform.Facts{
		Kind:       platform.KindOnPrem,
		Confidence: platform.ConfidenceLocal,
		// A placa eleita é a da LAN — exatamente o caso perigoso.
		Net: platform.NetFacts{PrimaryInterface: "br10", LinkMTU: 1500},
	}
	plat := platform.Snapshot{
		Format:       platform.SnapshotFormat,
		Facts:        fatos,
		Capabilities: platform.DeriveCapabilities(fatos),
	}

	if u := uplinkEfetivo(db, plat); u != (Uplink{}) {
		t.Fatalf("uma caixa on-prem ganhou uplink implícito em %q: seria masquerade na placa de dentro", u.Interface)
	}
	wans, err := wansEfetivas(db, plat)
	if err != nil {
		t.Fatalf("wansEfetivas: %v", err)
	}
	if len(wans) != 0 {
		t.Fatalf("a lista de WANs de uma caixa on-prem sem link tinha de ser VAZIA — é ela que mantém a "+
			"guarda de ReconcileMasquerade valendo. Obtive %v", wans)
	}
}

// TestPlataformaNaoAutoritativaNaoDerivaUplink: "achei que era nuvem por um
// sinal local" não é autoridade suficiente para começar a mascarar tráfego
// sozinho. Só o IMDS do provedor responde essa pergunta.
func TestPlataformaNaoAutoritativaNaoDerivaUplink(t *testing.T) {
	db := bancoDeTeste(t)
	base := instantaneoDaOCI()

	casos := map[string]func(platform.Snapshot) platform.Snapshot{
		"o IMDS não confirmou": func(s platform.Snapshot) platform.Snapshot {
			s.Facts.Confidence = platform.ConfidenceLocal
			return s
		},
		"a nuvem tem mais de uma VNIC": func(s platform.Snapshot) platform.Snapshot {
			s.Facts.OCI.MaxVNICAttachments = 2
			s.Capabilities = platform.DeriveCapabilities(s.Facts)
			return s
		},
		"a plataforma não sabe o nome da placa": func(s platform.Snapshot) platform.Snapshot {
			s.Facts.Net.PrimaryInterface = ""
			return s
		},
		"o instantâneo é de um formato que este binário não lê": func(s platform.Snapshot) platform.Snapshot {
			s.Format = platform.SnapshotFormat + 1
			return s
		},
	}
	for nome, torcer := range casos {
		t.Run(nome, func(t *testing.T) {
			s := torcer(instantaneoDaOCIComOCIPropria(base))
			if u := uplinkEfetivo(db, s); u != (Uplink{}) {
				t.Errorf("derivou uplink sem autoridade para isso: %+v", u)
			}
		})
	}
}

// instantaneoDaOCIComOCIPropria devolve uma cópia com OCIFacts PRÓPRIO: o campo
// é ponteiro, e um subteste que mexesse nele estragaria os outros — o tipo de
// acoplamento entre casos que só aparece quando a ordem muda.
func instantaneoDaOCIComOCIPropria(s platform.Snapshot) platform.Snapshot {
	oci := *s.Facts.OCI
	s.Facts.OCI = &oci
	return s
}

// TestAPlataformaDesconhecidaNaoDerivaUplink prende o zero-value permissivo no
// lugar onde ele decide se o produto escreve NAT sozinho: uma detecção que
// nunca rodou, falhou, ou não reconheceu a máquina não pode virar autorização.
func TestAPlataformaDesconhecidaNaoDerivaUplink(t *testing.T) {
	db := bancoDeTeste(t)
	casos := map[string]platform.Snapshot{
		"instantâneo zero":        {},
		"plataforma desconhecida": platform.UnknownSnapshot(),
	}
	for nome, snap := range casos {
		t.Run(nome, func(t *testing.T) {
			if u := uplinkEfetivo(db, snap); u != (Uplink{}) {
				t.Errorf("%s derivou uplink: %+v", nome, u)
			}
			wans, err := wansEfetivas(db, snap)
			if err != nil {
				t.Fatalf("wansEfetivas: %v", err)
			}
			if len(wans) != 0 {
				t.Errorf("%s produziu WANs: %v", nome, wans)
			}
		})
	}
}

// TestOLinkDesabilitadoNaoImpedeOUplinkImplicito: o cadastro que VENCE é o
// habilitado. Um link desligado (ou sem interface) é intenção guardada, não
// decisão valendo — e tratá-lo como cadastro deixaria a VM de nuvem sem saída
// justamente depois de o admin desligar o link que não funcionava.
func TestOLinkDesabilitadoNaoImpedeOUplinkImplicito(t *testing.T) {
	db := bancoDeTeste(t)
	plat := instantaneoDaOCI()
	if err := db.CreateLink(&storage.Link{
		Name: "desligado", Interface: "ens5", Enabled: false, TableID: 100,
	}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if u := uplinkEfetivo(db, plat); u.Interface != "ens3" || !u.Implicito {
		t.Fatalf("um link DESLIGADO bloqueou o uplink implícito: %+v", u)
	}
}

// TestATelaDizDeOndeVeioOUplink: as três origens têm de ser distinguíveis.
// "veio do cadastro" e "não há uplink nenhum" são estados diferentes, e só no
// segundo o operador tem trabalho a fazer.
func TestATelaDizDeOndeVeioOUplink(t *testing.T) {
	plat := instantaneoDaOCI()

	semNada := bancoDeTeste(t)
	v := uplinkParaTela(semNada, plat)
	if v.Origem != "platform" || v.Interface != "ens3" || v.PathMTU != 1500 || !v.Implicito {
		t.Errorf("a VM de nuvem sem link tinha de se anunciar como uplink da plataforma: %+v", v)
	}
	if v.Plataforma != string(platform.KindOCI) {
		t.Errorf("a tela não nomeou a plataforma: %+v", v)
	}

	comLink := bancoDeTeste(t)
	cadastrarLink(t, comLink, "WAN1", "ens5", 100)
	if v := uplinkParaTela(comLink, plat); v.Origem != "link" || v.Interface != "ens5" || v.Implicito {
		t.Errorf("com link cadastrado a tela tinha de dizer que a origem é o cadastro: %+v", v)
	}

	onprem := bancoDeTeste(t)
	if v := uplinkParaTela(onprem, platform.UnknownSnapshot()); v.Origem != "none" || v.Interface != "" {
		t.Errorf("a caixa sem link e sem plataforma que responda tinha de dizer que não há uplink: %+v", v)
	}
}
