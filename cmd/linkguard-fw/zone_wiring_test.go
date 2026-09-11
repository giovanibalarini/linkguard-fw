package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
	"github.com/giovanibalarini/linkguard-fw/internal/platform"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// TestMainLigaOEixoDasRegrasAPlataforma é um guarda de deriva no mesmo espírito
// de TestMainWiresTheInputChainSources, e existe pelo mesmo motivo: sem a
// chamada, NADA QUEBRA VISIVELMENTE.
//
// internal/nftables não pode importar internal/platform — é por isso que
// ZoneFacts existe como struct estreita —, então o único lugar que pode ligar
// os dois é este main. Se a ligação sumir num refactor, o zero-value permissivo
// entra em cena: toda Zone volta a renderizar por interface, os testes do
// pacote continuam verdes, a caixa on-prem continua perfeita, e a VM de uma
// placa só volta a medir zero e a cortar o próprio tráfego — calada, porque é
// exatamente o comportamento anterior.
func TestMainLigaOEixoDasRegrasAPlataforma(t *testing.T) {
	_, thisFile, ok := localizar()
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(thisFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	var ligada bool
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if isIdent && recv.Name == "nftSvc" && sel.Sel.Name == "SetZoneFactsSource" {
			ligada = true
		}
		return true
	})
	if !ligada {
		t.Error("main.go não chama nftSvc.SetZoneFactsSource: o eixo das regras não chega mais à plataforma, " +
			"e a máquina de uma placa só volta ao comportamento que este incremento corrigiu — sem nada falhar")
	}
}

func localizar() (uintptr, string, bool) {
	pc, f, _, ok := runtime.Caller(1)
	return pc, f, ok
}

// TestAPlataformaDesconhecidaMantemOEixoDeInterface prende a ponta que o
// guarda sintático acima não alcança: o VALOR que a fonte entrega.
//
// platform.Snapshot zero e platform.UnknownSnapshot têm de produzir Hairpin
// FALSO. É o contrato do zero-value permissivo, e é o que garante que uma
// detecção que não rodou, falhou ou não reconheceu a máquina deixe o firewall
// exatamente como a produção o tem hoje.
func TestAPlataformaDesconhecidaMantemOEixoDeInterface(t *testing.T) {
	casos := map[string]platform.Snapshot{
		"instantâneo zero":        {},
		"plataforma desconhecida": platform.UnknownSnapshot(),
	}
	for nome, snap := range casos {
		t.Run(nome, func(t *testing.T) {
			if hairpin := !snap.Capable().RoutedTransit; hairpin {
				t.Errorf("%s virou hairpin: o eixo das regras mudaria numa caixa que nunca foi detectada", nome)
			}
			// E a zona montada com esses fatos tem de renderizar por interface.
			z := nftables.NewZone([]string{"ppp0", "enp2s0"}, []string{"192.168.3.0/24"}, !snap.Capable().RoutedTransit)
			if z.Hairpin() {
				t.Error("a zona ficou em hairpin com plataforma desconhecida")
			}
		})
	}
}

// TestNaOCIDeUmaVNICOEixoViraCIDR é o outro lado: a máquina que este incremento
// existe para consertar tem de ser reconhecida como hairpin.
func TestNaOCIDeUmaVNICOEixoViraCIDR(t *testing.T) {
	fatos := platform.Facts{
		Kind: platform.KindOCI,
		OCI:  &platform.OCIFacts{Shape: "VM.Standard.E2.1.Micro", MaxVNICAttachments: 1},
	}
	snap := platform.Snapshot{
		Format:       platform.SnapshotFormat,
		Facts:        fatos,
		Capabilities: platform.DeriveCapabilities(fatos),
	}
	if snap.Capable().RoutedTransit {
		t.Fatal("uma VM de uma VNIC só não pode ser tratada como caixa de trânsito roteado")
	}
	z := nftables.NewZone([]string{"ens3"}, []string{"10.0.0.0/24"}, !snap.Capable().RoutedTransit)
	if !z.Hairpin() || !z.Discriminates() {
		t.Fatalf("a zona da VM de uma placa tinha de ser hairpin e discriminar: hairpin=%t discrimina=%t",
			z.Hairpin(), z.Discriminates())
	}
	if got := joinTokens(z.FromLocal()); got != "ip saddr { 10.0.0.0/24 }" {
		t.Errorf("o eixo não virou CIDR: %q", got)
	}
}

func joinTokens(toks []string) string {
	out := ""
	for i, t := range toks {
		if i > 0 {
			out += " "
		}
		out += t
	}
	return out
}

// bancoDeTeste abre um banco vazio, como o de uma instalação recém-feita.
func bancoDeTeste(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestAMaquinaNovaNaoHerdaARedeDeCasaDeQuemEscreveuOProduto trava um vazamento
// real, encontrado numa VM da OCI de verdade: as regras nasceram com
// `ip saddr { 10.0.0.0/24, 192.168.3.0/24 }`, e aquele /24 é a rede doméstica
// cravada em netsvc.DefaultConfig() — gateway 192.168.3.3 e tudo.
//
// Numa instalação nova não existe netsvc_config no banco, então ler o
// DefaultConfig punha a rede de um terceiro dentro do firewall do cliente,
// tratada como "dentro". Este é um produto de prateleira: quem instala tem de
// receber a própria topologia, não a de quem escreveu.
func TestAMaquinaNovaNaoHerdaARedeDeCasaDeQuemEscreveuOProduto(t *testing.T) {
	db := bancoDeTeste(t)
	fatos := platform.Facts{
		Kind: platform.KindOCI,
		OCI: &platform.OCIFacts{
			MaxVNICAttachments: 1,
			VNICs:              []platform.OCIVNIC{{SubnetCIDR: "10.0.0.0/24"}},
		},
	}
	snap := platform.Snapshot{Format: platform.SnapshotFormat, Facts: fatos, Capabilities: platform.DeriveCapabilities(fatos)}

	redes := redesLocais(db, snap)

	for _, r := range redes {
		if r == netsvc.DefaultConfig().SubnetCIDR {
			t.Fatalf("a rede do DefaultConfig (%s) vazou para as regras de uma máquina que nunca a configurou: %v", r, redes)
		}
	}
	if len(redes) != 1 || redes[0] != "10.0.0.0/24" {
		t.Errorf("a VM tinha de conhecer só a própria sub-rede, obtive %v", redes)
	}
}

// TestARedeConfiguradaPeloAdminEntraNoEixo é o outro lado: quando o admin
// configurou de fato a rede pela tela, ela conta — é a LAN do painel.
func TestARedeConfiguradaPeloAdminEntraNoEixo(t *testing.T) {
	db := bancoDeTeste(t)
	if err := db.SetSetting("netsvc_config", `{"subnet_cidr":"172.20.0.0/16"}`); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	fatos := platform.Facts{
		Kind: platform.KindOCI,
		OCI: &platform.OCIFacts{
			MaxVNICAttachments: 1,
			VNICs:              []platform.OCIVNIC{{SubnetCIDR: "10.0.0.0/24"}},
		},
	}
	snap := platform.Snapshot{Format: platform.SnapshotFormat, Facts: fatos, Capabilities: platform.DeriveCapabilities(fatos)}

	redes := redesLocais(db, snap)

	temConfigurada, temDaPlataforma := false, false
	for _, r := range redes {
		if r == "172.20.0.0/16" {
			temConfigurada = true
		}
		if r == "10.0.0.0/24" {
			temDaPlataforma = true
		}
	}
	if !temConfigurada || !temDaPlataforma {
		t.Errorf("as duas redes verdadeiras tinham de entrar, obtive %v", redes)
	}
}

// TestConfigIlegivelNaoApagaARedeDaPlataforma: JSON corrompido não pode virar
// silêncio — a mesma disciplina de ntpInputStateFrom e de hostflows.
func TestConfigIlegivelNaoApagaARedeDaPlataforma(t *testing.T) {
	db := bancoDeTeste(t)
	if err := db.SetSetting("netsvc_config", `{isto não é json`); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	fatos := platform.Facts{
		Kind: platform.KindOCI,
		OCI: &platform.OCIFacts{
			MaxVNICAttachments: 1,
			VNICs:              []platform.OCIVNIC{{SubnetCIDR: "10.0.0.0/24"}},
		},
	}
	snap := platform.Snapshot{Format: platform.SnapshotFormat, Facts: fatos, Capabilities: platform.DeriveCapabilities(fatos)}

	redes := redesLocais(db, snap)

	if len(redes) != 1 || redes[0] != "10.0.0.0/24" {
		t.Errorf("a rede da plataforma tinha de sobreviver a uma config ilegível, obtive %v", redes)
	}
}

// TestAListaAntiLockoutNaoNasceComARedeDeOutraPessoa é o mesmo vazamento do
// teste acima, no sítio onde ele é PIOR: AdminAccess.LANNetworks alimenta as
// regras que existem para o admin não se trancar para fora. Numa caixa nova a
// lista nascia com 192.168.3.0/24 — uma rede que aquela máquina não tem e que
// o dono dela nunca viu.
func TestAListaAntiLockoutNaoNasceComARedeDeOutraPessoa(t *testing.T) {
	db := bancoDeTeste(t)
	if got := redeConfigurada(db); got != "" {
		t.Errorf("sem netsvc_config gravado a resposta tem de ser vazia, obtive %q", got)
	}
	if got := redeConfigurada(db); got == netsvc.DefaultConfig().SubnetCIDR {
		t.Errorf("o DefaultConfig vazou: %q", got)
	}
}

// TestOnPremNaoRegridePorqueLaAConfiguracaoEstaGravada prende o motivo de este
// conserto ser seguro para a máquina que roda 24/7: lá o netsvc_config existe,
// então a leitura devolve exatamente o que devolvia antes.
func TestOnPremNaoRegridePorqueLaAConfiguracaoEstaGravada(t *testing.T) {
	db := bancoDeTeste(t)
	if err := db.SetSetting("netsvc_config", `{"subnet_cidr":"192.168.3.0/24","interface":"br10"}`); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if got := redeConfigurada(db); got != "192.168.3.0/24" {
		t.Errorf("a rede configurada da produção tem de sobreviver, obtive %q", got)
	}
}
