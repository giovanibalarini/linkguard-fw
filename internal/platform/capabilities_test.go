package platform

import "testing"

// Este arquivo é o guarda da produção. A regra que ele existe para proteger:
// DeriveCapabilities só desliga o que um fato PROVA impossível — sem fato,
// tudo ligado.

func TestMaquinaDesconhecidaMantemTodasAsCapacidades(t *testing.T) {
	// O teste mais importante da tabela: uma máquina sobre a qual nada se sabe
	// se comporta EXATAMENTE como o produto se comporta hoje, em produção,
	// 24/7. Se este teste ficar vermelho, alguém tornou a detecção restritiva
	// por padrão — e a rede do dono vai cair no próximo upgrade.
	if got := DeriveCapabilities(Facts{}); got != Permissive() {
		t.Errorf("capacidades de máquina desconhecida = %+v, esperado %+v", got, Permissive())
	}
}

func TestOnPremMantemTodasAsCapacidades(t *testing.T) {
	f := Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal}
	if got := DeriveCapabilities(f); got != Permissive() {
		t.Errorf("capacidades on-prem = %+v, esperado %+v", got, Permissive())
	}
}

func TestMaxVnicAttachmentsUmDesligaMultiWANEDerivadas(t *testing.T) {
	// O shape medido na instância real: VM.Standard.E2.1.Micro, uma VNIC só.
	f := Facts{
		Kind:       KindOCI,
		Confidence: ConfidenceAuthoritative,
		OCI:        &OCIFacts{Shape: "VM.Standard.E2.1.Micro", MaxVNICAttachments: 1},
	}
	c := DeriveCapabilities(f)

	desligadas := map[string]bool{
		"MultiWAN":             c.MultiWAN,
		"LinkFailover":         c.LinkFailover,
		"LoadBalancing":        c.LoadBalancing,
		"PerLinkPolicyRouting": c.PerLinkPolicyRouting,
		"RoutedTransit":        c.RoutedTransit,
	}
	for nome, ligada := range desligadas {
		if ligada {
			t.Errorf("%s continuou ligada com maxVnicAttachments=1 — o painel ofereceria algo que a máquina não tem", nome)
		}
	}
}

func TestDuasVNICsMantemMultiWAN(t *testing.T) {
	f := Facts{Kind: KindOCI, OCI: &OCIFacts{Shape: "VM.Standard.E4.Flex", MaxVNICAttachments: 2}}
	c := DeriveCapabilities(f)
	if !c.MultiWAN || !c.LinkFailover || !c.LoadBalancing || !c.PerLinkPolicyRouting || !c.RoutedTransit {
		t.Errorf("um shape de duas VNICs perdeu multi-WAN: %+v", c)
	}
}

func TestLimiteDeVNICDesconhecidoMantemMultiWAN(t *testing.T) {
	// Ausente é DESCONHECIMENTO, nunca "uma só". Desligar failover numa
	// máquina de duas WANs por causa de um campo que sumiu do JSON é a rede do
	// dono caindo; deixar ligado numa VNIC só custa um painel que oferece algo
	// que não dá para configurar.
	for _, limite := range []int{0, -1} {
		f := Facts{Kind: KindOCI, OCI: &OCIFacts{MaxVNICAttachments: limite}}
		if c := DeriveCapabilities(f); !c.MultiWAN || !c.LinkFailover || !c.LoadBalancing {
			t.Errorf("maxVnicAttachments=%d desligou multi-WAN: %+v", limite, c)
		}
	}
}

func TestPlataformaNuvemDesligaDHCPSmartDDNSETimeSync(t *testing.T) {
	f := Facts{Kind: KindOCI, OCI: &OCIFacts{MaxVNICAttachments: 1}}
	c := DeriveCapabilities(f)

	// Cada uma tem um fato por trás: a fabric é a autoridade de DHCP da
	// subnet; o disco é paravirtualizado; o IP público não existe em
	// interface nenhuma (NAT 1:1); NTP e DNS vêm da fabric no link-local.
	if c.DHCPServer {
		t.Error("DHCPServer continuou ligado na nuvem — subir kea ali é rogue e não funciona")
	}
	if c.SMART {
		t.Error("SMART continuou ligado sobre disco paravirtualizado")
	}
	if c.DDNS {
		t.Error("DDNS continuou ligado onde o IP público não existe em interface nenhuma")
	}
	if c.OwnTimeSync {
		t.Error("OwnTimeSync continuou ligado onde a fabric entrega a hora")
	}
}

func TestNuvemSemFatosDeShapeSoDesligaOQueEDaFabric(t *testing.T) {
	// Uma OCI cujo IMDS respondeu o gate e mais nada: as capacidades de
	// fabric caem (são propriedade da plataforma), as de uplink não (dependem
	// de um fato de shape que não veio).
	f := Facts{Kind: KindOCI, OCI: &OCIFacts{}}
	c := DeriveCapabilities(f)
	if !c.MultiWAN || !c.RoutedTransit {
		t.Errorf("as capacidades de uplink caíram sem fato de shape: %+v", c)
	}
	if c.DHCPServer || c.SMART {
		t.Errorf("as capacidades de fabric não caíram na nuvem: %+v", c)
	}
}

func TestInstancePrincipalNasceDesligadaEEhLigadaPorFato(t *testing.T) {
	// É a única capacidade que não é "o produto pode", e sim "existe uma
	// credencial nesta máquina". Afirmar isso sem fato não é ser permissivo,
	// é mentir.
	if Permissive().InstancePrincipal {
		t.Error("Permissive afirmou que existe credencial de instância numa máquina qualquer")
	}
	if DeriveCapabilities(Facts{Kind: KindOnPrem}).InstancePrincipal {
		t.Error("uma caixa on-prem apareceu com credencial de instância")
	}
	f := Facts{Kind: KindOCI, OCI: &OCIFacts{InstancePrincipal: true}}
	if !DeriveCapabilities(f).InstancePrincipal {
		t.Error("cert.pem respondeu 200 e a capacidade não subiu")
	}
}

func TestZeroValueDeSnapshotEhPermissivo(t *testing.T) {
	// O campo Capabilities de um Snapshot zerado tem todos os booleanos em
	// false — o conjunto MAIS restritivo possível. Capable é o que impede um
	// `var s platform.Snapshot` esquecido de esconder o painel de multi-WAN
	// da máquina de produção.
	var zero Snapshot
	if got := zero.Capable(); got != Permissive() {
		t.Errorf("Snapshot{}.Capable() = %+v, esperado %+v", got, Permissive())
	}
	if got := UnknownSnapshot().Capable(); got != Permissive() {
		t.Errorf("UnknownSnapshot().Capable() = %+v, esperado %+v", got, Permissive())
	}
}

func TestCapableDevolveOQueFoiDetectadoQuandoOInstantaneoEstaCompleto(t *testing.T) {
	f := Facts{Kind: KindOCI, OCI: &OCIFacts{MaxVNICAttachments: 1}}
	s := Snapshot{Format: SnapshotFormat, Facts: f, Capabilities: DeriveCapabilities(f)}
	if s.Capable().MultiWAN {
		t.Error("Capable devolveu permissivo sobre um instantâneo completo de OCI de uma VNIC")
	}
}

func TestFormatoAntigoNoInstantaneoNaoRestringe(t *testing.T) {
	// Um instantâneo de formato desconhecido pode ter capacidades com outro
	// significado. Interpretá-las é pior do que ignorá-las.
	s := Snapshot{Format: SnapshotFormat + 99, Facts: Facts{Kind: KindOCI}, Capabilities: Capabilities{}}
	if got := s.Capable(); got != Permissive() {
		t.Errorf("um formato desconhecido virou restrição: %+v", got)
	}
}
