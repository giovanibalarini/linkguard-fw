// Package platform descobre EM QUE MÁQUINA o LinkGuard está rodando e o que
// aquela máquina deixa o produto fazer.
//
// POR QUE ISTO É A PRIMEIRA PEÇA. O produto é de prateleira: quem cria a
// máquina e instala o .deb tem que ver rede funcionando sem configurar nada.
// "Funcionar" quer dizer coisas diferentes em cada lugar — numa OCI de
// maxVnicAttachments=1 não existe multi-WAN para configurar, e um painel que
// oferece failover de link ali está mentindo para o dono da máquina. Todo o
// resto (perfil de execução, uplink automático, o que a tela mostra ou
// esconde) deriva daqui.
//
// O QUE ESTE PACOTE NÃO FAZ. Não executa comando nenhum: ele roda no boot
// ANTES de internal/bootstrapdeps garantir a base (ver BasePackages), num
// instante em que `ip`, `nft` e `ping` podem simplesmente não existir na
// máquina. Por isso nada de firewall.Executor aqui — só os.ReadFile,
// os.Stat, net.Interfaces e net/http, todos atrás de Env. Quem "consertar"
// essa inconsistência trocando uma sonda por `ip -j link` ou por
// `systemctl is-active` quebra o boot de uma instalação pelada, que é
// exatamente o caso que o produto precisa acertar de primeira.
//
// O DMI NÃO É LIDO, E ISSO FOI MEDIDO. Numa instância OCI real o
// hostnamectl diz "Hardware Vendor: QEMU", "Standard PC _i440FX + PIIX,
// 1996_", "Virtualization: kvm" — QEMU genérico. Detecção apoiada em
// DMI/SMBIOS dá falso NEGATIVO justamente na nuvem que precisa ser
// reconhecida, e falso POSITIVO em qualquer KVM on-prem. Ver signals.go.
//
// NÃO TRAZ O SDK DA ORACLE. O que interessa do IMDS são doze campos de JSON;
// um SDK inteiro por causa disso é superfície de cadeia de suprimentos num
// appliance de segurança em troca de nada. Instance Principal entra aqui
// como um booleano e nada mais.
//
// Os identificadores são em inglês (como storage, qos, nftables e netif)
// porque os consumidores deste pacote são aqueles; os comentários são em
// português, como todo código novo do repositório.
package platform

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Kind é a plataforma. String tipada (e não iota) pelo mesmo motivo de
// netif.Kind: o valor viaja para o JSON do painel e para a tabela settings, e
// um inteiro gravado hoje vira lixo ilegível no dia em que alguém inserir um
// valor no meio da lista.
type Kind string

const (
	// KindUnknown é a máquina sobre a qual nada se sabe — inclusive a que
	// nunca passou por Detect. NUNCA é restritiva: ver Permissive.
	KindUnknown Kind = "unknown"
	// KindOnPrem é bare metal ou VM genérica: a máquina de produção de hoje.
	KindOnPrem Kind = "onprem"
	// KindOCI é a Oracle Cloud Infrastructure.
	KindOCI Kind = "oci"
	// Os próximos provedores entram aqui. Nada além de OCI está implementado.
)

// IsCloud diz se a plataforma é de um provedor de nuvem. É o predicado que as
// capacidades de fabric usam (DHCP, DDNS, hora, SMART), para que o dia em que
// entrar um segundo provedor não vire uma lista de comparações espalhada.
func (k Kind) IsCloud() bool {
	return k == KindOCI
}

// Confidence diz de onde veio o veredito, porque "on-prem porque não achei
// sinal nenhum" e "on-prem porque o IMDS negou" não são a mesma afirmação —
// e quem lê um diagnóstico precisa poder separar as duas.
type Confidence string

const (
	// ConfidenceLocal: só os sinais locais falaram.
	ConfidenceLocal Confidence = "local"
	// ConfidenceAuthoritative: o IMDS do provedor confirmou.
	ConfidenceAuthoritative Confidence = "authoritative"
)

// Origem de uma chamada a Detect. Não é gravada: descreve ESTA chamada.
const (
	SourceCache = "cache"
	SourceProbe = "probe"
)

// De onde saiu NetFacts.PathMTU.
const (
	// PathMTUSourcePlatform: é uma propriedade conhecida da fabric, não desta
	// instância. Na OCI o caminho externo é 1500 mesmo com a interface em 9000.
	PathMTUSourcePlatform = "platform"
	// PathMTUSourceMeasured: medido de verdade. Nada neste incremento mede;
	// a constante existe para o incremento que medir não precisar mudar o tipo.
	PathMTUSourceMeasured = "measured"
)

// Facts é o que foi OBSERVADO. Nada aqui é decisão; decisão é Capabilities.
type Facts struct {
	Kind       Kind       `json:"kind"`
	Confidence Confidence `json:"confidence"`
	DetectedAt int64      `json:"detected_at"` // unix seconds

	// Signals são os sinais locais que acenderam, por nome. Vai para o log e
	// para a tela de diagnóstico: "achei que era OCI por causa de X" é a única
	// forma de alguém contestar um falso positivo sem ler código.
	Signals []string `json:"signals,omitempty"`

	// Fingerprint amarra este instantâneo A ESTA máquina — ver o cache em
	// detect.go. Existe porque storage.ExportSettings copia a tabela settings
	// inteira para o backup, sem filtro: um backup de uma OCI restaurado numa
	// caixa on-prem traria este instantâneo junto, dizendo "OCI".
	Fingerprint string `json:"fingerprint"`

	Net NetFacts  `json:"net"`
	OCI *OCIFacts `json:"oci,omitempty"` // nil quando Kind != KindOCI
}

// NetFacts vale em qualquer plataforma.
type NetFacts struct {
	PrimaryInterface string `json:"primary_interface"`
	PrimaryMAC       string `json:"primary_mac"`

	// LinkMTU é a MTU da interface, lida de net.Interface.MTU. 0 = não deu
	// para saber qual é a interface primária.
	LinkMTU int `json:"link_mtu"`

	// PathMTU é a MTU do CAMINHO até a Internet, que na OCI NÃO é a da
	// interface: medido na VM real, ens3 tem MTU 9000 e o caminho externo tem
	// 1500 (ping -M do). Isto é fato, e não capacidade, porque o consumidor
	// futuro é um número — hoje o MSS clamp usa `rt mtu`
	// (internal/nftables/mssclamp.go) e erraria feio ali.
	//
	// 0 = desconhecido, e desconhecido tem que continuar significando "o
	// produto segue fazendo o que faz hoje". Fora da nuvem é SEMPRE 0 neste
	// incremento: copiar LinkMTU para cá seria pior do que não saber, porque
	// a interface primária é uma ELEIÇÃO (rota default, ou a primeira que não
	// é de sistema) e o palpite de uma NIC de 9000 viraria um clamp alto
	// demais — o modo de falha que trava conexão em vez de só degradá-la.
	// Quem quiser a MTU da interface tem LinkMTU ao lado, dito pelo nome
	// certo.
	PathMTU int `json:"path_mtu"`

	// PathMTUSource diz de onde saiu o número. Ver as constantes.
	PathMTUSource string `json:"path_mtu_source"`
}

// OCIFacts é o subconjunto do IMDS que muda alguma decisão. Campos que não
// mudam nada (image, timeCreated, definedTags, metadata.user_data) ficam de
// fora de propósito: user_data é base64 de um script de provisionamento e não
// tem por que morar no banco de um firewall.
type OCIFacts struct {
	InstanceOCID       string  `json:"instance_ocid"`
	DisplayName        string  `json:"display_name"`
	Region             string  `json:"region"`     // canonicalRegionName: "sa-saopaulo-1"
	RegionKey          string  `json:"region_key"` // regionInfo.regionKey: "GRU"
	RealmKey           string  `json:"realm_key"`  // regionInfo.realmKey: "oc1"
	AvailabilityDomain string  `json:"availability_domain"`
	CompartmentOCID    string  `json:"compartment_ocid"`
	TenancyOCID        string  `json:"tenancy_ocid"`
	Shape              string  `json:"shape"` // "VM.Standard.E2.1.Micro"
	OCPUs              float64 `json:"ocpus"`
	MemoryGB           float64 `json:"memory_gb"`
	BandwidthGbps      float64 `json:"bandwidth_gbps"`

	// MaxVNICAttachments é O campo que decide multi-WAN. 0 significa
	// DESCONHECIDO (o IMDS não mandou), e nunca "uma só" — ver
	// DeriveCapabilities.
	MaxVNICAttachments int `json:"max_vnic_attachments"`

	// AlwaysFree sai de systemTags["orcl-cloud"]["free-tier-retained"]=="true".
	AlwaysFree bool `json:"always_free"`

	// InstancePrincipal: /opc/v2/identity/cert.pem respondeu 200, então o SDK
	// da Oracle autenticaria sem chave nenhuma. Só se REGISTRA que a
	// capacidade existe; o certificado não é lido nem guardado.
	InstancePrincipal bool `json:"instance_principal"`

	IMDSVersion int       `json:"imds_version"` // 2, ou 1 quando caiu no fallback
	VNICs       []OCIVNIC `json:"vnics,omitempty"`
}

// OCIVNIC tem EXATAMENTE os seis campos que /opc/v2/vnics/ devolve, mais o
// nome de kernel casado pelo MAC. skipSourceDestCheck NÃO existe no IMDS —
// medido na instância real; não procure por ele aqui.
type OCIVNIC struct {
	VNICOCID        string `json:"vnic_ocid"`
	MAC             string `json:"mac"`
	PrivateIP       string `json:"private_ip"`
	SubnetCIDR      string `json:"subnet_cidr"`
	VirtualRouterIP string `json:"virtual_router_ip"`
	VLANTag         int    `json:"vlan_tag"`
	Interface       string `json:"interface,omitempty"` // "" = o MAC não casou com nenhuma interface
}

// Capabilities é o que a máquina DEIXA o produto fazer. Booleano nomeado e não
// lista de strings: vira JSON direto para o painel, o compilador pega o campo
// renomeado, e um teste afirma sobre um campo em vez de procurar uma string
// numa slice.
//
// Todo campo é afirmativo ("o produto PODE") e, salvo InstancePrincipal, o
// valor seguro é true: a máquina desconhecida recebe todos true, que é
// exatamente o comportamento do produto em produção hoje. Ver Permissive.
type Capabilities struct {
	// ─── Uplink ──────────────────────────────────────────────────────────
	MultiWAN             bool `json:"multi_wan"`
	LinkFailover         bool `json:"link_failover"`
	LoadBalancing        bool `json:"load_balancing"`
	PerLinkPolicyRouting bool `json:"per_link_policy_routing"`

	// RoutedTransit é false quando entra e sai pela MESMA interface
	// (hairpin). Com uma VNIC só não existe "de uma porta para outra".
	RoutedTransit bool `json:"routed_transit"`

	// ─── Serviços de rede ────────────────────────────────────────────────
	DHCPServer  bool `json:"dhcp_server"`
	DDNS        bool `json:"ddns"`
	OwnTimeSync bool `json:"own_time_sync"`

	// ─── Hardware ────────────────────────────────────────────────────────
	SMART bool `json:"smart"`

	// ─── Nuvem ───────────────────────────────────────────────────────────
	// InstancePrincipal é a ÚNICA capacidade que nasce false e é ligada por um
	// fato, e por isso é também a única que Permissive deixa em false: ela não
	// afirma "o produto pode", e sim "existe uma credencial de instância nesta
	// máquina". Afirmar isso sem fato não é ser permissivo, é mentir — e quem
	// acreditasse tentaria autenticar com uma credencial que não existe.
	InstancePrincipal bool `json:"instance_principal"`
}

// Permissive é o conjunto com tudo ligado: o comportamento do produto hoje, em
// produção, 24/7. É o que KindUnknown recebe, o que uma detecção que falhou
// recebe, e o que o zero-value de Snapshot precisa acabar tendo (ver
// Snapshot.Capable).
func Permissive() Capabilities {
	return Capabilities{
		MultiWAN:             true,
		LinkFailover:         true,
		LoadBalancing:        true,
		PerLinkPolicyRouting: true,
		RoutedTransit:        true,
		DHCPServer:           true,
		DDNS:                 true,
		OwnTimeSync:          true,
		SMART:                true,
		InstancePrincipal:    false, // ver o campo
	}
}

// DeriveCapabilities traduz fatos em capacidades. Função pura: nenhuma leitura
// de disco, de rede ou de relógio — é o que a torna uma tabela de teste em vez
// de um cenário.
//
// A REGRA QUE MANDA: só desliga o que o fato PROVA impossível. Campo ausente
// ou zero é desconhecimento, e desconhecimento fica permissivo. Uma OCI que um
// dia não mandar maxVnicAttachments tem que continuar com o painel de
// multi-WAN de pé; o inverso — desligar failover numa máquina de duas WANs por
// causa de um campo que sumiu do JSON — é a rede do dono caindo.
func DeriveCapabilities(f Facts) Capabilities {
	c := Permissive()

	// Fabric de nuvem: estas quatro não dependem de shape nenhum.
	if f.Kind.IsCloud() {
		// A fabric é a autoridade de DHCP da subnet (o lease traz
		// SERVER_ADDRESS=169.254.169.254); subir kea aqui é rogue e não
		// funciona.
		c.DHCPServer = false
		// Disco paravirtualizado: não há o que o SMART leia.
		c.SMART = false
		// O IP público não existe em interface nenhuma (NAT 1:1 na fabric),
		// então DDNS como fonte de endpoint perde a função.
		c.DDNS = false
		// NTP entregue pela fabric no link-local; um serviço de hora próprio
		// disputaria com ela.
		c.OwnTimeSync = false
	}

	if f.OCI != nil {
		// A comparação é com 1 EXATAMENTE. 0 é "o IMDS não informou", e
		// desconhecimento nunca desliga capacidade; negativo é JSON absurdo e
		// recebe o mesmo tratamento.
		if f.OCI.MaxVNICAttachments == 1 {
			c.MultiWAN = false
			// As quatro abaixo são derivadas: sem uma segunda WAN não há para
			// onde cair, o que balancear, o que rotear por link, nem "de uma
			// porta para outra" — todo trânsito é hairpin.
			c.LinkFailover = false
			c.LoadBalancing = false
			c.PerLinkPolicyRouting = false
			c.RoutedTransit = false
		}
		c.InstancePrincipal = f.OCI.InstancePrincipal
	}

	return c
}

// SnapshotFormat é a versão do FORMATO gravado. Um instantâneo de formato
// diferente é ignorado e redetectado, em vez de interpretado errado — é também
// o que faz uma mudança nas regras de DeriveCapabilities alcançar as máquinas
// que já têm um instantâneo gravado.
const SnapshotFormat = 1

// Snapshot é o resultado inteiro de uma detecção: o que se viu e o que se
// concluiu.
type Snapshot struct {
	Format       int          `json:"format"`
	Facts        Facts        `json:"facts"`
	Capabilities Capabilities `json:"capabilities"`

	// Source não é gravado: diz se ESTA chamada veio do cache ou da sondagem.
	Source string `json:"-"` // SourceCache | SourceProbe

	// NegativeProbes conta sondagens seguidas em que os sinais locais
	// acenderam e o IMDS negou. Ver a regra do cache em detect.go.
	NegativeProbes int `json:"negative_probes,omitempty"`
}

// Capable devolve as capacidades SEGURAS deste instantâneo.
//
// Existe porque o zero-value de Snapshot (Format 0, Kind "") tem Capabilities
// com todos os booleanos em false — o conjunto mais RESTRITIVO possível, que é
// o oposto do que "não sei" pode significar neste produto. Um `var s
// platform.Snapshot` esquecido num caminho de teste ou de boot esconderia o
// painel de multi-WAN da máquina de produção sem que nada falhasse.
//
// Quem for PERGUNTAR capacidade chama isto; o campo Capabilities é para o JSON
// do painel, que sempre vem de um instantâneo completo.
func (s Snapshot) Capable() Capabilities {
	if s.Format != SnapshotFormat || s.Facts.Kind == "" || s.Facts.Kind == KindUnknown {
		return Permissive()
	}
	return s.Capabilities
}

// UnknownSnapshot é o instantâneo de quem não detectou nada: plataforma
// desconhecida e todas as capacidades ligadas, ou seja, o produto exatamente
// como ele se comporta hoje.
//
// Confidence fica vazia de propósito: nem os sinais locais falaram.
func UnknownSnapshot() Snapshot {
	return Snapshot{
		Format:       SnapshotFormat,
		Facts:        Facts{Kind: KindUnknown},
		Capabilities: Permissive(),
	}
}

// SnapshotSettingKey é a chave na tabela "settings" (internal/storage).
// Ausente = nunca detectado.
const SnapshotSettingKey = "platform_snapshot"

// SettingsStore é a fatia de storage.DB usada aqui. Interface local pelo mesmo
// motivo de hostflows.Banco: testar de mesa, sem SQLite, e não arrastar
// internal/storage para dentro de um pacote que precisa ser folha.
type SettingsStore interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
}

// Load lê o instantâneo gravado SEM detectar nada. ok=false quando nunca houve
// detecção — e quem chamar TEM que tratar isso como "não sei", nunca como "é
// on-prem".
//
// Erro de leitura e JSON corrompido viajam como erro, e não viram
// (Snapshot{}, false) silencioso: é a mesma regra de ntpInputStateFrom e de
// hostflows.Config — um SELECT que falhou não é uma resposta sobre a máquina.
func Load(store SettingsStore) (Snapshot, bool, error) {
	if store == nil {
		return UnknownSnapshot(), false, nil
	}
	raw, err := store.GetSetting(SnapshotSettingKey)
	if err != nil {
		return UnknownSnapshot(), false, fmt.Errorf("ler o instantâneo de plataforma: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return UnknownSnapshot(), false, nil
	}
	var snap Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return UnknownSnapshot(), false, fmt.Errorf("instantâneo de plataforma ilegível: %w", err)
	}
	snap.Source = SourceCache
	return snap, true, nil
}
