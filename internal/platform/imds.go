package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Caminhos do IMDS da OCI. A v2 exige o cabeçalho Authorization; a v1 não o
// exige e continua existindo, o que a torna o fallback natural para imagens
// antigas.
const (
	imdsInstancePathV2 = "/opc/v2/instance/"
	imdsInstancePathV1 = "/opc/v1/instance/"
	imdsVNICsPathV2    = "/opc/v2/vnics/"
	imdsVNICsPathV1    = "/opc/v1/vnics/"
	imdsCertPathV2     = "/opc/v2/identity/cert.pem"
	imdsCertPathV1     = "/opc/v1/identity/cert.pem"

	// imdsBearer é literalmente esta string. Não é um segredo e não é um
	// token: é o cabeçalho fixo que a v2 do IMDS da Oracle exige para provar
	// que a requisição foi feita de propósito, e não por um SSRF ingênuo.
	imdsBearer = "Bearer Oracle"

	// imdsMaxBody é o teto de leitura de uma resposta. O JSON da instância tem
	// alguns KB; o teto existe porque quem responde no 169.254.169.254 numa
	// rede on-prem pode ser qualquer coisa, inclusive algo que transmite sem
	// parar.
	imdsMaxBody = 512 << 10
)

// errNotOCI é a resposta honesta de "falei (ou tentei falar) com o
// 169.254.169.254 e ali não tem uma instância OCI". Não é falha do produto: é
// o resultado normal em toda máquina que não é da Oracle.
var errNotOCI = errors.New("o serviço de metadados não respondeu como uma instância OCI")

// imdsInstance é a resposta de /opc/vN/instance/, reduzida ao que muda alguma
// decisão. Campos que o JSON tem e não estão aqui são ignorados pelo
// encoding/json de graça — é isso que faz um campo novo do provedor não
// quebrar nada.
type imdsInstance struct {
	ID                  string `json:"id"`
	DisplayName         string `json:"displayName"`
	CanonicalRegionName string `json:"canonicalRegionName"`
	Region              string `json:"region"`
	AvailabilityDomain  string `json:"availabilityDomain"`
	CompartmentID       string `json:"compartmentId"`
	TenantID            string `json:"tenantId"`
	Shape               string `json:"shape"`

	ShapeConfig struct {
		MaxVnicAttachments        int     `json:"maxVnicAttachments"`
		MemoryInGBs               float64 `json:"memoryInGBs"`
		NetworkingBandwidthInGbps float64 `json:"networkingBandwidthInGbps"`
		OCPUs                     float64 `json:"ocpus"`
	} `json:"shapeConfig"`

	RegionInfo struct {
		RealmKey         string `json:"realmKey"`
		RegionKey        string `json:"regionKey"`
		RegionIdentifier string `json:"regionIdentifier"`
	} `json:"regionInfo"`

	// SystemTags é map de map de any, e não de string, porque só um dos
	// valores interessa e o tipo dos outros é do provedor, não nosso.
	SystemTags map[string]map[string]any `json:"systemTags"`
}

// imdsVNIC tem EXATAMENTE os seis campos que /opc/vN/vnics/ devolve. Medido:
// skipSourceDestCheck NÃO existe ali. Não adicione o campo esperando que um
// dia apareça — o valor viria zerado e alguém decidiria com ele.
type imdsVNIC struct {
	VNICID          string `json:"vnicId"`
	MacAddr         string `json:"macAddr"`
	PrivateIP       string `json:"privateIp"`
	SubnetCIDR      string `json:"subnetCidrBlock"`
	VirtualRouterIP string `json:"virtualRouterIp"`
	VLANTag         int    `json:"vlanTag"`
}

// queryIMDS pergunta ao serviço de metadados quem é esta máquina.
//
// "Não consegui falar com o IMDS" é uma RESPOSTA legítima e quer dizer
// on-prem: o erro devolvido aqui nunca é falha do produto, e quem chama o
// trata como veredito e não como problema.
func queryIMDS(ctx context.Context, env Env) (*OCIFacts, error) {
	inst, version, err := fetchInstance(ctx, env)
	if err != nil {
		return nil, err
	}

	facts := &OCIFacts{
		InstanceOCID:       inst.ID,
		DisplayName:        inst.DisplayName,
		Region:             inst.CanonicalRegionName,
		RegionKey:          inst.RegionInfo.RegionKey,
		RealmKey:           inst.RegionInfo.RealmKey,
		AvailabilityDomain: inst.AvailabilityDomain,
		CompartmentOCID:    inst.CompartmentID,
		TenancyOCID:        inst.TenantID,
		Shape:              inst.Shape,
		OCPUs:              inst.ShapeConfig.OCPUs,
		MemoryGB:           inst.ShapeConfig.MemoryInGBs,
		BandwidthGbps:      inst.ShapeConfig.NetworkingBandwidthInGbps,
		MaxVNICAttachments: inst.ShapeConfig.MaxVnicAttachments,
		AlwaysFree:         alwaysFree(inst.SystemTags),
		IMDSVersion:        version,
	}

	// O limite de VNICs é O campo que decide multi-WAN. Ausente é
	// DESCONHECIDO, e desconhecido mantém tudo ligado (ver
	// DeriveCapabilities) — mas merece aviso, porque é a única forma de
	// alguém descobrir que o provedor mudou o nome do campo.
	if facts.MaxVNICAttachments == 0 {
		slog.Warn("o IMDS não informou o limite de VNICs; multi-WAN segue habilitado",
			"shape", facts.Shape, "imds", version)
	}

	// Daqui para baixo nada derruba o veredito: a máquina JÁ é uma OCI.
	facts.VNICs = fetchVNICs(ctx, env, version)
	facts.InstancePrincipal = hasInstancePrincipal(ctx, env, version)

	return facts, nil
}

// fetchInstance busca o documento da instância, com o fallback da v1.
func fetchInstance(ctx context.Context, env Env) (imdsInstance, int, error) {
	status, body, err := imdsGet(ctx, env, imdsInstancePathV2, true)
	switch {
	case err != nil:
		// Dial recusado, timeout, host inalcançável: o caso NORMAL de uma
		// máquina on-prem cujo sinal local foi falso positivo. Debug, nunca
		// Warn — senão vira uma linha de journal a cada boot para sempre.
		slog.Debug("o serviço de metadados não respondeu", "path", imdsInstancePathV2, "err", err)
		return imdsInstance{}, 0, errNotOCI
	case status == http.StatusOK:
		inst, ok := decodeInstance(body)
		if !ok {
			return imdsInstance{}, 0, errNotOCI
		}
		return inst, 2, nil
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusNotFound:
		// Imagem antiga, ou instância criada antes da v2: a v1 responde o
		// mesmo documento e não pede cabeçalho.
		status1, body1, err1 := imdsGet(ctx, env, imdsInstancePathV1, false)
		if err1 != nil {
			slog.Debug("o serviço de metadados não respondeu na v1", "err", err1)
			return imdsInstance{}, 0, errNotOCI
		}
		if status1 != http.StatusOK {
			slog.Debug("o serviço de metadados recusou as duas versões", "v2", status, "v1", status1)
			return imdsInstance{}, 0, errNotOCI
		}
		inst, ok := decodeInstance(body1)
		if !ok {
			return imdsInstance{}, 0, errNotOCI
		}
		return inst, 1, nil
	default:
		// 200 e os códigos acima são o esperado; qualquer outra coisa é
		// anômala e merece ficar registrada.
		slog.Warn("resposta inesperada do serviço de metadados", "path", imdsInstancePathV2, "status", status)
		return imdsInstance{}, 0, errNotOCI
	}
}

// decodeInstance parseia e aplica o GATE DE SANIDADE.
//
// O gate é a defesa contra o 169.254.0.0/16 roteável: numa rede on-prem aquele
// endereço pode ser um appliance qualquer, ou um proxy devolvendo uma página
// de erro com status 200. Um corpo que não tem um OCID de instância e um nome
// canônico de região NÃO é uma instância OCI, por mais que tenha respondido.
//
// Um erro de TIPO (o provedor trocar um número por string, por exemplo) não
// invalida a resposta se o gate ainda passar: encoding/json preenche o que
// conseguiu, e recusar a instância inteira por causa de um campo seria
// declarar on-prem uma máquina que é comprovadamente OCI.
func decodeInstance(body []byte) (imdsInstance, bool) {
	var inst imdsInstance
	err := json.Unmarshal(body, &inst)
	if err != nil {
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) || !instanceLooksOCI(inst) {
			slog.Warn("o serviço de metadados respondeu com um corpo ilegível", "err", err)
			return imdsInstance{}, false
		}
		slog.Warn("o IMDS mandou um campo com tipo inesperado; seguindo com o resto",
			"campo", typeErr.Field, "err", err)
		return inst, true
	}
	if !instanceLooksOCI(inst) {
		slog.Warn("o IMDS respondeu, mas o corpo não é de uma instância OCI",
			"id", inst.ID, "region", inst.CanonicalRegionName)
		return imdsInstance{}, false
	}
	return inst, true
}

// instanceLooksOCI é o gate. Dois campos, os dois estáveis desde que o IMDS
// existe, e nenhum outro é obrigatório em lugar nenhum deste pacote.
func instanceLooksOCI(inst imdsInstance) bool {
	return strings.HasPrefix(inst.ID, "ocid1.instance.oc") && inst.CanonicalRegionName != ""
}

// fetchVNICs busca a lista de VNICs. Falha aqui NÃO derruba o veredito: a
// máquina continua sendo OCI, a lista fica vazia, e quem depender dela trata
// vazio como desconhecido.
func fetchVNICs(ctx context.Context, env Env, version int) []OCIVNIC {
	path, bearer := imdsVNICsPathV2, true
	if version == 1 {
		path, bearer = imdsVNICsPathV1, false
	}
	status, body, err := imdsGet(ctx, env, path, bearer)
	if err != nil || status != http.StatusOK {
		slog.Warn("não foi possível listar as VNICs no serviço de metadados",
			"path", path, "status", status, "err", err)
		return nil
	}
	var raw []imdsVNIC
	if err := json.Unmarshal(body, &raw); err != nil {
		slog.Warn("a lista de VNICs do serviço de metadados é ilegível", "err", err)
		return nil
	}
	out := make([]OCIVNIC, 0, len(raw))
	for _, v := range raw {
		out = append(out, OCIVNIC{
			VNICOCID:        v.VNICID,
			MAC:             normalizeVNICMAC(v.MacAddr),
			PrivateIP:       v.PrivateIP,
			SubnetCIDR:      v.SubnetCIDR,
			VirtualRouterIP: v.VirtualRouterIP,
			VLANTag:         v.VLANTag,
		})
	}
	return out
}

// hasInstancePrincipal pergunta se existe credencial de instância. Só o
// STATUS interessa: o certificado não é lido nem guardado, e o SDK da Oracle
// não entra neste binário por causa disto.
//
// A versão vem de quem respondeu o documento da instância, como em fetchVNICs:
// perguntar na v2 a uma imagem que só tem a v1 devolveria 404 e registraria
// "não tem credencial" numa máquina que tem.
func hasInstancePrincipal(ctx context.Context, env Env, version int) bool {
	path, bearer := imdsCertPathV2, true
	if version == 1 {
		path, bearer = imdsCertPathV1, false
	}
	status, _, err := imdsGet(ctx, env, path, bearer)
	if err != nil {
		// Sem Warn: não ter Instance Principal é uma configuração legítima.
		slog.Debug("não foi possível consultar a credencial de instância", "err", err)
		return false
	}
	return status == http.StatusOK
}

// imdsGet faz uma requisição ao serviço de metadados e devolve status e corpo.
// O corpo é lido com teto e a resposta é sempre drenada e fechada, para a
// conexão poder ser reusada pelas requisições seguintes.
func imdsGet(ctx context.Context, env Env, path string, bearer bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.IMDSBase+path, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("montar a requisição ao serviço de metadados: %w", err)
	}
	if bearer {
		req.Header.Set("Authorization", imdsBearer)
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, imdsMaxBody))
		resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, imdsMaxBody))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("ler a resposta do serviço de metadados: %w", err)
	}
	return resp.StatusCode, body, nil
}

// alwaysFree lê systemTags["orcl-cloud"]["free-tier-retained"].
//
// Aceita a string "true" (o que a instância real manda) e o booleano true, por
// o tipo do valor ser do provedor. Qualquer outra coisa é false, e a diferença
// não decide nada — é informação de tela.
func alwaysFree(tags map[string]map[string]any) bool {
	v, ok := tags["orcl-cloud"]["free-tier-retained"]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	case bool:
		return t
	default:
		return false
	}
}

// normalizeVNICMAC põe o MAC do IMDS na grafia que net.Interface devolve —
// minúsculo, com dois-pontos —, que é a única forma de o casamento da VNIC com
// a interface de kernel acontecer. O IMDS manda MAIÚSCULO
// ("02:00:17:0A:19:30") e o kernel manda minúsculo.
//
// validate.NormalizeMAC sozinha NÃO resolve isto, e o doc dela diz por quê:
// ela delega a net.ParseMAC, que aceita "aa-bb-cc-dd-ee-ff" e
// "aabb.ccdd.eeff", e só passa para minúsculas — a PONTUAÇÃO original
// sobrevive. Um dia em que o provedor mandasse a forma com hífen, o MAC
// passaria na validação, não casaria com interface nenhuma e o campo
// Interface ficaria vazio sem um único erro. É o defeito que fez
// internal/validate nascer (issue #161); reconstruir a string a partir do
// endereço parseado é o que o fecha aqui.
//
// Um MAC que não parseia volta como veio, para a tela poder mostrar o que o
// provedor disse em vez de um campo vazio.
func normalizeVNICMAC(mac string) string {
	mac = strings.TrimSpace(mac)
	if validate.NormalizeMAC(mac) == "" {
		return mac
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return mac
	}
	return hw.String()
}
