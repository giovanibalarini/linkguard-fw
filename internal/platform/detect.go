package platform

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

const (
	// DetectBudget é o teto de TUDO. Na máquina on-prem nada disto é gasto:
	// sem sinal local aceso a camada 2 não roda, nenhum socket é aberto e
	// Detect volta em microssegundos. É a garantia que a produção de hoje
	// paga por esta feature, e tem um teste só dela
	// (TestSemSinalLocalNenhumSocketEhAberto).
	DetectBudget = 3 * time.Second

	// maxNegativeProbes é quantas sondagens negativas seguidas fazem o cache
	// passar a valer mesmo discordando dos sinais.
	//
	// O caso é concreto: uma imagem Ubuntu-da-OCI copiada para uma VM local
	// mantém o kernel "-oracle" para sempre, então o sinal acende em todo
	// boot e o IMDS nunca vai existir. Sem este contador aquela máquina
	// pagaria a sondagem eternamente. Três é pequeno o bastante para uma OCI
	// de verdade cujo IMDS demorou a subir ainda ter chances de se corrigir.
	maxNegativeProbes = 3
)

// Detector descobre a plataforma e guarda o resultado.
//
// Não existe estado global neste pacote — nada de platform.Current(). O
// Snapshot é devolvido por valor, viaja de main para buildServices e dali para
// quem precisa, que é o que impede alguém de consultar a plataforma antes de
// ela ter sido detectada.
type Detector struct {
	store SettingsStore
	env   Env
}

// NewDetector cria o detector para a máquina de verdade.
func NewDetector(store SettingsStore) *Detector {
	return &Detector{store: store, env: RealEnv()}
}

// SetEnv troca as sondas. Existe para teste; em produção o padrão é o único
// que serve. Mesmo desenho de updater.SetSpoolDir.
func (d *Detector) SetEnv(env Env) { d.env = env }

// Detect responde em que máquina o produto está.
//
// NUNCA DEVOLVE ERRO HOJE, e a assinatura mantém o erro de propósito: quem
// chama tem que tratar "não deu" como UnknownSnapshot (que é permissivo), e
// não como motivo para abortar o boot. Nenhum caminho aqui derruba o processo
// — mesmo contrato de bootstrapdeps.Ensure.
//
// A ordem é cara-para-barata ao contrário: sinais locais (três leituras de
// arquivo e um net.Interfaces), depois o cache, e só então a rede.
func (d *Detector) Detect(ctx context.Context) (Snapshot, error) {
	env := d.env.withDefaults()

	// A camada 1 roda SEMPRE, inclusive quando há cache: é ela que valida o
	// cache, e é barata o bastante para isso não ter preço.
	signals := localSignals(env)
	fingerprint := currentFingerprint(env, signals.Interfaces)

	cached, ok, err := Load(d.store)
	if err != nil {
		// Instantâneo ilegível não vira on-prem silencioso: vira uma
		// detecção nova, com o motivo registrado.
		slog.Warn("o instantâneo de plataforma gravado é ilegível; detectando de novo", "err", err)
		ok = false
	}
	if ok && cacheUsable(cached, fingerprint, signals) {
		cached.Source = SourceCache
		return cached, nil
	}

	previous := Snapshot{}
	if ok && cached.Facts.Fingerprint == fingerprint {
		// O contador de negativas só é herdado na MESMA máquina; num backup
		// restaurado noutra caixa ele não diz nada sobre esta.
		previous = cached
	}

	snap := d.probe(ctx, env, signals, fingerprint, previous)
	d.save(snap)
	return snap, nil
}

// cacheUsable decide se o instantâneo gravado dispensa a sondagem.
//
// A quarta condição é o coração do desenho: o cache só vale quando CONCORDA
// com os sinais locais. É o que impede uma OCI cujo IMDS estava mudo no
// primeiro boot de ficar gravada como on-prem para sempre — e o que faz uma
// máquina migrada para a nuvem se corrigir sozinha no boot seguinte.
func cacheUsable(c Snapshot, fingerprint string, s LocalSignals) bool {
	if c.Format != SnapshotFormat {
		// Formato antigo é ignorado e redetectado, em vez de interpretado
		// errado. É também como uma regra nova de DeriveCapabilities alcança
		// as máquinas que já têm instantâneo.
		return false
	}
	if c.Facts.Kind == "" || c.Facts.Kind == KindUnknown {
		// "Não sei" gravado nunca é resposta: redetecta.
		return false
	}
	if c.Facts.Fingerprint == "" || c.Facts.Fingerprint != fingerprint {
		// Outra máquina. O caso real é o backup restaurado: ExportSettings
		// leva a tabela settings inteira, este instantâneo junto.
		return false
	}
	if (c.Facts.Kind != KindOnPrem) == s.Lit() {
		return true
	}
	// Discordam. A única saída é o contador: um cache de on-prem que já negou
	// três vezes seguidas para de gastar rede. Um cache de nuvem sem sinal
	// nenhum sempre redetecta, porque perder os sinais numa OCI de verdade é
	// anômalo e merece uma pergunta ao IMDS.
	return c.Facts.Kind == KindOnPrem && c.NegativeProbes >= maxNegativeProbes
}

// probe é a detecção de verdade: camada 2 (IMDS) quando algum sinal acendeu,
// mais os fatos de rede.
func (d *Detector) probe(ctx context.Context, env Env, signals LocalSignals, fingerprint string, previous Snapshot) Snapshot {
	facts := Facts{
		// O padrão é on-prem, e não desconhecido: chegar até aqui já é ter
		// olhado a máquina.
		Kind:        KindOnPrem,
		Confidence:  ConfidenceLocal,
		DetectedAt:  env.Now().Unix(),
		Signals:     signals.Names(),
		Fingerprint: fingerprint,
	}
	negatives := 0

	if signals.Lit() {
		// O orçamento vale para as três requisições juntas. WithTimeout
		// respeita um prazo mais curto que já venha no ctx do chamador.
		imdsCtx, cancel := context.WithTimeout(ctx, DetectBudget)
		oci, err := queryIMDS(imdsCtx, env)
		cancel()

		if err != nil {
			// Sinal aceso e IMDS calado. É on-prem, e é o caso da imagem
			// copiada — por isso o contador.
			negatives = previous.NegativeProbes + 1
			slog.Warn("sinal local de nuvem aceso, mas o serviço de metadados negou; tratando como máquina genérica",
				"sinais", strings.Join(facts.Signals, ","), "negativas", negatives, "err", err)
		} else {
			facts.Kind = KindOCI
			facts.Confidence = ConfidenceAuthoritative
			matchVNICInterfaces(oci, signals.Interfaces)
			facts.OCI = oci
		}
	}

	facts.Net = netFacts(env, facts, signals.Interfaces)

	return Snapshot{
		Format:         SnapshotFormat,
		Facts:          facts,
		Capabilities:   DeriveCapabilities(facts),
		Source:         SourceProbe,
		NegativeProbes: negatives,
	}
}

// matchVNICInterfaces casa cada VNIC com o nome de kernel da interface, pelo
// MAC. Sem casamento o campo fica vazio — e vazio quer dizer "não sei qual é",
// nunca "não tem".
func matchVNICInterfaces(oci *OCIFacts, ifaces []netFact) {
	if oci == nil {
		return
	}
	for i := range oci.VNICs {
		if oci.VNICs[i].MAC == "" {
			continue
		}
		for _, f := range ifaces {
			if f.MAC != "" && f.MAC == oci.VNICs[i].MAC {
				oci.VNICs[i].Interface = f.Name
				break
			}
		}
	}
}

// netFacts monta os fatos de rede: qual é a interface primária, a MTU dela e a
// MTU do caminho.
func netFacts(env Env, facts Facts, ifaces []netFact) NetFacts {
	primary := primaryInterface(env, facts, ifaces)

	nf := NetFacts{
		PrimaryInterface: primary.Name,
		PrimaryMAC:       primary.MAC,
		LinkMTU:          primary.MTU,
	}

	switch {
	case facts.Kind.IsCloud() && primary.MTU > cloudPathMTU:
		// Medido na instância real: ens3 com MTU 9000 e o caminho até a
		// Internet com 1500 (ping -M do). É propriedade da fabric, não
		// daquela instância — por isso vale sem medir nada aqui.
		nf.PathMTU = cloudPathMTU
		nf.PathMTUSource = PathMTUSourcePlatform
	default:
		// Fora da nuvem, DESCONHECIDO. Não é preguiça: medir o caminho exige
		// `ping -M do`, e iputils pode não estar instalado no instante em que
		// isto roda (ver o cabeçalho do pacote). E 0 é a única resposta que
		// mantém a máquina de produção como ela é hoje — o MSS clamp segue
		// com `rt mtu` (internal/nftables/mssclamp.go), que acerta por rota,
		// em vez de herdar um palpite tirado da interface eleita aqui.
		nf.PathMTU = 0
		nf.PathMTUSource = ""
	}

	return nf
}

// cloudPathMTU é a MTU do caminho até a Internet numa fabric de nuvem.
const cloudPathMTU = 1500

// primaryInterface escolhe a interface por onde a máquina fala com o mundo.
//
// Na OCI é a que casou com a primeira VNIC — o provedor já disse qual é. Fora
// dali é a da rota default, lida de /proc/net/route com um parser de duas
// linhas: o arquivo é o MESMO que internal/links já lê, e usar aquele pacote
// aqui traria internal/storage junto.
func primaryInterface(env Env, facts Facts, ifaces []netFact) netFact {
	byName := func(name string) (netFact, bool) {
		for _, f := range ifaces {
			if f.Name == name {
				return f, true
			}
		}
		return netFact{}, false
	}

	if facts.OCI != nil {
		for _, v := range facts.OCI.VNICs {
			if v.Interface == "" {
				continue
			}
			if f, ok := byName(v.Interface); ok {
				return f
			}
		}
	}

	if name := defaultRouteInterface(env); name != "" {
		if f, ok := byName(name); ok {
			return f
		}
	}

	// Sem rota default (uma instalação nova pode estar exatamente assim): a
	// primeira interface de verdade serve para registrar a MTU.
	for _, f := range ifaces {
		if !f.System && f.MAC != "" {
			return f
		}
	}
	return netFact{}
}

// defaultRouteInterface lê /proc/net/route e devolve a interface da rota
// default. "" quando não há rota default ou o arquivo não pôde ser lido — as
// duas coisas são normais numa máquina recém-instalada.
func defaultRouteInterface(env Env) string {
	b, err := env.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Destino 00000000 é a rota default. A primeira coluna é a interface.
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// save grava o instantâneo.
//
// Falhar aqui é WARN e nunca erro de retorno: o instantâneo detectado é válido
// e vale para este processo; o preço de não gravar é sondar de novo no próximo
// boot.
//
// Não existe atalho de --dry-run neste caminho, e não pode passar a existir:
// SetSetting não é comando de sistema, e o dry-run do produto é sobre o que o
// firewall.Executor dispara. Um `if IsDryRun()` aqui quebraria o cache em CI e
// em qualquer máquina de teste.
func (d *Detector) save(snap Snapshot) {
	if d.store == nil {
		return
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		slog.Warn("não foi possível serializar o instantâneo de plataforma", "err", err)
		return
	}
	if err := d.store.SetSetting(SnapshotSettingKey, string(raw)); err != nil {
		slog.Warn("não foi possível gravar o instantâneo de plataforma; a detecção vale para este processo",
			"err", err)
	}
}
