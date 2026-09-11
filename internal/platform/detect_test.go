package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

// lojaFalsa é a fatia de storage.DB de mesa: um mapa, sem SQLite.
type lojaFalsa struct {
	valores  map[string]string
	erroLer  error
	erroGrav error
	gravacao int
}

func novaLoja() *lojaFalsa { return &lojaFalsa{valores: map[string]string{}} }

func (l *lojaFalsa) GetSetting(key string) (string, error) {
	if l.erroLer != nil {
		return "", l.erroLer
	}
	return l.valores[key], nil
}

func (l *lojaFalsa) SetSetting(key, value string) error {
	l.gravacao++
	if l.erroGrav != nil {
		return l.erroGrav
	}
	l.valores[key] = value
	return nil
}

// guardar grava um instantâneo já pronto, como o boot anterior teria deixado.
func (l *lojaFalsa) guardar(t *testing.T, snap Snapshot) {
	t.Helper()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("serializar o instantâneo: %v", err)
	}
	l.valores[SnapshotSettingKey] = string(b)
}

// detectorDeTeste monta o detector sobre um ambiente de mesa.
func detectorDeTeste(loja SettingsStore, env Env) *Detector {
	d := NewDetector(loja)
	d.SetEnv(env)
	return d
}

// maquinaOCI é a instância medida: kernel -oracle, cloud-id oracle, agente
// instalado, ens3 com MAC da Oracle e MTU 9000.
func maquinaOCI(t *testing.T) Env {
	t.Helper()
	env := envFalso(t,
		map[string]string{
			cloudIDPath:       "oracle\n",
			osreleasePath:     "6.17.0-1020-oracle\n",
			machineIDPath:     "3f1c9a77b84d4e2ab0c5d6e7f8091a2b\n",
			"/proc/net/route": procNetRoute("ens3"),
		},
		[]string{"/var/snap/oracle-cloud-agent"},
		[]net.Interface{ifaceLoopback(), ensDaOCI(t)},
	)
	return env
}

// ─── a garantia da produção ──────────────────────────────────────────────────

func TestSemSinalLocalNenhumSocketEhAberto(t *testing.T) {
	// O TESTE MAIS IMPORTANTE DO PACOTE. A caixa de produção roda 24/7 e não
	// pode pagar timeout de rede no boot por causa de uma feature de nuvem. O
	// Env.HTTP de envFalso é a armadilha: qualquer requisição falha o teste.
	loja := novaLoja()
	snap, err := detectorDeTeste(loja, maquinaOnPrem(t)).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem {
		t.Errorf("Kind = %q, esperado %q", snap.Facts.Kind, KindOnPrem)
	}
	if snap.Facts.Confidence != ConfidenceLocal {
		t.Errorf("Confidence = %q, esperado %q", snap.Facts.Confidence, ConfidenceLocal)
	}
	if snap.Capabilities != Permissive() {
		t.Errorf("a caixa on-prem perdeu capacidade: %+v", snap.Capabilities)
	}
	if snap.Source != SourceProbe {
		t.Errorf("Source = %q, esperado %q", snap.Source, SourceProbe)
	}
}

func TestDeteccaoOnPremEhImediata(t *testing.T) {
	// Sem sinal local, a camada 2 não roda: nenhum orçamento é gasto. Meio
	// segundo é ordens de grandeza acima do custo real (quatro leituras de
	// arquivo) e muito abaixo de qualquer timeout de rede.
	loja := novaLoja()
	d := detectorDeTeste(loja, maquinaOnPrem(t))

	inicio := time.Now()
	if _, err := d.Detect(context.Background()); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if gasto := time.Since(inicio); gasto > 500*time.Millisecond {
		t.Errorf("a detecção on-prem gastou %s; ela não pode depender de timeout de rede", gasto)
	}
}

func TestVMQEMUGenericaNaoViraOCI(t *testing.T) {
	// A instância OCI real diz "QEMU / Standard PC _i440FX + PIIX, 1996_ /
	// kvm" no DMI — QEMU genérico. Detecção por DMI daria falso positivo em
	// toda VM local. Aqui: uma VM QEMU comum, com virtio, kernel do Debian e
	// nenhum rastro da Oracle. Tem que sair on-prem, e sem tocar a rede.
	env := envFalso(t,
		map[string]string{
			osreleasePath:     "6.12.48+deb13-amd64\n",
			machineIDPath:     "aaaa1111bbbb2222cccc3333dddd4444\n",
			"/proc/net/route": procNetRoute("enp0s3"),
			// cloud-init de uma VM local provisionada por NoCloud.
			cloudIDPath: "nocloud\n",
		},
		nil,
		[]net.Interface{ifaceLoopback(), iface(t, "enp0s3", "52:54:00:12:34:56", 1500)},
	)
	snap, err := detectorDeTeste(novaLoja(), env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem {
		t.Errorf("uma VM QEMU genérica virou %q", snap.Facts.Kind)
	}
	if len(snap.Facts.Signals) != 0 {
		t.Errorf("sinais acesos numa VM sem nada da Oracle: %v", snap.Facts.Signals)
	}
}

// ─── a OCI de verdade ────────────────────────────────────────────────────────

func TestDeteccaoNaOCIRealProduzOsFatosEAsCapacidades(t *testing.T) {
	loja := novaLoja()
	env := maquinaOCI(t)
	imds := &imdsDaInstanciaReal{t: t}
	env.HTTP, env.IMDSBase = clienteIMDS(t, imds)

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if snap.Facts.Kind != KindOCI {
		t.Fatalf("Kind = %q, esperado %q", snap.Facts.Kind, KindOCI)
	}
	if snap.Facts.Confidence != ConfidenceAuthoritative {
		t.Errorf("Confidence = %q; o IMDS confirmou, isto é autoritativo", snap.Facts.Confidence)
	}
	// Os quatro sinais da instância medida: cloud-id, kernel -oracle, MAC
	// 02:00:17 e o snap do agente.
	if len(snap.Facts.Signals) != 4 {
		t.Errorf("Signals = %v, esperados os quatro sinais da instância medida", snap.Facts.Signals)
	}
	if snap.Facts.Fingerprint == "" {
		t.Error("o instantâneo saiu sem fingerprint; um backup restaurado o levaria para outra máquina")
	}

	// A VNIC casou com o nome de kernel pelo MAC.
	if len(snap.Facts.OCI.VNICs) != 1 || snap.Facts.OCI.VNICs[0].Interface != "ens3" {
		t.Errorf("a VNIC não casou com a interface: %+v", snap.Facts.OCI.VNICs)
	}

	// MTU: a interface diz 9000, o caminho até a Internet é 1500. Deduzir um
	// do outro é o defeito que estes dois campos existem para impedir.
	if snap.Facts.Net.PrimaryInterface != "ens3" || snap.Facts.Net.LinkMTU != 9000 {
		t.Errorf("interface primária = %q, LinkMTU = %d", snap.Facts.Net.PrimaryInterface, snap.Facts.Net.LinkMTU)
	}
	if snap.Facts.Net.PathMTU != 1500 || snap.Facts.Net.PathMTUSource != PathMTUSourcePlatform {
		t.Errorf("PathMTU = %d (%s), esperado 1500 pela fabric", snap.Facts.Net.PathMTU, snap.Facts.Net.PathMTUSource)
	}

	// E as capacidades saíram dos fatos.
	if snap.Capabilities.MultiWAN || snap.Capabilities.LinkFailover || snap.Capabilities.LoadBalancing {
		t.Errorf("maxVnicAttachments=1 e multi-WAN continuou de pé: %+v", snap.Capabilities)
	}
	if snap.Capabilities.DHCPServer || snap.Capabilities.SMART || snap.Capabilities.DDNS || snap.Capabilities.OwnTimeSync {
		t.Errorf("as capacidades de fabric não caíram: %+v", snap.Capabilities)
	}

	// E foi gravado, para o próximo boot não sondar.
	if loja.valores[SnapshotSettingKey] == "" {
		t.Fatal("o instantâneo não foi gravado")
	}
	lido, ok, err := Load(loja)
	if err != nil || !ok {
		t.Fatalf("Load do que acabou de ser gravado: ok=%v err=%v", ok, err)
	}
	if lido.Facts.OCI == nil || lido.Facts.OCI.Shape != "VM.Standard.E2.1.Micro" {
		t.Errorf("o que voltou do banco não é o que foi detectado: %+v", lido.Facts)
	}
}

func TestOnPremRegistraAMTUDaInterfaceEDeixaOCaminhoDesconhecido(t *testing.T) {
	// Fora da nuvem este incremento não afirma NADA sobre o caminho: PathMTU
	// fica 0. É o que mantém a máquina de produção como ela é hoje, porque o
	// MSS clamp segue com `rt mtu` (internal/nftables/mssclamp.go), que acerta
	// por rota. Copiar LinkMTU para PathMTU seria pior do que não saber — a
	// interface primária é uma ELEIÇÃO, e um palpite alto demais vira um clamp
	// alto demais, que trava conexão em vez de só degradá-la.
	snap, err := detectorDeTeste(novaLoja(), maquinaOnPrem(t)).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Net.PrimaryInterface != "enp1s0" || snap.Facts.Net.LinkMTU != 1500 {
		t.Errorf("interface primária = %q com LinkMTU %d, esperado enp1s0/1500",
			snap.Facts.Net.PrimaryInterface, snap.Facts.Net.LinkMTU)
	}
	if snap.Facts.Net.PathMTU != 0 || snap.Facts.Net.PathMTUSource != "" {
		t.Errorf("PathMTU = %d (%q); fora da nuvem o caminho é DESCONHECIDO, e desconhecido é o que mantém o produto como está",
			snap.Facts.Net.PathMTU, snap.Facts.Net.PathMTUSource)
	}
}

func TestInterfacePrimariaVemDaRotaDefault(t *testing.T) {
	// A eleição não pode ser "a primeira da lista": numa caixa de duas WANs e
	// uma LAN, a primeira interface do kernel não é por onde a máquina fala com
	// o mundo. Aqui a rota default está na SEGUNDA, e as MTUs são diferentes
	// para o teste não poder acertar por acaso.
	env := envFalso(t,
		map[string]string{
			osreleasePath:     "6.12.48+deb13-amd64\n",
			machineIDPath:     "8f0a1b2c3d4e5f60718293a4b5c6d7e8\n",
			"/proc/net/route": procNetRoute("enp2s0"),
		},
		nil,
		[]net.Interface{
			ifaceLoopback(),
			iface(t, "enp1s0", "aa:bb:cc:dd:ee:01", 9000),
			iface(t, "enp2s0", "aa:bb:cc:dd:ee:02", 1492),
		},
	)
	snap, err := detectorDeTeste(novaLoja(), env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Net.PrimaryInterface != "enp2s0" || snap.Facts.Net.LinkMTU != 1492 {
		t.Errorf("interface primária = %q com MTU %d; a rota default está em enp2s0 (1492)",
			snap.Facts.Net.PrimaryInterface, snap.Facts.Net.LinkMTU)
	}
}

func TestSemRotaDefaultAEleicaoCaiNaPrimeiraInterfaceDeVerdade(t *testing.T) {
	// Uma instalação nova pode estar exatamente assim. Registrar a MTU de
	// alguma interface de verdade é melhor do que não registrar nada — e o
	// loopback, com seus 65536, não pode ser a escolhida.
	env := envFalso(t,
		map[string]string{
			osreleasePath: "6.12.48+deb13-amd64\n",
			machineIDPath: "8f0a1b2c3d4e5f60718293a4b5c6d7e8\n",
		}, // sem /proc/net/route
		nil,
		[]net.Interface{ifaceLoopback(), iface(t, "enp1s0", "aa:bb:cc:dd:ee:01", 1500)},
	)
	snap, err := detectorDeTeste(novaLoja(), env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Net.PrimaryInterface != "enp1s0" || snap.Facts.Net.LinkMTU != 1500 {
		t.Errorf("interface primária = %q com MTU %d, esperado enp1s0/1500",
			snap.Facts.Net.PrimaryInterface, snap.Facts.Net.LinkMTU)
	}
}

func TestCloudIDPresenteComIMDSMudoEhOnPrem(t *testing.T) {
	// Sinal aceso não é veredito: é a autorização para perguntar. Quem
	// responde é o IMDS, e o silêncio dele é uma resposta.
	env := maquinaOCI(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), "http://127.0.0.1:1"

	loja := novaLoja()
	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem {
		t.Errorf("Kind = %q; o IMDS não respondeu, isto não é uma OCI", snap.Facts.Kind)
	}
	if snap.Facts.Confidence != ConfidenceLocal {
		t.Errorf("Confidence = %q, esperado %q", snap.Facts.Confidence, ConfidenceLocal)
	}
	if snap.Capabilities != Permissive() {
		t.Errorf("um IMDS mudo virou restrição: %+v", snap.Capabilities)
	}
	if snap.NegativeProbes != 1 {
		t.Errorf("NegativeProbes = %d, esperado 1", snap.NegativeProbes)
	}
}

// ─── o cache ─────────────────────────────────────────────────────────────────

func TestCacheValidoEvitaOIMDS(t *testing.T) {
	// Cache de OCI + sinais acesos: concordam, então nem o transporte
	// armadilha é tocado.
	env := maquinaOCI(t) // Env.HTTP é a armadilha
	fp := currentFingerprint(env, readInterfaces(env))

	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format: SnapshotFormat,
		Facts: Facts{
			Kind: KindOCI, Confidence: ConfidenceAuthoritative, Fingerprint: fp,
			OCI: &OCIFacts{Shape: "VM.Standard.E2.1.Micro", MaxVNICAttachments: 1},
		},
		Capabilities: DeriveCapabilities(Facts{Kind: KindOCI, OCI: &OCIFacts{MaxVNICAttachments: 1}}),
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceCache {
		t.Errorf("Source = %q, esperado %q", snap.Source, SourceCache)
	}
	if snap.Facts.Kind != KindOCI || snap.Capabilities.MultiWAN {
		t.Errorf("o cache não foi honrado: %+v", snap)
	}
	if loja.gravacao != 0 {
		t.Errorf("o cache válido gravou de novo (%d vezes)", loja.gravacao)
	}
}

func TestCacheDeOnPremEmMaquinaSemSinalEvitaTudo(t *testing.T) {
	// 99,99% dos boots da caixa de produção. Zero rede, zero gravação.
	env := maquinaOnPrem(t)
	fp := currentFingerprint(env, readInterfaces(env))

	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format:       SnapshotFormat,
		Facts:        Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal, Fingerprint: fp},
		Capabilities: Permissive(),
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceCache || loja.gravacao != 0 {
		t.Errorf("a caixa on-prem não aproveitou o cache: source=%q gravações=%d", snap.Source, loja.gravacao)
	}
}

func TestCacheQueDiscordaDosSinaisRedetecta(t *testing.T) {
	// O caso que isto existe para consertar: uma OCI cujo IMDS estava mudo no
	// primeiro boot gravou "on-prem". Sem esta regra, ficaria on-prem para
	// sempre.
	env := maquinaOCI(t)
	imds := &imdsDaInstanciaReal{t: t}
	env.HTTP, env.IMDSBase = clienteIMDS(t, imds)
	fp := currentFingerprint(env, readInterfaces(env))

	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format:       SnapshotFormat,
		Facts:        Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal, Fingerprint: fp},
		Capabilities: Permissive(),
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Errorf("Source = %q; cache e sinais discordavam, era para sondar", snap.Source)
	}
	if snap.Facts.Kind != KindOCI {
		t.Errorf("a máquina não se corrigiu: Kind = %q", snap.Facts.Kind)
	}
}

func TestQuandoOCacheVale(t *testing.T) {
	// A tabela do cacheUsable, que é onde as quatro condições moram. Os testes
	// de ponta a ponta abaixo provam os dois cenários que doem; esta tabela é o
	// que impede uma das condições de sumir sem ninguém notar — cada linha aqui
	// é uma condição que, sozinha, já recusa o instantâneo.
	const fp = "1234567890abcdef"
	aceso := LocalSignals{KernelOracle: true}
	apagado := LocalSignals{}
	gravado := func(k Kind, fingerprint string, formato, negativas int) Snapshot {
		return Snapshot{
			Format:         formato,
			Facts:          Facts{Kind: k, Fingerprint: fingerprint},
			NegativeProbes: negativas,
		}
	}

	casos := []struct {
		nome   string
		cache  Snapshot
		sinais LocalSignals
		vale   bool
	}{
		{"on-prem sem sinal nenhum: o boot da caixa de produção",
			gravado(KindOnPrem, fp, SnapshotFormat, 0), apagado, true},
		{"OCI com os sinais acesos",
			gravado(KindOCI, fp, SnapshotFormat, 0), aceso, true},
		{"on-prem gravado numa máquina que acende sinal: pode ser uma OCI cujo IMDS estava mudo no primeiro boot",
			gravado(KindOnPrem, fp, SnapshotFormat, 0), aceso, false},
		{"OCI gravada numa máquina que não acende mais sinal nenhum",
			gravado(KindOCI, fp, SnapshotFormat, 0), apagado, false},
		{"on-prem que já negou três vezes seguidas: para de gastar rede",
			gravado(KindOnPrem, fp, SnapshotFormat, maxNegativeProbes), aceso, true},
		{"on-prem que negou duas vezes: ainda tem chance de se corrigir",
			gravado(KindOnPrem, fp, SnapshotFormat, maxNegativeProbes-1), aceso, false},
		{"OCI sem sinal, mesmo com negativas acumuladas: o escape é só do on-prem",
			gravado(KindOCI, fp, SnapshotFormat, maxNegativeProbes+6), apagado, false},
		{"formato de outro tempo, cujas capacidades querem dizer outra coisa",
			gravado(KindOnPrem, fp, SnapshotFormat+1, 0), apagado, false},
		// As duas linhas do "não sei" vêm com o sinal ACESO de propósito: com
		// ele apagado, quem recusaria seria a discordância com os sinais, e a
		// linha passaria mesmo sem o guarda do Kind desconhecido. Honrar um
		// cache desses deixaria a máquina parada em "não sei" para sempre, sem
		// nunca mais perguntar.
		{`"não sei" gravado nunca é resposta`,
			gravado(KindUnknown, fp, SnapshotFormat, 0), aceso, false},
		{"instantâneo sem plataforma nenhuma",
			gravado("", fp, SnapshotFormat, 0), aceso, false},
		{"outra máquina: o backup restaurado",
			gravado(KindOnPrem, "outramaquina0000", SnapshotFormat, 0), apagado, false},
		{"sem fingerprint: não dá para saber de quem é",
			gravado(KindOnPrem, "", SnapshotFormat, 0), apagado, false},
	}
	for _, c := range casos {
		if got := cacheUsable(c.cache, fp, c.sinais); got != c.vale {
			t.Errorf("%s: cacheUsable = %v, esperado %v", c.nome, got, c.vale)
		}
	}
}

func TestFingerprintDeOutraMaquinaInvalidaOCache(t *testing.T) {
	// storage.ExportSettings copia a tabela settings inteira para o backup, sem
	// filtro (internal/backup já recusa esta chave no restore, mas a defesa do
	// detector tem que valer sozinha).
	//
	// O instantâneo gravado aqui CONCORDA com os sinais desta máquina, de
	// propósito: assim a única coisa que pode recusá-lo é o fingerprint. A
	// versão anterior deste teste guardava um instantâneo de OCI numa caixa sem
	// sinal nenhum, e ali quem recusava era a discordância com os sinais — ele
	// passava igual com a checagem de fingerprint removida.
	env := maquinaOnPrem(t) // a armadilha: sem sinal, nada de rede
	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format:       SnapshotFormat,
		Facts:        Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal, Fingerprint: "outramaquina0000"},
		Capabilities: Permissive(),
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Errorf("Source = %q; o instantâneo era de outra máquina e tinha que ser redetectado", snap.Source)
	}
	if snap.Facts.Fingerprint == "outramaquina0000" || snap.Facts.Fingerprint == "" {
		t.Errorf("o instantâneo novo saiu com o fingerprint %q; ele tem que ser o desta máquina", snap.Facts.Fingerprint)
	}
}

func TestBackupDeOutraOCINaoDecidePorEstaMaquina(t *testing.T) {
	// O caso que realmente dói, e onde só o fingerprint separa: as duas
	// máquinas são OCI, as duas acendem os mesmos sinais, e o instantâneo
	// restaurado veio de uma instância de UMA VNIC. Sem o fingerprint, esta
	// caixa — que o IMDS diz ter quatro — herdaria multi_wan=false e o painel
	// esconderia dela um failover que ela pode fazer.
	env := maquinaOCI(t)
	quatroVNICs := `{"id":"ocid1.instance.oc1.sa-saopaulo-1.estamaquina",
		"canonicalRegionName":"sa-saopaulo-1","shape":"VM.Standard.E4.Flex",
		"shapeConfig":{"maxVnicAttachments":4,"ocpus":2.0}}`
	env.HTTP, env.IMDSBase = clienteIMDS(t, &imdsDaInstanciaReal{t: t, corpoV2: []byte(quatroVNICs)})

	deUmaVNIC := Facts{
		Kind: KindOCI, Confidence: ConfidenceAuthoritative,
		Fingerprint: "outrainstancia00",
		OCI:         &OCIFacts{Shape: "VM.Standard.E2.1.Micro", MaxVNICAttachments: 1},
	}
	loja := novaLoja()
	loja.guardar(t, Snapshot{Format: SnapshotFormat, Facts: deUmaVNIC, Capabilities: DeriveCapabilities(deUmaVNIC)})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Fatalf("Source = %q; o instantâneo era de outra instância", snap.Source)
	}
	if snap.Facts.OCI == nil || snap.Facts.OCI.MaxVNICAttachments != 4 {
		t.Fatalf("os fatos não foram refeitos nesta máquina: %+v", snap.Facts.OCI)
	}
	if !snap.Capabilities.MultiWAN || !snap.Capabilities.LinkFailover {
		t.Errorf("esta instância perdeu multi-WAN por causa do backup de outra: %+v", snap.Capabilities)
	}
}

func TestFormatoAntigoEhIgnorado(t *testing.T) {
	// O instantâneo gravado concorda com os sinais e é desta máquina: a única
	// coisa que pode recusá-lo é o formato. É isso que faz uma regra nova de
	// DeriveCapabilities alcançar as máquinas que já têm instantâneo — e é
	// isso que impede capacidades de outro tempo, com outro significado, de
	// serem lidas como se fossem destas.
	env := maquinaOnPrem(t)
	fp := currentFingerprint(env, readInterfaces(env))

	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format:       SnapshotFormat - 1,
		Facts:        Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal, Fingerprint: fp},
		Capabilities: Capabilities{}, // tudo desligado, com o significado antigo
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Errorf("Source = %q; um formato antigo tem que ser redetectado", snap.Source)
	}
	if snap.Format != SnapshotFormat {
		t.Errorf("Format = %d; o instantâneo novo tem que sair no formato de hoje", snap.Format)
	}
	if snap.Capabilities != Permissive() {
		t.Errorf("as capacidades do formato antigo vazaram: %+v", snap.Capabilities)
	}
}

func TestTresNegativasSeguidasParamDeSondar(t *testing.T) {
	// Uma imagem Ubuntu-da-OCI copiada para uma VM local mantém o kernel
	// "-oracle" para sempre: o sinal acende em todo boot e o IMDS nunca vai
	// existir. Sem o contador, essa máquina pagaria a sondagem eternamente.
	env := maquinaOCI(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), "http://127.0.0.1:1" // ninguém atende
	loja := novaLoja()

	for boot := 1; boot <= maxNegativeProbes; boot++ {
		snap, err := detectorDeTeste(loja, env).Detect(context.Background())
		if err != nil {
			t.Fatalf("boot %d: %v", boot, err)
		}
		if snap.Source != SourceProbe {
			t.Fatalf("boot %d: Source = %q, ainda era para sondar", boot, snap.Source)
		}
		if snap.NegativeProbes != boot {
			t.Fatalf("boot %d: NegativeProbes = %d", boot, snap.NegativeProbes)
		}
	}

	// A partir daqui o cache vale, e a armadilha prova que a rede parou de ser
	// tocada.
	comArmadilha := maquinaOCI(t) // Env.HTTP é a armadilha
	snap, err := detectorDeTeste(loja, comArmadilha).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceCache {
		t.Errorf("Source = %q; depois de %d negativas o cache tem que valer", snap.Source, maxNegativeProbes)
	}
	if snap.Facts.Kind != KindOnPrem || snap.Capabilities != Permissive() {
		t.Errorf("a máquina parou num estado errado: %+v", snap)
	}
}

func TestContadorDeNegativasNaoViajaEntreMaquinas(t *testing.T) {
	// O contador é o que faz uma máquina desistir de perguntar ao IMDS. Herdado
	// de um backup de OUTRA caixa, faria esta desistir na primeira tentativa —
	// e uma OCI de verdade cujo IMDS demorou a subir nunca mais se corrigiria.
	env := maquinaOCI(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), "http://127.0.0.1:1" // ninguém atende

	loja := novaLoja()
	loja.guardar(t, Snapshot{
		Format:         SnapshotFormat,
		Facts:          Facts{Kind: KindOnPrem, Confidence: ConfidenceLocal, Fingerprint: "outramaquina0000"},
		Capabilities:   Permissive(),
		NegativeProbes: maxNegativeProbes,
	})

	snap, err := detectorDeTeste(loja, env).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Fatalf("Source = %q; o instantâneo era de outra máquina", snap.Source)
	}
	if snap.NegativeProbes != 1 {
		t.Errorf("NegativeProbes = %d; esta máquina negou UMA vez, o resto é de outra caixa", snap.NegativeProbes)
	}
}

// ─── nada aqui derruba o boot ────────────────────────────────────────────────

func TestFalhaAoGravarNaoDerrubaADeteccao(t *testing.T) {
	loja := novaLoja()
	loja.erroGrav = errors.New("banco em somente-leitura")

	snap, err := detectorDeTeste(loja, maquinaOnPrem(t)).Detect(context.Background())
	if err != nil {
		t.Fatalf("uma falha de gravação virou erro de detecção: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem || snap.Capabilities != Permissive() {
		t.Errorf("o instantâneo detectado se perdeu junto com a gravação: %+v", snap)
	}
}

func TestJSONCorrompidoNoBancoNaoViraOnPremSilencioso(t *testing.T) {
	// Load PROPAGA o erro — um SELECT que devolveu lixo não é uma afirmação
	// sobre a máquina — e Detect redetecta em vez de aceitar o lixo.
	loja := novaLoja()
	loja.valores[SnapshotSettingKey] = "{isto não é json"

	if _, ok, err := Load(loja); err == nil || ok {
		t.Errorf("Load engoliu um instantâneo corrompido: ok=%v err=%v", ok, err)
	}

	snap, err := detectorDeTeste(loja, maquinaOnPrem(t)).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if snap.Source != SourceProbe {
		t.Errorf("Source = %q; um instantâneo corrompido tem que forçar nova detecção", snap.Source)
	}
	if loja.valores[SnapshotSettingKey] == "{isto não é json" {
		t.Error("o instantâneo corrompido continua no banco")
	}
}

func TestErroDeLeituraDoBancoNaoDerrubaADeteccao(t *testing.T) {
	loja := novaLoja()
	loja.erroLer = errors.New("banco travado")

	snap, err := detectorDeTeste(loja, maquinaOnPrem(t)).Detect(context.Background())
	if err != nil {
		t.Fatalf("um erro de banco virou erro de detecção: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem {
		t.Errorf("Kind = %q", snap.Facts.Kind)
	}
}

func TestLoadSemNuncaTerDetectadoDizQueNaoSabe(t *testing.T) {
	snap, ok, err := Load(novaLoja())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok {
		t.Error("Load afirmou conhecer uma máquina que nunca foi detectada")
	}
	// E o que ele devolve nesse caso é permissivo, nunca on-prem.
	if snap.Facts.Kind != KindUnknown || snap.Capable() != Permissive() {
		t.Errorf("chave ausente não virou desconhecido-permissivo: %+v", snap)
	}
}

func TestDetectComContextoJaCanceladoNaoDerruba(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := maquinaOCI(t)
	env.HTTP, env.IMDSBase = newIMDSClient(), "http://127.0.0.1:1"

	snap, err := detectorDeTeste(novaLoja(), env).Detect(ctx)
	if err != nil {
		t.Fatalf("um contexto cancelado derrubou a detecção: %v", err)
	}
	if snap.Facts.Kind != KindOnPrem || snap.Capabilities != Permissive() {
		t.Errorf("o cancelamento virou restrição: %+v", snap)
	}
}

func TestEnvIncompletoNaoDerrubaOBoot(t *testing.T) {
	// SetEnv recebe um struct montado do lado de fora; um campo esquecido não
	// pode virar nil-deref no caminho de boot do produto.
	//
	// ReadFile, Exists, HTTP e Now ficam nulos de propósito: são eles os
	// candidatos a nil-deref, e completá-los aqui não testaria nada. O IMDSBase
	// é a exceção e vai preenchido para lugar nenhum: com o padrão, esta
	// asserção passaria a depender do /proc da máquina que roda `go test` —
	// num runner com kernel de nuvem, um sinal aceso mandaria o teste falar com
	// o serviço de metadados de verdade daquele provedor.
	d := NewDetector(novaLoja())
	d.SetEnv(Env{
		Interfaces: func() ([]net.Interface, error) { return nil, nil },
		IMDSBase:   "http://127.0.0.1:1",
	})
	if _, err := d.Detect(context.Background()); err != nil {
		t.Fatalf("Detect com Env incompleto: %v", err)
	}
}
