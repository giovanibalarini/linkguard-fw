package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"

	"github.com/giovanibalarini/linkguard-fw/internal/validate"
)

// Caminhos das sondas locais. Não precisam ser substituíveis: quem testa
// troca Env.ReadFile por um mapa em memória chaveado por estes mesmos nomes.
const (
	cloudIDPath   = "/run/cloud-init/cloud-id"
	osreleasePath = "/proc/sys/kernel/osrelease"
	machineIDPath = "/etc/machine-id"
)

// oracleAgentPaths são os lugares onde o snap do agente da Oracle aparece, em
// ordem de probabilidade. É os.Stat, NUNCA `systemctl is-active`: systemctl é
// fork, e este pacote não tem executor por decisão (ver platform.go).
var oracleAgentPaths = []string{
	"/var/snap/oracle-cloud-agent",
	"/snap/oracle-cloud-agent",
	"/etc/systemd/system/multi-user.target.wants/snap.oracle-cloud-agent.oracle-cloud-agent.service",
}

// oracleMACPrefix é o prefixo de MAC que a Oracle usa nas VNICs. Medido na
// instância real: 02:00:17:0A:19:30.
const oracleMACPrefix = "02:00:17"

// Nomes dos sinais, como aparecem em Facts.Signals e no log. São contrato de
// diagnóstico: quem lê "achei que era OCI por causa de kernel_oracle" precisa
// achar a mesma string no código.
const (
	signalCloudID = "cloud_id_oracle"
	signalKernel  = "kernel_oracle"
	signalMAC     = "mac_oracle"
	signalAgent   = "oracle_cloud_agent"
)

// systemPrefixes são os prefixos de nome que marcam RUÍDO de infraestrutura.
// A lista é uma cópia da de internal/netif (systemPrefixes), e a cópia é
// deliberada: netif importa internal/storage, e arrastar o banco para dentro
// de um pacote que precisa ser folha — e que roda antes de o banco existir em
// boa parte dos boots — custa muito mais do que seis strings repetidas. É o
// mesmo argumento que internal/timesync usa para duplicar um regex.
var systemPrefixes = []string{"docker", "br-", "veth", "tun", "tap", "wg"}

// netFact é o que a detecção precisa saber de uma interface. Vem de
// net.Interfaces, e de mais nada: `ip -j link` exigiria iproute2, que pode não
// estar instalado no instante em que isto roda.
type netFact struct {
	Name   string
	MAC    string // grafia canônica (minúscula, dois-pontos); "" quando não há
	MTU    int
	System bool // ruído de infraestrutura (docker/veth/...) ou loopback
}

// LocalSignals é a camada 1: quatro perguntas que não custam rede.
//
// Nenhuma delas é obrigatória, e nenhuma delas é o VEREDITO — são a
// autorização para gastar alguns segundos perguntando a quem sabe. Um único
// sinal basta para isso porque os quatro são específicos da Oracle.
type LocalSignals struct {
	CloudIDOracle   bool // /run/cloud-init/cloud-id == "oracle"
	KernelOracle    bool // /proc/sys/kernel/osrelease termina em "-oracle"
	OracleMACPrefix bool // alguma interface com MAC 02:00:17:*
	OracleAgent     bool // o snap oracle-cloud-agent existe em disco

	// Interfaces é a lista já lida, reaproveitada pelo fingerprint, pelo
	// casamento das VNICs e pela MTU. net.Interfaces é chamado UMA vez.
	Interfaces []netFact
}

// Lit diz se pelo menos um sinal acendeu. Falso aqui significa on-prem sem
// abrir um único socket — é a garantia que a máquina de produção paga.
func (s LocalSignals) Lit() bool {
	return s.CloudIDOracle || s.KernelOracle || s.OracleMACPrefix || s.OracleAgent
}

// Names lista os sinais acesos, na ordem em que são sondados.
func (s LocalSignals) Names() []string {
	var out []string
	if s.CloudIDOracle {
		out = append(out, signalCloudID)
	}
	if s.KernelOracle {
		out = append(out, signalKernel)
	}
	if s.OracleMACPrefix {
		out = append(out, signalMAC)
	}
	if s.OracleAgent {
		out = append(out, signalAgent)
	}
	return out
}

// localSignals responde as quatro perguntas baratas.
//
// Erro de leitura é sinal apagado, sem log: um /run/cloud-init inexistente é o
// caso NORMAL de toda máquina on-prem, e logar isso a cada boot seria ruído
// puro no journal da máquina de produção.
func localSignals(env Env) LocalSignals {
	s := LocalSignals{Interfaces: readInterfaces(env)}

	// 1. cloud-init. Comparação EXATA depois de TrimSpace, nunca Contains: num
	// MAAS ou num Proxmox on-prem este arquivo existe com outro valor, e
	// "oraclexyz" não é a Oracle.
	if b, err := env.ReadFile(cloudIDPath); err == nil {
		s.CloudIDOracle = strings.TrimSpace(string(b)) == "oracle"
	}

	// 2. Sabor do kernel. Este arquivo e não `uname -r`: é a mesma string, sem
	// fork, sem executor, sem depender de coreutils numa máquina pelada.
	if b, err := env.ReadFile(osreleasePath); err == nil {
		s.KernelOracle = strings.HasSuffix(strings.TrimSpace(string(b)), "-oracle")
	}

	// 3. Prefixo de MAC, sobre a lista que já foi lida. Interfaces de ruído
	// ficam de fora: um MAC de veth é sorteado, e um sorteio que caísse no
	// prefixo da Oracle acenderia o sinal numa caixa on-prem.
	for _, f := range s.Interfaces {
		if !f.System && strings.HasPrefix(f.MAC, oracleMACPrefix) {
			s.OracleMACPrefix = true
			break
		}
	}

	// 4. Agente da Oracle em disco.
	for _, p := range oracleAgentPaths {
		if env.Exists(p) {
			s.OracleAgent = true
			break
		}
	}

	return s
}

// readInterfaces traduz net.Interfaces para o que a detecção usa.
//
// Uma lista PARCIAL é tolerada de propósito: no boot esta função pode rodar
// antes de o systemd-networkd terminar. O preço de uma lista incompleta é
// redetectar no próximo boot (o fingerprint muda) — e esperar por rede aqui
// seria pôr uma espera no caminho crítico do boot, que é pior.
func readInterfaces(env Env) []netFact {
	ifaces, err := env.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]netFact, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, netFact{
			Name:   i.Name,
			MAC:    validate.NormalizeMAC(i.HardwareAddr.String()),
			MTU:    i.MTU,
			System: isSystemInterface(i.Name) || i.Flags&net.FlagLoopback != 0,
		})
	}
	return out
}

// isSystemInterface repete a classificação de internal/netif. Ver
// systemPrefixes para por que é uma cópia.
func isSystemInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// currentFingerprint amarra um instantâneo A ESTA máquina.
//
// É machine-id + os MACs das interfaces de verdade, ordenados. As interfaces
// de RUÍDO ficam de fora e isso não é detalhe: o MAC de uma veth é sorteado na
// criação, e um host com contêineres subindo e descendo teria um fingerprint
// diferente a cada boot — o cache nunca valeria, e a detecção sondaria a rede
// para sempre numa máquina que não é nuvem.
//
// machine-id ausente não é erro: entra vazio, e os MACs seguram sozinhos.
func currentFingerprint(env Env, ifaces []netFact) string {
	var macs []string
	for _, f := range ifaces {
		if f.System || f.MAC == "" {
			continue
		}
		macs = append(macs, f.MAC)
	}
	sort.Strings(macs)

	var machineID string
	if b, err := env.ReadFile(machineIDPath); err == nil {
		machineID = strings.TrimSpace(string(b))
	}

	sum := sha256.Sum256([]byte(machineID + "\x00" + strings.Join(macs, ",")))
	return hex.EncodeToString(sum[:])[:16]
}
