package platform

import (
	"io/fs"
	"net"
	"net/http"
	"testing"
	"time"
)

// ─── ambiente de mesa ────────────────────────────────────────────────────────

// transporteArmadilha falha o teste se alguém abrir um socket.
//
// É o Env.HTTP PADRÃO de todo teste deste pacote, e isso é de propósito: a
// afirmação "a máquina on-prem não paga rede" só vale se ela for o padrão, e
// não uma lembrança de quem escrever o próximo teste. Quem quer IMDS chama
// clienteIMDS e troca o campo.
type transporteArmadilha struct{ t *testing.T }

func (a transporteArmadilha) RoundTrip(r *http.Request) (*http.Response, error) {
	a.t.Helper()
	a.t.Errorf("a detecção abriu um socket para %s — nenhuma máquina sem sinal de nuvem pode pagar rede no boot", r.URL)
	return nil, fs.ErrClosed
}

// envFalso monta um ambiente que só enxerga o que o teste disser: nada de
// /proc de verdade, nada de rede.
func envFalso(t *testing.T, arquivos map[string]string, presentes []string, ifaces []net.Interface) Env {
	t.Helper()
	return Env{
		ReadFile: func(name string) ([]byte, error) {
			v, ok := arquivos[name]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(v), nil
		},
		Exists: func(name string) bool {
			for _, p := range presentes {
				if p == name {
					return true
				}
			}
			return false
		},
		Interfaces: func() ([]net.Interface, error) { return ifaces, nil },
		HTTP:       &http.Client{Transport: transporteArmadilha{t}},
		IMDSBase:   defaultIMDSBase,
		Now:        func() time.Time { return time.Unix(1751328000, 0) },
	}
}

// iface monta uma interface de kernel como net.Interfaces a devolveria.
func iface(t *testing.T, name, mac string, mtu int) net.Interface {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("MAC de teste inválido %q: %v", mac, err)
	}
	return net.Interface{Name: name, HardwareAddr: hw, MTU: mtu, Flags: net.FlagUp | net.FlagBroadcast}
}

func ifaceLoopback() net.Interface {
	return net.Interface{Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback}
}

// ensDaOCI é a interface medida na instância real: ens3, MAC do prefixo da
// Oracle, MTU 9000.
func ensDaOCI(t *testing.T) net.Interface {
	t.Helper()
	return iface(t, "ens3", "02:00:17:0a:19:30", 9000)
}

// maquinaOnPrem é a caixa de produção de hoje: kernel Debian, nenhum rastro de
// cloud-init, uma WAN e uma LAN de verdade.
func maquinaOnPrem(t *testing.T) Env {
	t.Helper()
	return envFalso(t,
		map[string]string{
			osreleasePath:     "6.12.48+deb13-amd64\n",
			machineIDPath:     "8f0a1b2c3d4e5f60718293a4b5c6d7e8\n",
			"/proc/net/route": procNetRoute("enp1s0"),
		},
		nil,
		[]net.Interface{ifaceLoopback(), iface(t, "enp1s0", "aa:bb:cc:dd:ee:01", 1500), iface(t, "enp2s0", "aa:bb:cc:dd:ee:02", 1500)},
	)
}

// procNetRoute devolve um /proc/net/route com rota default por iface.
func procNetRoute(iface string) string {
	return "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		iface + "\t00000000\t0102030A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		iface + "\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
}

// ─── camada 1: sinais locais ─────────────────────────────────────────────────

func TestMaquinaSemSinalNaoAcendeNada(t *testing.T) {
	s := localSignals(maquinaOnPrem(t))
	if s.Lit() {
		t.Fatalf("a caixa de produção acendeu sinal de nuvem: %+v", s)
	}
	if len(s.Names()) != 0 {
		t.Errorf("Names() = %v, esperado vazio", s.Names())
	}
	if len(s.Interfaces) != 3 {
		t.Errorf("as interfaces não foram lidas: %+v", s.Interfaces)
	}
}

func TestCloudIDExatamenteOracle(t *testing.T) {
	// Contains casaria com "oraclexyz", e um MAAS ou Proxmox on-prem grava
	// este MESMO arquivo com outro valor.
	casos := []struct {
		conteudo string
		acende   bool
	}{
		{"oracle", true},
		{"oracle\n", true},
		{"  oracle \n", true},
		{"nocloud", false},
		{"oraclexyz", false},
		{"xyzoracle", false},
		{"", false},
	}
	for _, c := range casos {
		env := maquinaOnPrem(t)
		arquivos := map[string]string{cloudIDPath: c.conteudo, osreleasePath: "6.12.48+deb13-amd64\n"}
		env.ReadFile = leitorDeMapa(arquivos)
		if got := localSignals(env).CloudIDOracle; got != c.acende {
			t.Errorf("cloud-id %q acendeu %v, esperado %v", c.conteudo, got, c.acende)
		}
	}
}

func TestKernelOracleSoNoSufixo(t *testing.T) {
	casos := []struct {
		osrelease string
		acende    bool
	}{
		{"6.17.0-1020-oracle\n", true}, // o kernel medido na instância real
		{"6.17.0-1020-oracle", true},
		{"6.12.48+deb13-amd64\n", false},
		{"6.8.0-oracle-generic", false}, // "oracle" no meio não é o sabor
		{"", false},
	}
	for _, c := range casos {
		env := maquinaOnPrem(t)
		env.ReadFile = leitorDeMapa(map[string]string{osreleasePath: c.osrelease})
		if got := localSignals(env).KernelOracle; got != c.acende {
			t.Errorf("osrelease %q acendeu %v, esperado %v", c.osrelease, got, c.acende)
		}
	}
}

func TestPrefixoDeMACIgnoraInterfaceDeRuido(t *testing.T) {
	// O MAC de uma veth ou de uma bridge do docker é sorteado na criação. Um
	// sorteio que caísse no prefixo da Oracle mandaria a caixa de produção
	// sondar o IMDS a cada boot.
	ruido := []net.Interface{
		ifaceLoopback(),
		iface(t, "docker0", "02:00:17:11:22:33", 1500),
		iface(t, "veth9f2a1c", "02:00:17:44:55:66", 1500),
		iface(t, "wg0", "02:00:17:77:88:99", 1420),
		iface(t, "br-1a2b3c", "02:00:17:aa:bb:cc", 1500),
	}
	env := maquinaOnPrem(t)
	env.Interfaces = func() ([]net.Interface, error) { return ruido, nil }
	if localSignals(env).OracleMACPrefix {
		t.Error("um MAC de interface de ruído acendeu o sinal da Oracle")
	}

	comEns3 := append(ruido, ensDaOCI(t))
	env.Interfaces = func() ([]net.Interface, error) { return comEns3, nil }
	if !localSignals(env).OracleMACPrefix {
		t.Error("o MAC 02:00:17 de uma interface de verdade não acendeu o sinal")
	}
}

func TestAgenteDetectadoPorQualquerUmDosTresCaminhos(t *testing.T) {
	for _, caminho := range oracleAgentPaths {
		env := maquinaOnPrem(t)
		env.Exists = func(n string) bool { return n == caminho }
		s := localSignals(env)
		if !s.OracleAgent {
			t.Errorf("o agente em %s não acendeu o sinal", caminho)
		}
		if !s.Lit() {
			t.Errorf("só o agente em %s deveria bastar para autorizar a sondagem", caminho)
		}
	}
}

func TestNomesDosSinaisSaoEstaveis(t *testing.T) {
	// Facts.Signals vai para o log e para a tela de diagnóstico: renomear um
	// destes quebra a única forma de alguém contestar um falso positivo sem
	// ler código.
	s := LocalSignals{CloudIDOracle: true, KernelOracle: true, OracleMACPrefix: true, OracleAgent: true}
	esperado := []string{"cloud_id_oracle", "kernel_oracle", "mac_oracle", "oracle_cloud_agent"}
	got := s.Names()
	if len(got) != len(esperado) {
		t.Fatalf("Names() = %v, esperado %v", got, esperado)
	}
	for i := range esperado {
		if got[i] != esperado[i] {
			t.Errorf("Names()[%d] = %q, esperado %q", i, got[i], esperado[i])
		}
	}
}

// ─── fingerprint ─────────────────────────────────────────────────────────────

func TestFingerprintIgnoraInterfaceDeRuido(t *testing.T) {
	// Um host com contêineres cria e destrói veth o tempo todo. Se elas
	// entrassem no fingerprint, o cache nunca valeria e a máquina sondaria a
	// rede para sempre.
	base := maquinaOnPrem(t)
	antes := currentFingerprint(base, readInterfaces(base))

	comRuido := maquinaOnPrem(t)
	comRuido.Interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			ifaceLoopback(),
			iface(t, "enp1s0", "aa:bb:cc:dd:ee:01", 1500),
			iface(t, "enp2s0", "aa:bb:cc:dd:ee:02", 1500),
			iface(t, "veth9f2a1c", "6e:11:22:33:44:55", 1500),
			iface(t, "docker0", "02:42:ac:11:00:01", 1500),
		}, nil
	}
	depois := currentFingerprint(comRuido, readInterfaces(comRuido))

	if antes != depois {
		t.Errorf("o fingerprint mudou por causa de interfaces de ruído: %s != %s", antes, depois)
	}
}

func TestFingerprintMudaComAMaquina(t *testing.T) {
	a := maquinaOnPrem(t)
	b := maquinaOnPrem(t)
	b.ReadFile = leitorDeMapa(map[string]string{machineIDPath: "0000000000000000000000000000dead"})

	if currentFingerprint(a, readInterfaces(a)) == currentFingerprint(b, readInterfaces(b)) {
		t.Error("duas máquinas com machine-id diferente têm o mesmo fingerprint — o cache viajaria no backup")
	}
}

func TestFingerprintSobreviveAMachineIDAusente(t *testing.T) {
	env := maquinaOnPrem(t)
	env.ReadFile = leitorDeMapa(map[string]string{}) // sem /etc/machine-id
	if fp := currentFingerprint(env, readInterfaces(env)); fp == "" {
		t.Error("machine-id ausente zerou o fingerprint; os MACs deveriam segurar sozinhos")
	}
}

// leitorDeMapa é o Env.ReadFile de mesa.
func leitorDeMapa(arquivos map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		v, ok := arquivos[name]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(v), nil
	}
}
