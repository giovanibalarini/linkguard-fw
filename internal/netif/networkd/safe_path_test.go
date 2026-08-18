package networkd

import "testing"

// safeUnitPath é a última barreira antes do os.Rename que escreve, como root,
// dentro de /etc/systemd/network.
//
// Ela existe porque a validação do nome de interface mora em OUTRO pacote e é
// chamada por quem monta o ConfigFile — não por quem escreve o arquivo. Esta
// função é a que tem o os.Rename na mão, e até então dependia de o chamador ter
// feito a coisa certa. Foi exatamente assim que uma cópia divergente da regex
// sobreviveu nesta base (ver o comentário de internal/netif/rules.go).

func TestSafeUnitPathRecusaOQueNaoEArquivoSolto(t *testing.T) {
	for _, p := range []string{
		"",
		"10-eth0.network",                     // relativo
		"etc/systemd/network/10-eth0.network", // relativo
		"/etc/systemd/network/",               // termina em diretório
		"/etc/systemd/network/..",             // sobe
		"/",                                   // raiz
		"/etc/systemd/network/  ",             // só espaço no nome
	} {
		if _, err := safeUnitPath(p, ""); err == nil {
			t.Errorf("safeUnitPath(%q) foi aceito", p)
		}
	}
}

// A travessia é RECUSADA, não normalizada — e a primeira versão deste arquivo
// afirmava o contrário, o que era um erro meu.
//
// Normalizar "/etc/systemd/network/../../passwd" para "/etc/passwd" faria a
// escrita ACONTECER, num lugar que o chamador não pediu, em silêncio e como
// root. Um caminho produzido por Render nunca tem "..": se um aparecer, quem
// montou o ConfigFile errou, e o certo é parar.
func TestSafeUnitPathRecusaTravessia(t *testing.T) {
	for _, p := range []string{
		"/etc/systemd/network/../../passwd",
		"/etc/systemd/network/../10-eth0.network",
		"/etc/systemd/network/./10-eth0.network",
	} {
		if _, err := safeUnitPath(p, ""); err == nil {
			t.Errorf("safeUnitPath(%q) aceitou travessia", p)
		}
	}
}

func TestSafeUnitPathAceitaOsCaminhosReais(t *testing.T) {
	for _, p := range []string{
		"/etc/systemd/network/10-eth0.network",
		"/etc/systemd/network/10-enp3s0.100.network",
		"/etc/systemd/network/10-br-lan.network",
		"/etc/systemd/network/10-aa:bb:cc:dd:ee:ff.link",
	} {
		got, err := safeUnitPath(p, "/etc/systemd/network")
		if err != nil {
			t.Errorf("safeUnitPath(%q) recusou um caminho legítimo: %v", p, err)
		}
		if got != p {
			t.Errorf("safeUnitPath(%q) alterou o caminho: %q", p, got)
		}
	}
}

// A conferência contra a raiz é a que sobrevive a uma mudança no validador de
// nome de interface — e é ela que responde a pergunta certa: "isto está onde eu
// mandei escrever?".
func TestSafeUnitPathExigeEstarDentroDaRaiz(t *testing.T) {
	const root = "/etc/systemd/network"

	if _, err := safeUnitPath(root+"/10-eth0.network", root); err != nil {
		t.Errorf("recusou um arquivo legítimo da raiz: %v", err)
	}
	// Fora da raiz.
	if _, err := safeUnitPath("/etc/passwd", root); err == nil {
		t.Error("aceitou caminho fora da raiz")
	}
	// Subdiretório: o arquivo tem de ser filho DIRETO — systemd-networkd não
	// lê recursivo, então um caminho assim já seria um bug do chamador.
	if _, err := safeUnitPath(root+"/sub/10-eth0.network", root); err == nil {
		t.Error("aceitou arquivo em subdiretório")
	}
	// O clássico do prefixo: "network-do-atacante" começa igual a "network".
	// Comparar o diretório-pai, e não a string com HasPrefix, é o que barra.
	if _, err := safeUnitPath("/etc/systemd/network-do-atacante/10-eth0.network", root); err == nil {
		t.Error("aceitou diretório vizinho de nome parecido")
	}
}

// Raiz vazia cai só na conferência de forma, para não quebrar o chamador que
// monta um ConfigFile a partir de um Path já gravado (o rollback do service).
func TestSafeUnitPathSemRaizAindaConfereForma(t *testing.T) {
	if _, err := safeUnitPath("/etc/systemd/network/10-eth0.network", ""); err != nil {
		t.Errorf("recusou caminho válido sem raiz: %v", err)
	}
	if _, err := safeUnitPath("/etc/systemd/network/../x", ""); err == nil {
		t.Error("aceitou travessia mesmo sem raiz")
	}
}
