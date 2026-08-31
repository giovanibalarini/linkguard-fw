package sysprep

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/bootstrapdeps"
)

// Estes testes leem os arquivos de empacotamento de verdade. Eles existem
// porque três defeitos independentes desta rodada de revisão eram todos a
// mesma coisa — uma afirmação sobre o empacotamento que ninguém verificava:
//
//   - o .deb oficial (release.yml) continuava com `Depends:` e parava em `iU`
//     numa máquina pelada, enquanto o `make deb` já tinha a premissa nova;
//   - o install.sh e o `make install` não criavam o /etc/nftables.conf, e o
//     serviço morria em loop de 226/NAMESPACE;
//   - o /etc/chrony/conf.d e o /etc/sysctl.d ficaram de fora da lista, com o
//     comentário da unidade afirmando o contrário.
//
// Nenhum deles aparece em teste unitário de lógica: só olhando os arquivos.

// repoRoot devolve a raiz do repositório a partir da localização deste
// arquivo — independente do diretório de onde o `go test` foi chamado.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não consegui localizar este arquivo de teste")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("ler %s: %v", rel, err)
	}
	return string(b)
}

// readWritePaths devolve as entradas de ReadWritePaths= da unidade, na ordem,
// com o prefixo `-` preservado.
func readWritePaths(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readRepoFile(t, "deploy/linkguard-fw.service"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ReadWritePaths=") {
			continue
		}
		out = append(out, strings.Fields(strings.TrimPrefix(line, "ReadWritePaths="))...)
	}
	if len(out) == 0 {
		t.Fatal("nenhum ReadWritePaths= encontrado na unidade — o teste ficou cego")
	}
	return out
}

// optionalPathsWeDoNotCreate são as entradas com `-` que o LinkGuard
// deliberadamente NÃO cria, cada uma com o motivo. Uma entrada nova com `-`
// que não esteja aqui quebra o teste de propósito: a decisão "quem garante
// este caminho?" tem que ser tomada por alguém, não esquecida.
var optionalPathsWeDoNotCreate = map[string]string{
	"/etc/systemd/network": "vem do pacote systemd, sempre presente numa máquina com systemd",
	"/etc/resolv.conf":     "sempre presente; e criar um vazio seria pior que não ter",
	"/etc/dhcp":            "vem do isc-dhcp-client, que este pacote não declara nem em Recommends: — num box só com WAN estática, ou no Debian 13, ele legitimamente não existe",
}

// A armadilha original, em forma de teste: uma entrada SEM o prefixo `-` que
// não exista no start mata a unidade com 226/NAMESPACE, em loop de restart,
// sem executar uma linha do binário. Então toda entrada sem `-` tem que ser
// garantida pelo instalador.
func TestTodoReadWritePathObrigatorioEPreparadoPeloInstalador(t *testing.T) {
	for _, p := range readWritePaths(t) {
		if strings.HasPrefix(p, "-") {
			continue
		}
		if !Covers(p) {
			t.Errorf("%s está em ReadWritePaths= sem o prefixo `-` e ninguém o cria: "+
				"numa máquina em que ele falte, a unidade morre em 226/NAMESPACE. "+
				"Ou adicione-o a sysprep.Entries, ou coloque o prefixo `-`", p)
		}
	}
}

// O `-` evita o 226/NAMESPACE mas NÃO cria montagem: um diretório que passa a
// existir depois do start continua somente-leitura para o processo em
// execução. Todo caminho opcional em que o LinkGuard escreve tem que ser
// criado por nós; os que não são precisam de justificativa explícita.
func TestTodoReadWritePathOpcionalEPreparadoOuJustificado(t *testing.T) {
	for _, raw := range readWritePaths(t) {
		if !strings.HasPrefix(raw, "-") {
			continue
		}
		p := strings.TrimPrefix(raw, "-")
		if Covers(p) {
			continue
		}
		if why := optionalPathsWeDoNotCreate[p]; why != "" {
			continue
		}
		t.Errorf("%s é opcional na unidade e não é criado por ninguém. Se o LinkGuard escreve nele, "+
			"o primeiro apply depois de instalar o pacote dono vai falhar com \"Read-only file system\" "+
			"até alguém reiniciar o serviço. Adicione-o a sysprep.Entries, ou a "+
			"optionalPathsWeDoNotCreate com o motivo", p)
	}
}

// E o contrário: um caminho que preparamos e que ninguém declarou na unidade
// é trabalho jogado fora — o processo não conseguiria escrever nele de
// qualquer jeito.
func TestTudoQuePreparamosEstaNaUnidade(t *testing.T) {
	declared := map[string]bool{}
	for _, p := range readWritePaths(t) {
		declared[strings.TrimPrefix(p, "-")] = true
	}
	for _, e := range Entries {
		covered := false
		for d := range declared {
			if d == e.Path || strings.HasPrefix(e.Path, d+"/") {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("%s é criado pelo instalador mas não está em ReadWritePaths=: "+
				"o serviço não vai conseguir escrever nele", e.Path)
		}
	}
}

// Os TRÊS caminhos de instalação têm que deixar a máquina no mesmo estado.
// Enquanto isso morava só no postinst, quem instalava por install.sh ou por
// `make install` ficava com o serviço em loop de 226/NAMESPACE.
func TestOsTresInstaladoresPreparamOSistema(t *testing.T) {
	for _, f := range []string{"deploy/deb/postinst", "deploy/install.sh", "Makefile"} {
		if !strings.Contains(readRepoFile(t, f), "--prepare-system") {
			t.Errorf("%s não chama `linkguard-fw --prepare-system`: essa instalação deixa o "+
				"serviço sem os caminhos que a unidade exige", f)
		}
	}
}

// execStartPre devolve as linhas ExecStartPre= da unidade, com os prefixos
// (`-`, `+`, `@`, `!`) preservados.
func execStartPre(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readRepoFile(t, "deploy/linkguard-fw.service"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStartPre=") {
			out = append(out, strings.TrimPrefix(line, "ExecStartPre="))
		}
	}
	return out
}

// O conserto do defeito de instalação, amarrado nos dois lados.
//
// Um caminho marcado OnlyAtServiceStart não pode sair de instalador nenhum
// (é conffile de outro pacote — o dpkg trava no prompt). Quem o cria é o
// ExecStartPre da unidade, e para isso DUAS condições do systemd têm que
// valer ao mesmo tempo. As duas foram medidas no systemd 257 (Debian 13),
// com unidades de teste numa VM, antes de escolher este desenho:
//
//	A) ReadWritePaths=/etc/exp.conf (SEM `-`) + ExecStartPre=+... que cria o
//	   arquivo  →  "Failed to set up mount namespacing: /etc/exp.conf: No
//	   such file or directory", "Failed at step NAMESPACE spawning /bin/sh",
//	   226/NAMESPACE. O `+` NÃO pula a montagem do namespace: o pre-comando
//	   morre antes de criar o que quer que seja.
//	E) ReadWritePaths=-/etc/exp.conf + ExecStartPre=+...  →  unidade active,
//	   arquivo com o conteúdo do pre E o do ExecStart. Ou seja: o namespace é
//	   montado UMA VEZ POR COMANDO, e o ExecStart enxerga como gravável o que
//	   o pre-comando acabou de criar.
//	F) ReadWritePaths=-/etc/exp.conf + ExecStartPre SEM `+`  →  "cannot
//	   create /etc/exp.conf: Read-only file system". O `+` é o que tira o
//	   pre-comando do ProtectSystem=strict.
//
// Este teste é o que impede alguém de desfazer qualquer uma das três.
func TestPreparoDeStartExigeCaminhoOpcionalEExecStartPrePrivilegiado(t *testing.T) {
	pres := execStartPre(t)
	if len(pres) == 0 {
		t.Fatal("a unidade não tem ExecStartPre=: sem ele ninguém cria o /etc/nftables.conf " +
			"depois que o apt termina, e a instalação volta a travar no prompt de conffile do dpkg")
	}

	var prepara string
	for _, p := range pres {
		if strings.Contains(p, "--prepare-system-at-start") {
			prepara = p
		}
	}
	if prepara == "" {
		t.Fatalf("nenhum ExecStartPre= chama `--prepare-system-at-start`; encontrei %v", pres)
	}
	prefixes := prepara[:len(prepara)-len(strings.TrimLeft(prepara, "-+@!:"))]
	if !strings.Contains(prefixes, "+") {
		t.Errorf("o ExecStartPre do preparo está sem o prefixo `+` (%q): sem ele o comando roda "+
			"dentro do ProtectSystem=strict e recebe \"Read-only file system\" ao criar em /etc", prepara)
	}
	if !strings.Contains(prefixes, "-") {
		t.Errorf("o ExecStartPre do preparo está sem o prefixo `-` (%q): uma falha no preparo "+
			"derrubaria a unidade inteira e não sobraria painel para explicar o que houve", prepara)
	}

	declared := map[string]string{} // caminho sem prefixo -> entrada crua
	for _, raw := range readWritePaths(t) {
		declared[strings.TrimPrefix(raw, "-")] = raw
	}
	for _, e := range Entries {
		if !e.OnlyAtServiceStart {
			continue
		}
		raw, ok := declared[e.Path]
		if !ok {
			t.Errorf("%s nasce só na partida do serviço mas não está em ReadWritePaths=", e.Path)
			continue
		}
		if !strings.HasPrefix(raw, "-") {
			t.Errorf("%s está em ReadWritePaths= sem o prefixo `-`. Medido no systemd 257: "+
				"nessa forma o próprio ExecStartPre=+ morre em 226/NAMESPACE antes de criar o "+
				"arquivo, e o serviço entra em loop de restart numa máquina pelada", e.Path)
		}
	}
}

// E o outro lado do mesmo conserto: nenhum dos três instaladores pode voltar
// a criar o /etc/nftables.conf. Eles rodam com o dpkg no comando; o arquivo
// é conffile do pacote `nftables`, e um conffile que o dpkg não escreveu faz
// ele parar para perguntar a quem obedecer no meio do `apt install`.
func TestNenhumInstaladorCriaOConffileDoNftables(t *testing.T) {
	for _, f := range []string{"deploy/deb/postinst", "deploy/install.sh", "Makefile"} {
		body := readRepoFile(t, f)
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, "--prepare-system-at-start") {
				t.Errorf("%s chama `--prepare-system-at-start`: essa forma cria o %s dentro da "+
					"transação do dpkg e trava o `apt install` no prompt de conffile", f, NftablesConfPath)
			}
		}
	}

	nft := false
	for _, e := range Entries {
		if e.Path == NftablesConfPath {
			nft = true
			if !e.OnlyAtServiceStart {
				t.Errorf("%s voltou a ser criado pelos instaladores (OnlyAtServiceStart=false): "+
					"é conffile do pacote nftables e o dpkg trava no prompt", NftablesConfPath)
			}
		}
	}
	if !nft {
		t.Fatalf("%s sumiu de sysprep.Entries — sem ele a unidade morre em 226/NAMESPACE", NftablesConfPath)
	}
}

var controlFieldRe = regexp.MustCompile(`(?m)^\s*(Depends|Pre-Depends|Recommends):\s*(.+)$`)

// controlFields devolve os campos de relação declarados num arquivo que
// EMITE um control, não que o contenha.
//
// O Makefile monta o DEBIAN/control com um `printf` de UMA linha só, com os
// `\n` escapados. Com a regex ancorada em linha (`(?m)^`), `Recommends:` no
// meio daquela linha casava ZERO vezes — o laço de TestABaseFicaEmRecommends
// nunca inspecionava nada e o guarda que a entrega inteira do empacotamento
// diz ter era vacuoso: reintroduzir `Depends: nftables, iproute2` no printf
// deixava a suíte verde (provado por mutação na revisão final). Desescapar o
// `\n` antes de casar é o que faz o teste enxergar o control como o dpkg vai
// enxergá-lo.
func controlFields(s string) [][]string {
	return controlFieldRe.FindAllStringSubmatch(strings.ReplaceAll(s, `\n`, "\n"), -1)
}

// A base em Depends: faz `dpkg -i` numa máquina pelada parar em `iU`: o
// pacote não é configurado, o serviço nunca sobe e não sobra painel para
// explicar o que houve — e o postinst não pode resolver isso sozinho, porque
// o dpkg segura o lock durante toda a execução.
func TestABaseFicaEmRecommendsNuncaEmDepends(t *testing.T) {
	mk := readRepoFile(t, "Makefile")
	fields := controlFields(mk)
	// Sem esta asserção o teste volta a ser vacuoso em silêncio no dia em que
	// alguém mudar COMO o control é emitido (heredoc, arquivo próprio,
	// variável) e a regex parar de casar: zero campos passa o laço abaixo
	// sem uma queixa.
	if len(fields) == 0 {
		t.Fatal("nenhum campo de relação encontrado no Makefile: ou o control deixou de declarar " +
			"Recommends:, ou mudou a forma de emiti-lo e este guarda ficou cego — conferir controlFields")
	}
	for _, m := range fields {
		if m[1] != "Recommends" {
			t.Errorf("o Makefile declara %s: %s — a base tem que ficar em Recommends:", m[1], m[2])
		}
	}
	recommends := debRecommends(t)
	for _, pkg := range bootstrapdeps.BasePackages {
		if !recommends[pkg] {
			t.Errorf("%s está em bootstrapdeps.BasePackages (o LinkGuard instala sozinho no boot) "+
				"mas não em Recommends: — `apt install ./linkguard-fw.deb` não o traria", pkg)
		}
	}
	// Os pacotes sob demanda: o admin que instala pelo apt (o caminho normal)
	// já recebe tudo e nunca chega a esperar por um download no painel.
	for _, pkg := range []string{"kea-dhcp4-server", "unbound", "dns-root-data", "chrony"} {
		if !recommends[pkg] {
			t.Errorf("%s é instalado sob demanda pelo LinkGuard e devia estar em Recommends:", pkg)
		}
	}
}

func debRecommends(t *testing.T) map[string]bool {
	t.Helper()
	mk := readRepoFile(t, "Makefile")
	re := regexp.MustCompile(`(?m)^DEB_RECOMMENDS\s*:?=\s*(.+)$`)
	m := re.FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("DEB_RECOMMENDS não encontrado no Makefile — a fonte única do control sumiu")
	}
	out := map[string]bool{}
	for _, p := range strings.Split(m[1], ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

// O defeito que barrou o deploy: o workflow de release montava o próprio
// DEBIAN/control e continuava dizendo `Depends: nftables, iproute2, ...`. O
// produto é entregue por release e por auto-update, então o artefato que
// chega ao firewall era justamente o que ainda tinha o defeito — e sem
// dns-root-data.
func TestControlFieldsAreSingleSourced(t *testing.T) {
	wf := readRepoFile(t, ".github/workflows/release.yml")

	if fields := controlFields(wf); len(fields) > 0 {
		m := fields[0]
		t.Errorf("o workflow de release declara %s: %s por conta própria. "+
			"O control tem uma fonte única (DEB_RECOMMENDS, no Makefile); duas cópias já divergiram "+
			"uma vez e o .deb oficial ficou parando em `iU` numa máquina pelada", m[1], m[2])
	}
	if !strings.Contains(wf, "make deb-from-binary") {
		t.Error("o workflow de release não empacota pelo Makefile: sem isso não existe fonte única de control")
	}
	if strings.Contains(wf, "dpkg-deb --build") {
		t.Error("o workflow de release voltou a montar o pacote por conta própria em vez de chamar o Makefile")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A MENSAGEM FINAL DO POSTINST TEM QUE DESCREVER O QUE ACABOU DE ACONTECER.
//
// Até 2026-08-31 as duas últimas linhas saíam sempre. Num upgrade o pacote
// reiniciava o serviço e, na linha seguinte, mandava habilitá-lo — negando a
// própria ação anterior. Foi visto num deploy real do firewall de produção
// (v1.0.186 → v1.0.192), e num firewall essa é a classe de mensagem que faz
// alguém mexer no que já estava certo.
//
// Este teste RODA o postinst em vez de ler o texto dele. Ler o texto provaria
// que as palavras mudaram; rodar prova que a decisão mudou — que é o que
// falhou. Só o CONFIG_DIR é redirecionado; o resto do script é o de produção.
// ─────────────────────────────────────────────────────────────────────────────

// runPostinst executa o postinst com um systemctl de mentira e devolve a saída.
// `enabled` diz o que o `systemctl is-enabled` vai responder; `oldVersion` é o
// `$2` do dpkg — vazio significa instalação nova.
func runPostinst(t *testing.T, enabled bool, oldVersion string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("o postinst é script de pacote Debian")
	}

	bin := t.TempDir()
	code := 1
	if enabled {
		code = 0
	}
	// O dublê registra o que foi chamado e responde ao is-enabled conforme o
	// caso sob teste. `daemon-reload` e `restart` viram no-op.
	stub := "#!/bin/sh\ncase \"$1\" in\n  is-enabled) exit " +
		strconv.Itoa(code) + " ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatalf("escrever systemctl de mentira: %v", err)
	}

	args := []string{filepath.Join(repoRoot(t), "deploy/deb/postinst"), "configure"}
	if oldVersion != "" {
		args = append(args, oldVersion)
	}
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"LINKGUARD_CONFIG_DIR="+t.TempDir(),
		"LINKGUARD_DATA_DIR="+t.TempDir(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("postinst falhou: %v\n%s", err, out)
	}
	return string(out)
}

func TestOPostinstNaoMandaHabilitarOQueAcabouDeReiniciar(t *testing.T) {
	out := runPostinst(t, true, "1.0.186")

	if strings.Contains(out, "enable --now") {
		t.Errorf("o postinst reiniciou o serviço e ainda assim mandou habilitá-lo:\n%s", out)
	}
	if !strings.Contains(out, "restarted") {
		t.Errorf("o upgrade não disse que reiniciou o serviço, que é a única coisa que o "+
			"admin precisa saber para não ir mexer:\n%s", out)
	}
	if !strings.Contains(out, "1.0.186") {
		t.Errorf("o upgrade não disse de qual versão veio:\n%s", out)
	}
}

func TestOPostinstAindaOrientaNaInstalacaoNova(t *testing.T) {
	// A metade de silêncio deste par: consertar o upgrade não pode calar a
	// instalação nova, onde o serviço REALMENTE não está habilitado e a
	// orientação é a única coisa que faz o produto subir.
	out := runPostinst(t, false, "")

	if !strings.Contains(out, "enable --now") {
		t.Errorf("a instalação nova deixou de dizer como subir o serviço:\n%s", out)
	}
	if strings.Contains(out, "upgraded") {
		t.Errorf("a instalação nova se anunciou como upgrade:\n%s", out)
	}
}

func TestOPostinstAvisaOUpgradeComServicoDesabilitado(t *testing.T) {
	// Terceiro caso, e o que a lógica antiga acertava por acidente: upgrade
	// numa máquina onde o serviço nunca foi habilitado. Aqui a orientação
	// PRECISA sair — e não pode se disfarçar de instalação nova.
	out := runPostinst(t, false, "1.0.186")

	if !strings.Contains(out, "enable --now") {
		t.Errorf("upgrade com serviço desabilitado precisa dizer como habilitá-lo:\n%s", out)
	}
	if strings.Contains(out, "restarted") {
		t.Errorf("nada foi reiniciado, mas a mensagem diz que sim:\n%s", out)
	}
}
