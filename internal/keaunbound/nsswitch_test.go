package keaunbound

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnalisarHostsNSS é o teste de mesa da pergunta que a issue #195 abriu: o
// resolv.conf que o produto escreve chega a ser consultado nesta máquina?
//
// As duas primeiras linhas não são inventadas — são as das máquinas de verdade.
// A de produção resolve pelo unbound (medido: o contador do unbound sobe num
// getent); a da VM de validação não (medido: não sobe). Um analisador que não
// separe essas duas linhas não serve para nada.
func TestAnalisarHostsNSS(t *testing.T) {
	casos := []struct {
		nome       string
		conteudo   string
		alcancavel bool
		cortadoPor string
	}{
		{
			nome:       "producao: files dns",
			conteudo:   "passwd: files\nhosts:          files dns\nnetworks:       files\n",
			alcancavel: true,
		},
		{
			nome:       "VM de validacao: resolve corta antes do dns",
			conteudo:   "hosts: files myhostname resolve [!UNAVAIL=return] dns\n",
			alcancavel: false,
			cortadoPor: "resolve",
		},
		{
			nome:       "resolve sem acao de corte: a busca desce ate o dns",
			conteudo:   "hosts: files myhostname resolve dns\n",
			alcancavel: true,
		},
		{
			nome:       "dns antes do resolve: o corte vem tarde demais para atrapalhar",
			conteudo:   "hosts: files dns resolve [!UNAVAIL=return]\n",
			alcancavel: true,
		},
		{
			nome:       "linha hosts ausente: a glibc usa o padrao embutido, que tem dns",
			conteudo:   "passwd: files\ngroup: files\nshadow: files\n",
			alcancavel: true,
		},
		{
			nome:       "arquivo vazio: mesmo caso da linha ausente",
			conteudo:   "",
			alcancavel: true,
		},
		{
			nome:       "linha hosts sem dns nenhum: o resolv.conf nao e lido por ninguem",
			conteudo:   "hosts: files myhostname\n",
			alcancavel: false,
		},
		{
			nome:       "mdns4_minimal com NOTFOUND=return: a linha padrao com avahi NAO quebra",
			conteudo:   "hosts: files mdns4_minimal [NOTFOUND=return] dns\n",
			alcancavel: true,
		},
		{
			nome:       "NOTFOUND=return num modulo generico corta",
			conteudo:   "hosts: files myhostname resolve [NOTFOUND=return] dns\n",
			alcancavel: false,
			cortadoPor: "resolve",
		},
		{
			nome:       "combinacao equivalente ao !UNAVAIL=return, com espaco dentro dos colchetes",
			conteudo:   "hosts: files resolve [SUCCESS=return NOTFOUND=return TRYAGAIN=return] dns\n",
			alcancavel: false,
			cortadoPor: "resolve",
		},
		{
			nome:       "SUCCESS=return sozinho e o padrao da glibc: nao corta",
			conteudo:   "hosts: files resolve [SUCCESS=return] dns\n",
			alcancavel: true,
		},
		{
			nome:       "!NOTFOUND=return deixa justamente o negativo continuar: nao corta",
			conteudo:   "hosts: files resolve [!NOTFOUND=return] dns\n",
			alcancavel: true,
		},
		{
			nome:       "UNAVAIL=return sozinho nao corta: NOTFOUND continua descendo",
			conteudo:   "hosts: files resolve [UNAVAIL=return] dns\n",
			alcancavel: true,
		},
		{
			nome:       "maiusculas e tabs, como o Debian escreve",
			conteudo:   "HOSTS:\tfiles\tmyhostname\tresolve\t[!UNAVAIL=RETURN]\tdns\n",
			alcancavel: false,
			cortadoPor: "resolve",
		},
		{
			nome:       "linha comentada nao vale: a que vale e a de baixo",
			conteudo:   "# hosts: files myhostname resolve [!UNAVAIL=return] dns\nhosts: files dns\n",
			alcancavel: true,
		},
		{
			nome:       "comentario no fim da linha nao entra na analise",
			conteudo:   "hosts: files dns # mexido a mao\n",
			alcancavel: true,
		},
		{
			nome:       "duas linhas hosts: vale a primeira, que e a que a glibc usa",
			conteudo:   "hosts: files myhostname resolve [!UNAVAIL=return] dns\nhosts: files dns\n",
			alcancavel: false,
			cortadoPor: "resolve",
		},
		{
			nome:       "colchete sem fechar: para de analisar em vez de inventar modulo",
			conteudo:   "hosts: files resolve [!UNAVAIL=return dns\n",
			alcancavel: false,
			cortadoPor: "",
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			got := analisarHostsNSS(c.conteudo)
			if got.Alcancavel != c.alcancavel {
				t.Errorf("Alcancavel = %v, queria %v (motivo: %s)", got.Alcancavel, c.alcancavel, got.Motivo)
			}
			if got.CortadoPor != c.cortadoPor {
				t.Errorf("CortadoPor = %q, queria %q", got.CortadoPor, c.cortadoPor)
			}
			if got.Motivo == "" {
				t.Error("o veredito veio sem motivo; ele vai para o log e para o alerta, e sem ele o aviso nao tem proximo passo")
			}
		})
	}
}

// TestAnalisarHostsNSSGuardaALinhaDeVerdade: o alerta e o log carregam a linha
// como ela esta no arquivo. Uma parafrase manda o admin procurar outra coisa.
func TestAnalisarHostsNSSGuardaALinhaDeVerdade(t *testing.T) {
	const linha = "files myhostname resolve [!UNAVAIL=return] dns"
	got := analisarHostsNSS("hosts:   " + linha + "\n")
	if got.Hosts != linha {
		t.Errorf("Hosts = %q, queria %q", got.Hosts, linha)
	}
	if !got.Achou {
		t.Error("Achou = false com linha hosts: presente")
	}
}

// alerterFalso conta as duas pontas do par de alertas.
type alerterFalso struct {
	abriu    int
	fechou   int
	detalhes []string
}

func (a *alerterFalso) CaminhoDNSForaDoLocal(detalhe string) error {
	a.abriu++
	a.detalhes = append(a.detalhes, detalhe)
	return nil
}

func (a *alerterFalso) CaminhoDNSNoLocal() {
	a.fechou++
}

// execCaminho e o recExec com a resposta de systemctl que a verificacao do
// caminho de resolucao consulta a mais.
type execCaminho struct {
	*recExec
	resolvedAtivo bool
}

func (e *execCaminho) ExecuteRead(ctx context.Context, cmd string, args ...string) (string, error) {
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-active" && args[1] == "systemd-resolved" {
		if e.resolvedAtivo {
			return "active\n", nil
		}
		// systemctl is-active sai com codigo diferente de zero quando a
		// unidade nao esta de pe — inclusive quando ela nem existe, que e o
		// caso da maquina de producao.
		return "inactive\n", os.ErrNotExist
	}
	return e.recExec.ExecuteRead(ctx, cmd, args...)
}

func servicoDeCaminho(t *testing.T, nsswitch string, resolvedAtivo, unboundLigado bool) (*Service, *alerterFalso) {
	t.Helper()
	dir := t.TempDir()
	s := NewService(&execCaminho{recExec: &recExec{unboundEnabled: unboundLigado}, resolvedAtivo: resolvedAtivo})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")
	s.nsswitchConf = filepath.Join(dir, "nsswitch.conf")
	if nsswitch != "" {
		if err := os.WriteFile(s.nsswitchConf, []byte(nsswitch), 0o644); err != nil {
			t.Fatalf("preparar nsswitch.conf: %v", err)
		}
	}
	a := &alerterFalso{}
	s.SetAlerter(a)
	return s, a
}

const hostsVM = "hosts: files myhostname resolve [!UNAVAIL=return] dns\n"

// TestCaminhoNSSAlertaQuandoOResolveCorta e o caso da VM de validacao: o
// produto escreve o resolv.conf e a resolucao da caixa nao passa por la. Antes
// desta issue ele logava INFO dizendo que o resolver local estava valendo —
// uma afirmacao falsa, e da pior especie: a que ninguem confere.
func TestCaminhoNSSAlertaQuandoOResolveCorta(t *testing.T) {
	s, a := servicoDeCaminho(t, hostsVM, true, true)

	s.EnsureResolvConf(context.Background())

	if a.abriu != 1 {
		t.Fatalf("alertas abertos = %d, queria 1", a.abriu)
	}
	if a.fechou != 0 {
		t.Errorf("fechou o alerta numa caixa quebrada (%d vezes)", a.fechou)
	}
	if !strings.Contains(a.detalhes[0], "resolve") {
		t.Errorf("o detalhe nao nomeia quem corta a cadeia: %q", a.detalhes[0])
	}
	if !strings.Contains(a.detalhes[0], "!UNAVAIL=return") {
		t.Errorf("o detalhe nao carrega a acao que corta: %q", a.detalhes[0])
	}
	if !strings.Contains(a.detalhes[0], "systemd-resolved") {
		t.Errorf("o detalhe nao diz que o systemd-resolved esta ativo: %q", a.detalhes[0])
	}
}

// TestCaminhoNSSFechaNaLinhaDeProducao: files dns com o systemd-resolved fora
// do ar e a producao de hoje, e ali o resolver local esta mesmo valendo. Um
// alerta aqui seria alarme falso.
func TestCaminhoNSSFechaNaLinhaDeProducao(t *testing.T) {
	s, a := servicoDeCaminho(t, "hosts: files dns\n", false, true)

	s.EnsureResolvConf(context.Background())

	if a.abriu != 0 {
		t.Errorf("abriu alerta numa caixa boa (%d vezes): %v", a.abriu, a.detalhes)
	}
	if a.fechou != 1 {
		t.Errorf("alertas fechados = %d, queria 1", a.fechou)
	}
}

// TestCaminhoNSSNaoAlertaComResolvedParado: o corte pelo resolve so corta se o
// systemd-resolved estiver de pe — parado, ele devolve UNAVAIL e a cadeia segue
// ate o dns. Alertar aqui seria dizer que esta quebrado o que funciona.
func TestCaminhoNSSNaoAlertaComResolvedParado(t *testing.T) {
	s, a := servicoDeCaminho(t, hostsVM, false, true)

	s.EnsureResolvConf(context.Background())

	if a.abriu != 0 {
		t.Errorf("abriu alerta com o systemd-resolved parado (%d vezes): %v", a.abriu, a.detalhes)
	}
	if a.fechou != 1 {
		t.Errorf("alertas fechados = %d, queria 1", a.fechou)
	}
}

// TestCaminhoNSSNaoAlertaQuandoNaoDaParaLer: nao saber nao e a mesma coisa que
// estar quebrado. Sem o arquivo em maos, abrir alerta inventa um defeito e
// fechar alerta desmente um defeito que talvez esteja la — as duas coisas sao
// mentira. O certo e nao mexer no estado do alerta.
func TestCaminhoNSSNaoAlertaQuandoNaoDaParaLer(t *testing.T) {
	s, a := servicoDeCaminho(t, "", false, true) // o nsswitch.conf nem existe

	s.EnsureResolvConf(context.Background())

	if a.abriu != 0 || a.fechou != 0 {
		t.Errorf("mexeu no alerta sem conseguir ler o nsswitch.conf: abriu=%d fechou=%d", a.abriu, a.fechou)
	}
}

// TestCaminhoNSSSemAlerterNaoQuebra: o alerter e opcional (dry-run, testes de
// outros pacotes). A verificacao tem de rodar e ir para o log do mesmo jeito.
func TestCaminhoNSSSemAlerterNaoQuebra(t *testing.T) {
	s, _ := servicoDeCaminho(t, hostsVM, true, true)
	s.SetAlerter(nil)

	s.EnsureResolvConf(context.Background())
}

// TestCaminhoNSSNaoAlertaSemUnbound: com o unbound fora do ar o produto nem
// toca no resolv.conf, entao nao ha o que afirmar sobre o caminho ate ele.
func TestCaminhoNSSNaoAlertaSemUnbound(t *testing.T) {
	s, a := servicoDeCaminho(t, hostsVM, true, false)

	s.EnsureResolvConf(context.Background())

	if a.abriu != 0 || a.fechou != 0 {
		t.Errorf("mexeu no alerta sem o resolver local no ar: abriu=%d fechou=%d", a.abriu, a.fechou)
	}
}
