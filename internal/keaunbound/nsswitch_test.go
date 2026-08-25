package keaunbound

import (
	"strings"
	"testing"
)

// resolvedDePe / resolvedParado são os dois predicados de módulo inerte que
// interessam: o systemd-resolved de pé (o módulo `resolve` corta) e parado (ele
// devolve UNAVAIL e não corta).
func resolvedDePe(string) bool { return false }

func resolvedParado(nome string) bool { return nome == ModuloResolved }

// TestAnalisarCaminhoNSS é o teste de mesa da pergunta que a issue #195 abriu: o
// resolv.conf que o produto escreve chega a ser consultado nesta máquina?
//
// As duas primeiras linhas não são inventadas — são as das máquinas de verdade.
// A de produção resolve pelo unbound (medido: o contador do unbound sobe num
// getent); a da VM de validação não (medido: não sobe). Um analisador que não
// separe essas duas linhas não serve para nada.
func TestAnalisarCaminhoNSS(t *testing.T) {
	casos := []struct {
		nome       string
		conteudo   string
		inerte     func(string) bool
		estado     EstadoNSS
		cortadoPor string
	}{
		{
			nome:     "producao: files dns",
			conteudo: "passwd: files\nhosts:          files dns\nnetworks:       files\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:       "VM de validacao: resolve corta antes do dns",
			conteudo:   "hosts: files myhostname resolve [!UNAVAIL=return] dns\n",
			inerte:     resolvedDePe,
			estado:     NSSCortadoAntesDoDNS,
			cortadoPor: "resolve",
		},
		{
			nome:     "resolve sem acao de corte: a busca desce ate o dns",
			conteudo: "hosts: files myhostname resolve dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "dns antes do resolve: o corte vem tarde demais para atrapalhar",
			conteudo: "hosts: files dns resolve [!UNAVAIL=return]\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "linha hosts ausente: a glibc usa o padrao embutido, que tem dns",
			conteudo: "passwd: files\ngroup: files\nshadow: files\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "arquivo vazio: mesmo caso da linha ausente",
			conteudo: "",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "linha hosts sem dns nenhum: ninguem le o resolv.conf",
			conteudo: "hosts: files myhostname\n",
			inerte:   resolvedDePe,
			estado:   NSSSemModuloDNS,
		},
		{
			nome:     "mdns4_minimal com NOTFOUND=return: a linha padrao com avahi NAO quebra",
			conteudo: "hosts: files mdns4_minimal [NOTFOUND=return] dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:       "NOTFOUND=return num modulo generico corta",
			conteudo:   "hosts: files myhostname resolve [NOTFOUND=return] dns\n",
			inerte:     resolvedDePe,
			estado:     NSSCortadoAntesDoDNS,
			cortadoPor: "resolve",
		},
		{
			nome:       "combinacao equivalente ao !UNAVAIL=return, com espaco dentro dos colchetes",
			conteudo:   "hosts: files resolve [SUCCESS=return NOTFOUND=return TRYAGAIN=return] dns\n",
			inerte:     resolvedDePe,
			estado:     NSSCortadoAntesDoDNS,
			cortadoPor: "resolve",
		},
		{
			nome:     "SUCCESS=return sozinho e o padrao da glibc: nao corta",
			conteudo: "hosts: files resolve [SUCCESS=return] dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "!NOTFOUND=return deixa justamente o negativo continuar: nao corta",
			conteudo: "hosts: files resolve [!NOTFOUND=return] dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "UNAVAIL=return sozinho nao corta: NOTFOUND continua descendo",
			conteudo: "hosts: files resolve [UNAVAIL=return] dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:       "maiusculas e tabs, como o Debian escreve",
			conteudo:   "HOSTS:\tfiles\tmyhostname\tresolve\t[!UNAVAIL=RETURN]\tdns\n",
			inerte:     resolvedDePe,
			estado:     NSSCortadoAntesDoDNS,
			cortadoPor: "resolve",
		},
		{
			nome:     "linha comentada nao vale: a que vale e a de baixo",
			conteudo: "# hosts: files myhostname resolve [!UNAVAIL=return] dns\nhosts: files dns\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:     "comentario no fim da linha nao entra na analise",
			conteudo: "hosts: files dns # mexido a mao\n",
			inerte:   resolvedDePe,
			estado:   NSSAlcancaDNS,
		},
		{
			nome:       "duas linhas hosts: vale a primeira, que e a que a glibc usa",
			conteudo:   "hosts: files myhostname resolve [!UNAVAIL=return] dns\nhosts: files dns\n",
			inerte:     resolvedDePe,
			estado:     NSSCortadoAntesDoDNS,
			cortadoPor: "resolve",
		},
		{
			nome:     "sem predicado de inercia: o corte vale como esta escrito",
			conteudo: "hosts: files resolve [!UNAVAIL=return] dns\n",
			inerte:   nil,
			estado:   NSSCortadoAntesDoDNS,
			// CortadoPor confere no laço abaixo.
			cortadoPor: "resolve",
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			got := AnalisarCaminhoNSS(c.conteudo, c.inerte)
			if got.Estado != c.estado {
				t.Errorf("Estado = %v, queria %v (motivo: %s)", got.Estado, c.estado, got.Motivo)
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

// TestArquivoMalformadoNaoViraVeredito e o defeito P2: colchete sem fechar fazia
// o parser parar no meio da linha e o analisador concluir "nao lista o modulo
// dns" — sobre uma linha que LISTA o dns logo depois do ponto em que ele parou.
// O alerta saia afirmando algo que o proprio arquivo citado no detalhe
// desmente. Nao saber nao e estar quebrado: nem abre nem fecha.
func TestArquivoMalformadoNaoViraVeredito(t *testing.T) {
	got := AnalisarCaminhoNSS("hosts: files resolve [!UNAVAIL=return dns\n", resolvedDePe)

	if got.Estado != NSSIndeterminado {
		t.Errorf("Estado = %v, queria NSSIndeterminado (motivo: %s)", got.Estado, got.Motivo)
	}
	if got.Quebrado() {
		t.Error("um arquivo que o parser nao conseguiu ler inteiro esta abrindo alerta")
	}
	if strings.Contains(got.Motivo, "não lista o módulo dns") {
		t.Errorf("o motivo afirma sobre a parte da linha que nao foi lida: %q", got.Motivo)
	}
}

// TestLinhaHostsVaziaNaoViraVeredito: `hosts:` sem servico nenhum e a mesma
// familia da linha ausente — nao ha modulo para analisar. Com o caso sem dns
// valendo Critical, tratar isto como "sem dns" seria um Critical falso.
func TestLinhaHostsVaziaNaoViraVeredito(t *testing.T) {
	got := AnalisarCaminhoNSS("hosts:\n", resolvedDePe)

	if got.Estado != NSSIndeterminado {
		t.Errorf("Estado = %v, queria NSSIndeterminado (motivo: %s)", got.Estado, got.Motivo)
	}
}

// TestModuloInerteNaoBranqueiaORestoDaLinha e o defeito P1, e e o mais grave dos
// cinco: com o systemd-resolved parado a analise RETORNAVA no modulo `resolve`
// dizendo "alcanca o dns" e o produto FECHAVA o alerta — numa linha em que o
// `nis [NOTFOUND=return]` logo adiante continua encerrando a busca. Anunciar
// saude numa caixa quebrada e pior que nao anunciar nada.
func TestModuloInerteNaoBranqueiaORestoDaLinha(t *testing.T) {
	const linha = "hosts: files myhostname resolve [!UNAVAIL=return] nis [NOTFOUND=return] dns\n"

	got := AnalisarCaminhoNSS(linha, resolvedParado)

	if got.Estado != NSSCortadoAntesDoDNS {
		t.Fatalf("Estado = %v, queria NSSCortadoAntesDoDNS (motivo: %s)", got.Estado, got.Motivo)
	}
	if got.CortadoPor != "nis" {
		t.Errorf("CortadoPor = %q, queria \"nis\": a varredura tem de seguir a partir do modulo inerte", got.CortadoPor)
	}
}

// TestModuloInerteSemDNSAdianteEhOCasoGrave e a outra metade do P1: a linha da
// VM sem o `dns` no fim. Com o resolved parado o `resolve` nao corta, mas nao ha
// mais nada depois dele — a caixa nao resolve nome externo algum, e o produto
// anunciava que o resolv.conf estava valendo.
func TestModuloInerteSemDNSAdianteEhOCasoGrave(t *testing.T) {
	got := AnalisarCaminhoNSS("hosts: files myhostname resolve [!UNAVAIL=return]\n", resolvedParado)

	if got.Estado != NSSSemModuloDNS {
		t.Fatalf("Estado = %v, queria NSSSemModuloDNS (motivo: %s)", got.Estado, got.Motivo)
	}
	if !got.Quebrado() {
		t.Error("uma linha sem modulo dns nenhum nao esta abrindo alerta")
	}
}

// TestChegarAoDNSPorModuloInerteNaoEhVeredictoDeSaude e o defeito P3: a linha da
// VM com o systemd-resolved parado chega ao dns HOJE, e so por um estado que nao
// esta no arquivo — o daemon volta no proximo boot sem ninguem tocar neste
// produto. Fechar alerta ali e anunciar um conserto que ninguem fez, e o alerta
// volta a piscar no reboot seguinte. Abrir exige certeza; fechar tambem.
func TestChegarAoDNSPorModuloInerteNaoEhVeredictoDeSaude(t *testing.T) {
	got := AnalisarCaminhoNSS("hosts: files myhostname resolve [!UNAVAIL=return] dns\n", resolvedParado)

	if got.Estado != NSSIndeterminado {
		t.Fatalf("Estado = %v, queria NSSIndeterminado (motivo: %s)", got.Estado, got.Motivo)
	}
	if got.Quebrado() {
		t.Error("veredito indeterminado nao pode abrir alerta")
	}
	if got.CortadoPor != ModuloResolved {
		t.Errorf("CortadoPor = %q: o motivo tem de nomear o modulo que deixou a resposta em suspenso", got.CortadoPor)
	}
}

// TestOMotivoDoCorteNaoAfirmaQueOModuloRespondeu e o defeito P5(b): o motivo
// dizia "o modulo X responde antes do dns". "Responde" e inferencia estrutural,
// nao medicao — quem foi lido foi o ARQUIVO. Um `nis [NOTFOUND=return]` numa
// caixa sem NIS devolve UNAVAIL e a cadeia desce ate o dns.
func TestOMotivoDoCorteNaoAfirmaQueOModuloRespondeu(t *testing.T) {
	got := AnalisarCaminhoNSS("hosts: files nis [NOTFOUND=return] dns\n", resolvedDePe)

	if got.Estado != NSSCortadoAntesDoDNS {
		t.Fatalf("Estado = %v, queria NSSCortadoAntesDoDNS", got.Estado)
	}
	if strings.Contains(got.Motivo, "responde") {
		t.Errorf("o motivo afirma comportamento que ninguem mediu: %q", got.Motivo)
	}
	if !strings.Contains(got.Motivo, "linha hosts:") {
		t.Errorf("o motivo nao deixa claro que a fonte e a linha do arquivo: %q", got.Motivo)
	}
	if !strings.Contains(got.Motivo, "NOTFOUND=return") {
		t.Errorf("o motivo perdeu a acao que encerra a busca: %q", got.Motivo)
	}
}

// TestAnalisarCaminhoNSSGuardaALinhaDeVerdade: o alerta e o log carregam a linha
// como ela esta no arquivo. Uma parafrase manda o admin procurar outra coisa.
func TestAnalisarCaminhoNSSGuardaALinhaDeVerdade(t *testing.T) {
	const linha = "files myhostname resolve [!UNAVAIL=return] dns"
	got := AnalisarCaminhoNSS("hosts:   "+linha+"\n", resolvedDePe)
	if got.Hosts != linha {
		t.Errorf("Hosts = %q, queria %q", got.Hosts, linha)
	}
	if !got.Achou {
		t.Error("Achou = false com linha hosts: presente")
	}
}
