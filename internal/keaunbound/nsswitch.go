package keaunbound

import (
	"fmt"
	"strings"
)

// NsswitchPath é o arquivo que decide POR ONDE passa a resolução de nome da
// própria caixa. O /etc/resolv.conf só entra na história se a busca chegar ao
// módulo `dns` do NSS; quem diz se ela chega é este arquivo, e nada no produto
// olhava para ele (issue #195). Sem esta verificação o produto reescreve o
// resolv.conf, anuncia que o resolver local está valendo, e não está.
const NsswitchPath = "/etc/nsswitch.conf"

// ModuloResolved é o módulo NSS do systemd-resolved.
//
// Ele é o único módulo comum cujo "corta a cadeia" depende de um estado que NÃO
// está no arquivo: com o systemd-resolved parado, o módulo devolve UNAVAIL, e
// aí a ação [!UNAVAIL=return] justamente não corta — a busca segue adiante. Ver
// o parâmetro moduloInerte de AnalisarCaminhoNSS e quem o preenche
// (monitoring.Collector.checkCaminhoNSS).
const ModuloResolved = "resolve"

// EstadoNSS é o veredito sobre a linha `hosts:`.
//
// O zero é NSSIndeterminado de propósito: um CaminhoNSS que ninguém preencheu
// não pode significar "está tudo bem" nem "está quebrado". Nesta checagem os
// dois erros custam caro — abrir alerta inventa defeito, fechar alerta desmente
// defeito de verdade —, então o valor que sai de graça tem de ser o único que
// não mexe em alerta nenhum.
type EstadoNSS int

const (
	// NSSIndeterminado: não dá para dizer. Arquivo malformado, linha vazia, ou
	// o veredito dependeria de um módulo inerte AGORA (ver moduloInerte). Não
	// abre nem fecha alerta.
	NSSIndeterminado EstadoNSS = iota
	// NSSAlcancaDNS: com certeza a busca chega ao módulo dns. O resolv.conf que
	// o produto escreve vale alguma coisa nesta caixa.
	NSSAlcancaDNS
	// NSSCortadoAntesDoDNS: com certeza um módulo encerra a busca antes do dns.
	// O módulo que corta está ANTES do dns na linha, ou seja: existe alguém
	// respondendo por esses nomes — a caixa resolve, só que por fora do unbound.
	NSSCortadoAntesDoDNS
	// NSSSemModuloDNS: a linha inteira foi percorrida e não há módulo dns
	// nenhum. É o caso grave: ninguém lê o resolv.conf, e como a varredura
	// passou por todos os módulos sem encontrar um que responda e corte, não há
	// nada nesta linha que resolva nome externo.
	NSSSemModuloDNS
)

// CaminhoNSS é o veredito sobre a linha `hosts:` do nsswitch.conf: o módulo
// `dns` (o único que consulta o resolv.conf) é alcançado numa resolução comum?
type CaminhoNSS struct {
	// Hosts é a linha `hosts:` como está no arquivo, já sem o rótulo e sem
	// comentário. Vai inteira para o log e para o alerta: quem lê precisa ver
	// o que a máquina tem escrito, não a nossa paráfrase disso.
	Hosts string
	// Achou diz se havia uma linha `hosts:` para analisar.
	Achou bool
	// Estado é a resposta da pergunta. Ver EstadoNSS.
	Estado EstadoNSS
	// CortadoPor nomeia o módulo que encerra a busca antes do dns, quando é
	// esse o motivo. Também nomeia o módulo inerte quando é ele que deixa o
	// veredito indeterminado. Vazio nos demais casos.
	CortadoPor string
	// Motivo é a frase pronta, em português, para o log e para o alerta.
	Motivo string
}

// Quebrado diz se este veredito é de defeito CERTO — o único que abre alerta.
func (c CaminhoNSS) Quebrado() bool {
	return c.Estado == NSSCortadoAntesDoDNS || c.Estado == NSSSemModuloDNS
}

// AnalisarCaminhoNSS decide, a partir do TEXTO do nsswitch.conf, se o módulo
// `dns` é alcançado numa resolução de nome comum.
//
// Pura de propósito: é a única parte disto que dá para provar em teste de mesa
// com as linhas reais das máquinas que interessam — a de produção
// (`hosts: files dns`) e a da VM de validação
// (`hosts: files myhostname resolve [!UNAVAIL=return] dns`). Ler o arquivo e
// perguntar ao systemd ficam de fora, no chamador, porque nenhum dos dois é
// reproduzível numa tabela de casos. Por isso o estado de fora do arquivo entra
// como PREDICADO e não como consulta: moduloInerte(nome) responde "este módulo
// não está respondendo agora", e o teste de mesa preenche isso com uma função
// de uma linha.
//
// O que moduloInerte faz com a varredura é o ponto delicado, e a versão
// anterior errou nele: um módulo inerte NÃO corta, mas isso não branqueia o
// resto da linha. A varredura CONTINUA a partir dele, porque quem vem depois
// pode cortar do mesmo jeito (`resolve [!UNAVAIL=return] nis [NOTFOUND=return]
// dns`) ou pode simplesmente não existir (`resolve [!UNAVAIL=return]`, sem dns
// nenhum). Retornar "alcançável" no primeiro módulo inerte era anunciar saúde
// numa caixa quebrada — e, pior, FECHAR o alerta lá.
//
// Ausência de linha `hosts:` NÃO é defeito: a glibc cai num padrão embutido
// que consulta o dns. Dizer "quebrado" aí seria alarme falso.
func AnalisarCaminhoNSS(conteudo string, moduloInerte func(nome string) bool) CaminhoNSS {
	hosts, achou := linhaHostsNSS(conteudo)
	if !achou {
		return CaminhoNSS{
			Estado: NSSAlcancaDNS,
			Motivo: "o nsswitch.conf não tem linha hosts:; a glibc usa o padrão embutido, que consulta o dns",
		}
	}

	modulos, malformado := modulosNSS(hosts)
	if malformado {
		// Não saber não é estar quebrado. O parser parou; a linha pode listar o
		// dns logo depois do ponto em que ele parou — e afirmar "não lista o
		// módulo dns" sobre uma linha que lista seria um alerta desmentido pelo
		// próprio arquivo que ele manda o admin abrir.
		return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSIndeterminado,
			Motivo: "a linha hosts: tem colchete sem fechar; o arquivo não dá para analisar com honestidade"}
	}
	if len(modulos) == 0 {
		// `hosts:` sem serviço nenhum é a mesma família da linha ausente: não há
		// o que analisar. Com o caso grave valendo Critical (ver NSSSemModuloDNS),
		// tratar isto como "sem dns" seria um Critical falso vindo de uma linha
		// que não diz nada.
		return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSIndeterminado,
			Motivo: "a linha hosts: está vazia; não há módulo para analisar"}
	}

	// inerteIgnorado guarda o módulo cujo corte foi desconsiderado por estar
	// inerte. Se a busca chegar ao dns SÓ por causa disso, o veredito não é
	// "alcança": é "hoje alcança, por um estado que não está no arquivo".
	inerteIgnorado := ""
	for _, m := range modulos {
		if m.Nome == "dns" {
			if inerteIgnorado != "" {
				return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSIndeterminado, CortadoPor: inerteIgnorado,
					Motivo: fmt.Sprintf("a linha hosts: só chega ao dns porque o módulo %q está sem o daemon de pé agora; de pé, a ação dele encerra a busca antes", inerteIgnorado)}
			}
			return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSAlcancaDNS,
				Motivo: "o módulo dns é alcançado na linha hosts:"}
		}
		if !moduloEncerraBusca(m) {
			continue
		}
		if moduloInerte != nil && moduloInerte(m.Nome) {
			inerteIgnorado = m.Nome
			continue
		}
		return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSCortadoAntesDoDNS, CortadoPor: m.Nome,
			// "indica que encerra" e não "responde e encerra": o que se leu foi
			// a LINHA, não uma resolução. Um módulo com ação de corte só corta
			// de fato quando responde, e se ele não estiver respondendo a
			// cadeia desce. A frase diz o que foi medido — o arquivo — e deixa
			// a inferência visível para quem vai conferir.
			Motivo: fmt.Sprintf("a linha hosts: põe o módulo %q antes do dns com a ação [%s], que encerra a busca ali", m.Nome, m.Acoes)}
	}

	// Percorreu a linha inteira: não há módulo dns. Ninguém aqui lê o
	// resolv.conf. E como nenhum módulo antes cortou a busca (o primeiro que
	// cortasse teria retornado acima), também não há nesta linha quem responda
	// por nome externo — sobram os módulos locais (files, myhostname) e os que
	// estão inertes agora.
	return CaminhoNSS{Hosts: hosts, Achou: true, Estado: NSSSemModuloDNS, CortadoPor: inerteIgnorado,
		Motivo: "a linha hosts: não lista o módulo dns, que é o único que consulta o resolv.conf"}
}

// linhaHostsNSS devolve o valor da PRIMEIRA linha `hosts:` do arquivo, que é a
// que a glibc usa — uma segunda declaração do mesmo banco é ignorada, então
// analisar a última daria um veredito sobre uma linha que não vale.
func linhaHostsNSS(conteudo string) (string, bool) {
	for _, bruta := range strings.Split(conteudo, "\n") {
		linha := bruta
		if i := strings.IndexByte(linha, '#'); i >= 0 {
			linha = linha[:i]
		}
		rotulo, valor, ok := strings.Cut(linha, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rotulo), "hosts") {
			continue
		}
		return strings.TrimSpace(valor), true
	}
	return "", false
}

// moduloNSS é um módulo da linha `hosts:` junto da ação que o segue.
type moduloNSS struct {
	Nome string
	// Acoes é o conteúdo do grupo entre colchetes que vem DEPOIS do módulo,
	// sem os colchetes (ex.: !UNAVAIL=return). Vazio quando o módulo usa as
	// ações padrão da glibc.
	Acoes string
}

// modulosNSS quebra o valor de `hosts:` em módulos com suas ações, e diz se o
// texto está malformado.
//
// A varredura é ciente de colchetes porque um grupo de ações pode ter espaço
// dentro ([NOTFOUND=return TRYAGAIN=return]): um strings.Fields simples
// partiria o grupo ao meio e transformaria "TRYAGAIN=return]" num módulo que
// não existe, o que faria a análise inteira mentir.
//
// O segundo retorno existe porque parar de analisar não é a mesma coisa que ter
// analisado: com um colchete sem fechar, os módulos devolvidos são um PREFIXO da
// linha, e concluir "não tem dns" de um prefixo é afirmar sobre a parte que não
// se leu. Quem chama tem de saber a diferença.
func modulosNSS(valor string) ([]moduloNSS, bool) {
	var modulos []moduloNSS
	i := 0
	for i < len(valor) {
		c := valor[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '[' {
			fim := strings.IndexByte(valor[i:], ']')
			if fim < 0 {
				return modulos, true
			}
			acoes := strings.TrimSpace(valor[i+1 : i+fim])
			if n := len(modulos); n > 0 {
				modulos[n-1].Acoes = acoes
			}
			i += fim + 1
			continue
		}
		j := i
		for j < len(valor) && valor[j] != ' ' && valor[j] != '\t' && valor[j] != '[' {
			j++
		}
		modulos = append(modulos, moduloNSS{Nome: strings.ToLower(valor[i:j])})
		i = j
	}
	return modulos, false
}

// moduloEncerraBusca diz se este módulo, posto antes do dns, impede o dns de
// rodar numa resolução comum.
//
// O que corta NÃO é "acertou e parou": SUCCESS=return é o padrão da glibc e é
// o comportamento certo — quem respondeu, respondeu. O que corta é a resposta
// NEGATIVA também encerrar a busca: com NOTFOUND=return, um nome que o módulo
// não conhece morre ali em vez de descer para o dns. O [!UNAVAIL=return] da VM
// de validação é isso escrito pelo avesso: tudo que não for UNAVAIL retorna, e
// NOTFOUND não é UNAVAIL.
//
// A família mdns fica de fora, e não é preguiça: "mdns4_minimal
// [NOTFOUND=return]" é a linha de qualquer Debian com avahi instalado, e ela
// NÃO quebra nada — aquele módulo só atende .local e devolve UNAVAIL para todo
// o resto, então a cadeia segue para o dns. Sem esta exceção o produto abriria
// alerta falso na maioria das instalações com avahi, e alerta que grita sem
// motivo ensina o operador a ignorar alerta.
func moduloEncerraBusca(m moduloNSS) bool {
	if m.Acoes == "" || strings.HasPrefix(m.Nome, "mdns") {
		return false
	}
	for _, campo := range strings.Fields(m.Acoes) {
		status, acao, ok := strings.Cut(campo, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(acao), "return") {
			continue
		}
		negado := strings.HasPrefix(status, "!")
		status = strings.ToLower(strings.TrimPrefix(status, "!"))
		// NOTFOUND=return corta; !X=return corta para todo X diferente de
		// NOTFOUND (porque aí o NOTFOUND está dentro do "!X"). O != faz
		// exatamente essa conta: !NOTFOUND=return não corta, já que o único
		// status que ali NÃO retorna é justamente o negativo.
		if negado != (status == "notfound") {
			return true
		}
	}
	return false
}
