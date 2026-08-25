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

// moduloResolved é o módulo NSS do systemd-resolved.
//
// Ele é tratado à parte no veredito final porque é o único cujo "corta a
// cadeia" depende de um estado que NÃO está no arquivo: com o systemd-resolved
// parado, o módulo devolve UNAVAIL, e aí a ação [!UNAVAIL=return] justamente
// não corta — a busca segue até o dns. Ver Service.verificarCaminhoNSS.
const moduloResolved = "resolve"

// caminhoNSS é o veredito sobre a linha `hosts:` do nsswitch.conf: o módulo
// `dns` (o único que consulta o resolv.conf) é alcançado numa resolução comum?
type caminhoNSS struct {
	// Hosts é a linha `hosts:` como está no arquivo, já sem o rótulo e sem
	// comentário. Vai inteira para o log e para o alerta: quem lê precisa ver
	// o que a máquina tem escrito, não a nossa paráfrase disso.
	Hosts string
	// Achou diz se havia uma linha `hosts:` para analisar.
	Achou bool
	// Alcancavel é a resposta da pergunta. Falso significa que reescrever o
	// resolv.conf é cosmético nesta caixa.
	Alcancavel bool
	// CortadoPor nomeia o módulo que encerra a busca antes do dns, quando é
	// esse o motivo. Vazio quando o dns simplesmente não está na linha.
	CortadoPor string
	// Motivo é a frase pronta, em português, para o log e para o alerta.
	Motivo string
}

// analisarHostsNSS decide, a partir do TEXTO do nsswitch.conf, se o módulo
// `dns` é alcançado numa resolução de nome comum.
//
// Pura de propósito: é a única parte disto que dá para provar em teste de mesa
// com as linhas reais das máquinas que interessam — a de produção
// (`hosts: files dns`) e a da VM de validação
// (`hosts: files myhostname resolve [!UNAVAIL=return] dns`). Ler o arquivo e
// perguntar ao systemd ficam de fora, no chamador, porque nenhum dos dois é
// reproduzível numa tabela de casos.
//
// Ausência de linha `hosts:` NÃO é defeito: a glibc cai num padrão embutido
// que consulta o dns. Dizer "quebrado" aí seria alarme falso.
func analisarHostsNSS(conteudo string) caminhoNSS {
	hosts, achou := linhaHostsNSS(conteudo)
	if !achou {
		return caminhoNSS{
			Alcancavel: true,
			Motivo:     "o nsswitch.conf não tem linha hosts:; a glibc usa o padrão embutido, que consulta o dns",
		}
	}

	for _, m := range modulosNSS(hosts) {
		if m.Nome == "dns" {
			return caminhoNSS{Hosts: hosts, Achou: true, Alcancavel: true,
				Motivo: "o módulo dns é alcançado na linha hosts:"}
		}
		if moduloEncerraBusca(m) {
			return caminhoNSS{Hosts: hosts, Achou: true, Alcancavel: false, CortadoPor: m.Nome,
				Motivo: fmt.Sprintf("o módulo %q responde antes do dns e a ação [%s] encerra a busca ali", m.Nome, m.Acoes)}
		}
	}

	return caminhoNSS{Hosts: hosts, Achou: true, Alcancavel: false,
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

// modulosNSS quebra o valor de `hosts:` em módulos com suas ações.
//
// A varredura é ciente de colchetes porque um grupo de ações pode ter espaço
// dentro ([NOTFOUND=return TRYAGAIN=return]): um strings.Fields simples
// partiria o grupo ao meio e transformaria "TRYAGAIN=return]" num módulo que
// não existe, o que faria a análise inteira mentir.
func modulosNSS(valor string) []moduloNSS {
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
				// Colchete sem fechamento: o arquivo está malformado. Para de
				// analisar em vez de inventar módulos com o resto — inventar
				// aqui vira alerta falso ou silêncio indevido.
				break
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
	return modulos
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
