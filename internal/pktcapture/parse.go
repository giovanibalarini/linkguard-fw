package pktcapture

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Este arquivo é a metade testável da feature: transforma a saída de
// `tcpdump -nn -tt` em estrutura, e a estrutura em diagnóstico. Nada aqui
// executa nada — é o mesmo desenho de internal/hosts/parseNeighbors e
// internal/hosttraffic/parseConntrack, e pelo mesmo motivo: a parte que erra é
// o parsing, e ele precisa ser exercitável sem uma máquina com tráfego.
//
// REGRA QUE NÃO PODE SER QUEBRADA AQUI: só campo estruturado sobrevive. O
// tcpdump, sem `-q`, dissecca o que reconhece — nome consultado em DNS, por
// exemplo, que ele lê dos primeiros bytes do payload. Esse texto é lido para
// classificar o pacote e DESCARTADO em seguida; ele nunca entra em Packet.
// É o que mantém verdadeira a frase que a tela mostra ao admin.

var (
	// reID casa o identificador de captura (usado como nome de arquivo).
	reID = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}$`)

	// reLength pega o "length N" que o tcpdump imprime no fim da linha. É o
	// tamanho dos DADOS (payload do transporte), não do quadro — o rótulo na
	// tela diz isso, para o número não ser lido como "bytes na interface".
	reLength = regexp.MustCompile(`length (\d+)`)
	// reParenLen é o fallback para linha dissecada (ex.: DNS), que termina em
	// "(29)" em vez de "length 29".
	reParenLen = regexp.MustCompile(`\((\d+)\)\s*$`)
	// reSeq pega o número de sequência TCP, inclusive na forma de intervalo
	// ("seq 1:1449"), de que só o início interessa.
	reSeq = regexp.MustCompile(`seq (\d+)`)
)

// Packet é um pacote, reduzido ao que se lê numa tabela.
type Packet struct {
	Time  string `json:"time"`  // HH:MM:SS.mmm, hora local
	Src   string `json:"src"`   // host[:porta]
	Dst   string `json:"dst"`   //
	Proto string `json:"proto"` // tcp | udp | icmp | arp | outro
	Len   int    `json:"len"`   // bytes de dados
	Flags string `json:"flags"` // TCP: S, S., P., F., R. …

	// Campos internos ao resumo — não vão para a tela.
	ts       float64
	srcHost  string
	dstHost  string
	dstPort  string
	seq      string
	isTCPSYN bool
	isTCPACK bool
	isRST    bool
}

// Count é uma linha de ranking do resumo.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Bytes int    `json:"bytes"`
}

// Bucket é um segundo da captura.
type Bucket struct {
	Sec     int `json:"sec"`
	Packets int `json:"packets"`
	Bytes   int `json:"bytes"`
}

// Handshake é uma tentativa de conexão TCP e o que aconteceu com ela.
type Handshake struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Time  string `json:"time"`
	Tries int    `json:"tries"`
}

// Summary é a leitura da captura inteira — inclusive das linhas que a tabela
// não mostra por causa de MaxRows.
type Summary struct {
	Packets     int         `json:"packets"`
	Bytes       int         `json:"bytes"`
	DurationSec float64     `json:"duration_sec"`
	Protos      []Count     `json:"protos"`
	Pairs       []Count     `json:"pairs"`
	Ports       []Count     `json:"ports"`
	PerSecond   []Bucket    `json:"per_second"`
	Unanswered  []Handshake `json:"unanswered"`
	Refused     []Handshake `json:"refused"`
	// *Total é quantas houve ao todo; a lista acima pode estar cortada em
	// maxHandshakes. Ver collectHandshakes.
	UnansweredTotal int `json:"unanswered_total"`
	RefusedTotal    int `json:"refused_total"`
	Retransmits     int `json:"retransmits"`
}

func (s Summary) clone() Summary {
	cp := s
	cp.Protos = append(make([]Count, 0, len(s.Protos)), s.Protos...)
	cp.Pairs = append(make([]Count, 0, len(s.Pairs)), s.Pairs...)
	cp.Ports = append(make([]Count, 0, len(s.Ports)), s.Ports...)
	cp.PerSecond = append(make([]Bucket, 0, len(s.PerSecond)), s.PerSecond...)
	cp.Unanswered = append(make([]Handshake, 0, len(s.Unanswered)), s.Unanswered...)
	cp.Refused = append(make([]Handshake, 0, len(s.Refused)), s.Refused...)
	return cp
}

// ParseLines transforma a saída de `tcpdump -nn -tt` em pacotes. Linha que não
// casa com o formato é ignorada em silêncio: o tcpdump escreve avisos e
// cabeçalhos junto, e abortar a leitura por causa deles perderia a captura
// inteira por causa de uma linha.
func ParseLines(out string) []Packet {
	var pkts []Packet
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, ok := parseLine(line)
		if !ok {
			continue
		}
		pkts = append(pkts, p)
	}
	return pkts
}

func parseLine(line string) (Packet, bool) {
	head, rest, ok := strings.Cut(line, " ")
	if !ok {
		return Packet{}, false
	}
	ts, err := strconv.ParseFloat(head, 64)
	if err != nil {
		return Packet{}, false
	}

	p := Packet{ts: ts, Time: formatTS(ts)}

	switch {
	case strings.HasPrefix(rest, "ARP,"):
		p.Proto = "arp"
		// "ARP, Request who-has 192.168.3.1 tell 192.168.3.50, length 28"
		if who := after(rest, "who-has "); who != "" {
			p.Dst = firstField(who)
			p.dstHost = p.Dst
		}
		if tell := after(rest, "tell "); tell != "" {
			p.Src = strings.TrimSuffix(firstField(tell), ",")
			p.srcHost = p.Src
		}
		p.Len = parseLen(rest)
		return p, true

	case strings.HasPrefix(rest, "IP "):
		rest = rest[3:]
	case strings.HasPrefix(rest, "IP6 "):
		rest = rest[4:]
	default:
		// Quadro que não é IP nem ARP (STP, LLDP…). Registrar como "outro"
		// sem endpoints seria uma linha vazia na tela; melhor não listar.
		return Packet{}, false
	}

	src, remainder, ok := strings.Cut(rest, " > ")
	if !ok {
		return Packet{}, false
	}
	// O separador é dois-pontos SEGUIDO DE ESPAÇO: endereço IPv6 tem
	// dois-pontos, mas nunca dois-pontos-espaço. É o que permite cortar aqui
	// sem quebrar `fe80::1.546 > ff02::1:2.547: dhcp6`.
	dst, payload, ok := strings.Cut(remainder, ": ")
	if !ok {
		// Pacote sem descrição depois do destino (acontece com quadro
		// truncado). Ainda vale como linha: os endpoints são o que importa.
		dst, payload = strings.TrimSuffix(remainder, ":"), ""
	}

	p.Src, p.Dst = src, dst
	p.srcHost, _ = splitEndpoint(src)
	p.dstHost, p.dstPort = splitEndpoint(dst)
	p.Len = parseLen(payload)
	p.Proto = classify(payload, p.dstPort)

	if p.Proto == "tcp" {
		p.Flags = tcpFlags(payload)
		if m := reSeq.FindStringSubmatch(payload); m != nil {
			p.seq = m[1]
		}
		// "[S]" é SYN puro (pedido); "[S.]" é SYN+ACK (resposta). O ponto é
		// como o tcpdump escreve o ACK, então a diferença entre os dois é
		// exatamente a diferença entre "tentou" e "responderam".
		p.isTCPSYN = p.Flags == "S"
		p.isTCPACK = strings.HasPrefix(p.Flags, "S.")
		p.isRST = strings.Contains(p.Flags, "R")
	}
	return p, true
}

// classify decide o protocolo sem confiar no texto dissecado. TCP sempre
// imprime "Flags ["; UDP aparece como "UDP," quando o tcpdump não reconhece a
// aplicação, e como texto da aplicação quando reconhece — por isso o último
// caso usa a presença de porta, e não o texto.
func classify(payload, dstPort string) string {
	switch {
	case strings.HasPrefix(payload, "Flags ["):
		return "tcp"
	case strings.HasPrefix(payload, "UDP,"):
		return "udp"
	case strings.HasPrefix(payload, "ICMP"), strings.Contains(payload, "ICMP6,"):
		return "icmp"
	case dstPort != "":
		return "udp"
	default:
		return "outro"
	}
}

func tcpFlags(payload string) string {
	open := strings.Index(payload, "[")
	if open < 0 {
		return ""
	}
	close := strings.Index(payload[open:], "]")
	if close < 0 {
		return ""
	}
	return payload[open+1 : open+close]
}

// splitEndpoint separa "192.168.3.50.44210" em host e porta, e devolve porta
// vazia quando não há. Funciona para IPv6 ("fe80::1.546") porque o teste é se o
// que sobra ANTES do último ponto continua sendo um endereço.
func splitEndpoint(s string) (host, port string) {
	i := strings.LastIndex(s, ".")
	if i <= 0 {
		return s, ""
	}
	cand := s[i+1:]
	if cand == "" || !allDigits(cand) {
		return s, ""
	}
	left := s[:i]
	if !looksLikeIP(left) {
		return s, ""
	}
	return left, cand
}

func looksLikeIP(s string) bool {
	if strings.Contains(s, ":") {
		return true // IPv6
	}
	return strings.Count(s, ".") == 3 && allDigitsOrDots(s)
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func allDigitsOrDots(s string) bool {
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return len(s) > 0
}

func parseLen(s string) int {
	if m := reLength.FindAllStringSubmatch(s, -1); len(m) > 0 {
		n, _ := strconv.Atoi(m[len(m)-1][1])
		return n
	}
	if m := reParenLen.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func after(s, sep string) string {
	i := strings.Index(s, sep)
	if i < 0 {
		return ""
	}
	return s[i+len(sep):]
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func formatTS(ts float64) string {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).Format("15:04:05.000")
}

// ─── resumo ──────────────────────────────────────────────────────────────────

const (
	topN = 10
	// maxHandshakes limita a lista de tentativas devolvida ao painel.
	maxHandshakes = 50
)

// Summarize é a parte que transforma log em diagnóstico. Ela responde três
// perguntas que a tabela sozinha não responde: quem falou mais, que serviço
// era, e — a que mais importa num produto multi-WAN — quem tentou conectar e
// não obteve resposta.
func Summarize(pkts []Packet) Summary {
	s := Summary{
		Protos:     []Count{},
		Pairs:      []Count{},
		Ports:      []Count{},
		PerSecond:  []Bucket{},
		Unanswered: []Handshake{},
		Refused:    []Handshake{},
	}
	if len(pkts) == 0 {
		return s
	}

	protos := map[string]*Count{}
	pairs := map[string]*Count{}
	ports := map[string]*Count{}
	buckets := map[int]*Bucket{}
	seen := map[string]int{} // (src,dst,seq,len) → vezes: repetição é retransmissão

	// pending guarda o SYN que ainda não teve resposta, indexado pelo sentido
	// da tentativa. A resposta chega no sentido inverso, e é isso que a busca
	// pela chave invertida aproveita.
	pending := map[string]*attempt{}
	refused := map[string]*attempt{}

	t0 := pkts[0].ts
	for i, p := range pkts {
		s.Packets++
		s.Bytes += p.Len

		add(protos, p.Proto, p.Len)
		if p.srcHost != "" && p.dstHost != "" {
			add(pairs, p.srcHost+" → "+p.dstHost, p.Len)
		}
		if p.dstPort != "" && (p.Proto == "tcp" || p.Proto == "udp") {
			add(ports, p.Proto+"/"+p.dstPort, p.Len)
		}

		sec := int(p.ts - t0)
		b, ok := buckets[sec]
		if !ok {
			b = &Bucket{Sec: sec}
			buckets[sec] = b
		}
		b.Packets++
		b.Bytes += p.Len

		if p.Proto == "tcp" && p.seq != "" {
			k := p.Src + "|" + p.Dst + "|" + p.seq + "|" + strconv.Itoa(p.Len)
			seen[k]++
			if seen[k] > 1 {
				s.Retransmits++
			}
		}

		key := p.Src + "|" + p.Dst
		rev := p.Dst + "|" + p.Src
		switch {
		case p.isTCPSYN:
			if a, ok := pending[key]; ok {
				// SYN repetido é o próprio sintoma: o cliente insistindo.
				a.h.Tries++
				break
			}
			pending[key] = &attempt{
				h:     Handshake{Src: p.Src, Dst: p.Dst, Time: p.Time, Tries: 1},
				order: i,
			}
		case p.isTCPACK:
			delete(pending, rev)
			delete(refused, rev)
		case p.isRST:
			// RST é resposta — negativa. Separar as duas coisas importa: "sem
			// resposta" aponta para rota/firewall no caminho, "recusado"
			// aponta para porta fechada no destino. Confundir os dois manda o
			// admin depurar o lugar errado.
			if a, ok := pending[rev]; ok {
				delete(pending, rev)
				refused[rev] = a
			}
		}
	}

	s.DurationSec = pkts[len(pkts)-1].ts - t0
	s.Protos = topCounts(protos)
	s.Pairs = topCounts(pairs)
	s.Ports = topCounts(ports)

	s.PerSecond = make([]Bucket, 0, len(buckets))
	for _, b := range buckets {
		s.PerSecond = append(s.PerSecond, *b)
	}
	sort.Slice(s.PerSecond, func(i, j int) bool { return s.PerSecond[i].Sec < s.PerSecond[j].Sec })

	s.Unanswered, s.UnansweredTotal = collectHandshakes(pending)
	s.Refused, s.RefusedTotal = collectHandshakes(refused)
	return s
}

func add(m map[string]*Count, key string, bytes int) {
	c, ok := m[key]
	if !ok {
		c = &Count{Key: key}
		m[key] = c
	}
	c.Count++
	c.Bytes += bytes
}

// topCounts ordena por contagem e, no empate, por chave — determinismo é o que
// permite testar o resumo sem depender da ordem de iteração do map.
func topCounts(m map[string]*Count) []Count {
	out := make([]Count, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// attempt é um SYN observado e a ordem em que apareceu, para o resumo listar
// as tentativas na ordem em que aconteceram (e não na do map).
type attempt struct {
	h     Handshake
	order int
}

// collectHandshakes devolve no máximo maxHandshakes tentativas, na ordem em
// que apareceram. O corte é explícito no total devolvido junto — varredura de
// portas produz milhares de SYN sem resposta, e uma lista truncada em silêncio
// leria como "só houve estes".
func collectHandshakes(m map[string]*attempt) ([]Handshake, int) {
	ord := make([]*attempt, 0, len(m))
	for _, a := range m {
		ord = append(ord, a)
	}
	sort.Slice(ord, func(i, j int) bool { return ord[i].order < ord[j].order })
	total := len(ord)
	if len(ord) > maxHandshakes {
		ord = ord[:maxHandshakes]
	}
	out := make([]Handshake, 0, len(ord))
	for _, a := range ord {
		out = append(out, a.h)
	}
	return out, total
}
