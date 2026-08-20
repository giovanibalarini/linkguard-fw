package pktcapture

import (
	"strings"
	"testing"
)

// As linhas destes testes são saída real de `tcpdump -nn -tt`, com os
// endereços trocados. O formato é o contrato de que esta feature depende, e é
// justamente o que muda sem avisar entre versões do tcpdump — por isso ele é
// exercitado aqui, e não só na VM.

func TestParseLineTCPSYN(t *testing.T) {
	line := "1755610000.123456 IP 192.168.3.50.44210 > 142.250.1.1.443: Flags [S], seq 1234567890, win 64240, options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0"
	p, ok := parseLine(line)
	if !ok {
		t.Fatal("não parseou")
	}
	if p.Src != "192.168.3.50.44210" || p.Dst != "142.250.1.1.443" {
		t.Errorf("endpoints: src=%q dst=%q", p.Src, p.Dst)
	}
	if p.Proto != "tcp" {
		t.Errorf("proto = %q, queria tcp", p.Proto)
	}
	if p.Flags != "S" {
		t.Errorf("flags = %q, queria S", p.Flags)
	}
	if !p.isTCPSYN || p.isTCPACK {
		t.Errorf("SYN puro classificado errado: syn=%v ack=%v", p.isTCPSYN, p.isTCPACK)
	}
	if p.Len != 0 {
		t.Errorf("len = %d, queria 0", p.Len)
	}
	if p.srcHost != "192.168.3.50" || p.dstPort != "443" {
		t.Errorf("host/porta: %q %q", p.srcHost, p.dstPort)
	}
}

func TestParseLineSYNACKNaoEhSYN(t *testing.T) {
	// A diferença entre "[S]" e "[S.]" é a diferença entre uma tentativa e uma
	// resposta. Confundir as duas faria o detector de "sem resposta" acusar
	// toda conexão bem-sucedida.
	line := "1755610000.223456 IP 142.250.1.1.443 > 192.168.3.50.44210: Flags [S.], seq 1, ack 1234567891, win 65535, length 0"
	p, _ := parseLine(line)
	if p.isTCPSYN {
		t.Error("SYN-ACK foi classificado como SYN puro")
	}
	if !p.isTCPACK {
		t.Error("SYN-ACK não foi reconhecido como resposta")
	}
}

func TestParseLineTCPComDadosESeqIntervalo(t *testing.T) {
	line := "1755610000.723456 IP 192.168.3.50.44210 > 142.250.1.1.443: Flags [P.], seq 1:1449, ack 1, win 502, length 1448"
	p, _ := parseLine(line)
	if p.Len != 1448 {
		t.Errorf("len = %d, queria 1448", p.Len)
	}
	if p.seq != "1" {
		t.Errorf("seq = %q, queria o início do intervalo (1)", p.seq)
	}
}

func TestParseLineUDPDissecadoNaoVazaOQueFoiPerguntado(t *testing.T) {
	// ESTE É O TESTE DA PROMESSA. Sem -q, o tcpdump imprime o nome consultado
	// em DNS, que ele lê do payload. A tela afirma que não mostra conteúdo — e
	// é aqui que isso deixa de ser afirmação e vira invariante.
	line := "1755610000.323456 IP 192.168.3.50.53142 > 8.8.8.8.53: 42045+ A? sitesecreto.example.com. (41)"
	p, ok := parseLine(line)
	if !ok {
		t.Fatal("não parseou")
	}
	if p.Proto != "udp" {
		t.Errorf("proto = %q, queria udp", p.Proto)
	}
	if p.Len != 41 {
		t.Errorf("len = %d, queria 41 (o (41) do fim da linha)", p.Len)
	}
	for _, campo := range []string{p.Src, p.Dst, p.Proto, p.Flags, p.Time} {
		if strings.Contains(campo, "sitesecreto") {
			t.Fatalf("o nome consultado vazou para um campo do pacote: %q", campo)
		}
	}
}

func TestParseLineUDPFormaQuieta(t *testing.T) {
	line := "1755610000.323456 IP 192.168.3.50.5353 > 224.0.0.251.5353: UDP, length 29"
	p, _ := parseLine(line)
	if p.Proto != "udp" || p.Len != 29 {
		t.Errorf("proto=%q len=%d", p.Proto, p.Len)
	}
}

func TestParseLineICMP(t *testing.T) {
	line := "1755610000.423456 IP 8.8.8.8 > 192.168.3.50: ICMP echo reply, id 1, seq 1, length 64"
	p, _ := parseLine(line)
	if p.Proto != "icmp" {
		t.Errorf("proto = %q, queria icmp", p.Proto)
	}
	if p.Src != "8.8.8.8" || p.dstPort != "" {
		t.Errorf("ICMP não tem porta: src=%q dstPort=%q", p.Src, p.dstPort)
	}
	if p.Len != 64 {
		t.Errorf("len = %d, queria 64", p.Len)
	}
}

func TestParseLineIPv6ComPorta(t *testing.T) {
	// Endereço IPv6 tem dois-pontos, e o separador do tcpdump é
	// dois-pontos-espaço. Se o corte fosse pelo primeiro ":", esta linha
	// viraria lixo.
	line := "1755610000.523456 IP6 fe80::1.546 > ff02::1:2.547: UDP, length 100"
	p, ok := parseLine(line)
	if !ok {
		t.Fatal("não parseou")
	}
	if p.Src != "fe80::1.546" || p.Dst != "ff02::1:2.547" {
		t.Errorf("endpoints v6: src=%q dst=%q", p.Src, p.Dst)
	}
	if p.srcHost != "fe80::1" || p.dstPort != "547" {
		t.Errorf("split v6: host=%q porta=%q", p.srcHost, p.dstPort)
	}
}

func TestParseLineARP(t *testing.T) {
	line := "1755610000.623456 ARP, Request who-has 192.168.3.1 tell 192.168.3.50, length 28"
	p, ok := parseLine(line)
	if !ok {
		t.Fatal("não parseou")
	}
	if p.Proto != "arp" {
		t.Errorf("proto = %q", p.Proto)
	}
	if p.Src != "192.168.3.50" || p.Dst != "192.168.3.1" {
		t.Errorf("ARP src=%q dst=%q (quem pergunta é o 'tell')", p.Src, p.Dst)
	}
}

func TestParseLinesIgnoraRuido(t *testing.T) {
	out := `reading from file /var/lib/linkguard-fw/captures/x.pcap, link-type EN10MB (Ethernet), snapshot length 96
1755610000.123456 IP 192.168.3.50.44210 > 142.250.1.1.443: Flags [S], seq 1, win 64240, length 0

12 packets captured`
	pkts := ParseLines(out)
	if len(pkts) != 1 {
		t.Fatalf("queria 1 pacote entre as linhas de ruído, veio %d", len(pkts))
	}
}

func TestSplitEndpoint(t *testing.T) {
	casos := []struct{ in, host, port string }{
		{"192.168.3.50.44210", "192.168.3.50", "44210"},
		{"192.168.3.50", "192.168.3.50", ""},
		{"fe80::1.546", "fe80::1", "546"},
		{"fe80::1", "fe80::1", ""},
		{"255.255.255.255", "255.255.255.255", ""},
	}
	for _, c := range casos {
		h, p := splitEndpoint(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitEndpoint(%q) = (%q, %q), queria (%q, %q)", c.in, h, p, c.host, c.port)
		}
	}
}

// ─── resumo ──────────────────────────────────────────────────────────────────

func linhas(t *testing.T, ls ...string) []Packet {
	t.Helper()
	return ParseLines(strings.Join(ls, "\n"))
}

func TestSummarizeSYNSemRespostaEhOQueSobra(t *testing.T) {
	// O caso que dá nome à feature: o SYN entra e ninguém responde. É o
	// sintoma de roteamento de retorno errado em caixa com duas WANs.
	pkts := linhas(t,
		"1755610000.100000 IP 200.1.1.1.51000 > 192.168.3.50.443: Flags [S], seq 1, win 64240, length 0",
		"1755610001.100000 IP 200.1.1.1.51000 > 192.168.3.50.443: Flags [S], seq 1, win 64240, length 0",
	)
	s := Summarize(pkts)
	if len(s.Unanswered) != 1 {
		t.Fatalf("queria 1 tentativa sem resposta, veio %d", len(s.Unanswered))
	}
	if s.Unanswered[0].Tries != 2 {
		t.Errorf("tentativas = %d, queria 2 (o cliente insistiu)", s.Unanswered[0].Tries)
	}
	if s.Retransmits != 1 {
		t.Errorf("retransmissões = %d, queria 1 (o SYN repetido)", s.Retransmits)
	}
}

func TestSummarizeSYNRespondidoNaoAparece(t *testing.T) {
	pkts := linhas(t,
		"1755610000.100000 IP 192.168.3.50.44210 > 142.250.1.1.443: Flags [S], seq 1, win 64240, length 0",
		"1755610000.200000 IP 142.250.1.1.443 > 192.168.3.50.44210: Flags [S.], seq 9, ack 2, win 65535, length 0",
	)
	s := Summarize(pkts)
	if len(s.Unanswered) != 0 {
		t.Errorf("conexão respondida não pode entrar na lista de sem resposta: %+v", s.Unanswered)
	}
}

func TestSummarizeRSTEhRecusaENaoSilencio(t *testing.T) {
	// A distinção existe porque manda o admin para lugares diferentes:
	// silêncio é caminho/firewall, recusa é porta fechada no destino.
	pkts := linhas(t,
		"1755610000.100000 IP 192.168.3.50.44210 > 192.168.3.9.22: Flags [S], seq 1, win 64240, length 0",
		"1755610000.200000 IP 192.168.3.9.22 > 192.168.3.50.44210: Flags [R.], seq 1, ack 2, win 0, length 0",
	)
	s := Summarize(pkts)
	if len(s.Unanswered) != 0 {
		t.Errorf("recusada não é sem resposta: %+v", s.Unanswered)
	}
	if len(s.Refused) != 1 {
		t.Fatalf("queria 1 recusada, veio %d", len(s.Refused))
	}
	if s.RefusedTotal != 1 {
		t.Errorf("total de recusadas = %d", s.RefusedTotal)
	}
}

func TestSummarizeRankingEDeterminismo(t *testing.T) {
	pkts := linhas(t,
		"1755610000.100000 IP 192.168.3.50.44210 > 142.250.1.1.443: Flags [P.], seq 1, ack 1, win 502, length 100",
		"1755610000.200000 IP 192.168.3.50.44211 > 142.250.1.1.443: Flags [P.], seq 1, ack 1, win 502, length 200",
		"1755610000.300000 IP 192.168.3.51.44212 > 1.1.1.1.53: UDP, length 50",
	)
	s := Summarize(pkts)
	if s.Packets != 3 || s.Bytes != 350 {
		t.Errorf("totais: %d pacotes, %d bytes", s.Packets, s.Bytes)
	}
	if len(s.Pairs) == 0 || s.Pairs[0].Key != "192.168.3.50 → 142.250.1.1" {
		t.Errorf("par mais falante errado: %+v", s.Pairs)
	}
	if s.Pairs[0].Count != 2 || s.Pairs[0].Bytes != 300 {
		t.Errorf("agregação do par: %+v", s.Pairs[0])
	}
	if len(s.Ports) == 0 || s.Ports[0].Key != "tcp/443" {
		t.Errorf("porta mais usada errada: %+v", s.Ports)
	}
	// O resumo é lido por humano e comparado por teste: empate tem de
	// desempatar por chave, senão a ordem vem do map e muda a cada execução.
	for i := 1; i < len(s.Ports); i++ {
		a, b := s.Ports[i-1], s.Ports[i]
		if a.Count == b.Count && a.Key > b.Key {
			t.Errorf("empate desordenado: %q antes de %q", a.Key, b.Key)
		}
	}
}

func TestSummarizePorSegundo(t *testing.T) {
	pkts := linhas(t,
		"1755610000.100000 IP 192.168.3.50.1 > 1.1.1.1.53: UDP, length 10",
		"1755610000.900000 IP 192.168.3.50.1 > 1.1.1.1.53: UDP, length 10",
		"1755610002.100000 IP 192.168.3.50.1 > 1.1.1.1.53: UDP, length 30",
	)
	s := Summarize(pkts)
	if len(s.PerSecond) != 2 {
		t.Fatalf("queria 2 segundos com tráfego, veio %d: %+v", len(s.PerSecond), s.PerSecond)
	}
	if s.PerSecond[0].Sec != 0 || s.PerSecond[0].Packets != 2 || s.PerSecond[0].Bytes != 20 {
		t.Errorf("primeiro segundo: %+v", s.PerSecond[0])
	}
	if s.PerSecond[1].Sec != 2 {
		t.Errorf("segundo balde deveria ser o segundo 2: %+v", s.PerSecond[1])
	}
	if s.DurationSec < 1.9 || s.DurationSec > 2.1 {
		t.Errorf("duração = %v, queria ~2s", s.DurationSec)
	}
}

func TestSummarizeCorteDeTentativasEhDeclarado(t *testing.T) {
	// Varredura de portas produz milhares de SYN sem resposta. A lista é
	// cortada, mas o total tem de continuar verdadeiro — corte silencioso
	// leria como "só houve estes".
	var ls []string
	for i := 0; i < maxHandshakes+7; i++ {
		ls = append(ls, "1755610000.100000 IP 200.1.1.1.5"+pad(i)+" > 192.168.3.50.443: Flags [S], seq 1, win 64240, length 0")
	}
	s := Summarize(ParseLines(strings.Join(ls, "\n")))
	if len(s.Unanswered) != maxHandshakes {
		t.Errorf("lista = %d, queria o corte em %d", len(s.Unanswered), maxHandshakes)
	}
	if s.UnansweredTotal != maxHandshakes+7 {
		t.Errorf("total = %d, queria %d", s.UnansweredTotal, maxHandshakes+7)
	}
}

func pad(i int) string {
	s := "0000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestSummarizeVazioNaoDevolveNil(t *testing.T) {
	// Slice nil vira null no JSON, e a tela quebra iterando null. Mesmo
	// motivo do snapshot do stresstest.
	s := Summarize(nil)
	if s.Pairs == nil || s.Ports == nil || s.Protos == nil || s.PerSecond == nil ||
		s.Unanswered == nil || s.Refused == nil {
		t.Error("resumo vazio tem de trazer slices vazias, nunca nil")
	}
}
