package balancer

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/links"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func TestNormalizeWeights(t *testing.T) {
	tests := []struct {
		name string
		raw  []int
		want []int
	}{
		{"equal", []int{100, 100}, []int{256, 256}},
		{"all zero -> equal split", []int{0, 0}, []int{1, 1}},
		{"ratio preserved", []int{700, 300}, []int{256, 110}},
		{"single", []int{5}, []int{256}},
		{"clamps to >=1", []int{1000, 1}, []int{256, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nhs := make([]Nexthop, len(tt.raw))
			for i, w := range tt.raw {
				nhs[i] = Nexthop{RawWeight: w}
			}
			normalizeWeights(nhs)
			for i := range nhs {
				if nhs[i].Weight != tt.want[i] {
					t.Errorf("idx %d: got weight %d, want %d", i, nhs[i].Weight, tt.want[i])
				}
			}
		})
	}
}

func TestBuildReplaceArgs(t *testing.T) {
	nhs := []Nexthop{
		{Gateway: "192.168.15.1", Interface: "enp5s0", Weight: 3},
		{Gateway: "192.168.18.1", Interface: "enp3s0", Weight: 1},
	}
	args := buildReplaceArgs("main", nhs)
	got := "ip " + strings.Join(args, " ")
	want := "ip route replace default table main " +
		"nexthop via 192.168.15.1 dev enp5s0 weight 3 onlink " +
		"nexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	if buildReplaceArgs("main", nil) != nil {
		t.Error("expected nil args for empty nexthops")
	}

	// Single nexthop is still valid multipath.
	single := buildReplaceArgs("main", nhs[:1])
	if !strings.Contains(strings.Join(single, " "), "nexthop via 192.168.15.1") {
		t.Errorf("single nexthop missing: %v", single)
	}
}

func TestRestoreArgsFromShow_SinglePath(t *testing.T) {
	// Mirrors the production WAN1 default route.
	show := "default via 192.168.15.1 dev enp5s0 onlink"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main via 192.168.15.1 dev enp5s0 onlink"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRestoreArgsFromShow_SinglePathNoOnlink(t *testing.T) {
	show := "default via 192.168.18.1 dev enp3s0"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main via 192.168.18.1 dev enp3s0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Contains(got, "onlink") {
		t.Error("must not invent onlink when absent")
	}
}

func TestRestoreArgsFromShow_Multipath(t *testing.T) {
	// `ip route show` prints multipath across lines; we collapse whitespace.
	show := "default proto static \n\tnexthop via 192.168.15.1 dev enp5s0 weight 3 onlink \n\tnexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	args := restoreArgsFromShow(show, "main")
	got := strings.Join(args, " ")
	want := "route replace default table main " +
		"nexthop via 192.168.15.1 dev enp5s0 weight 3 onlink " +
		"nexthop via 192.168.18.1 dev enp3s0 weight 1 onlink"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRestoreArgsFromShow_Empty(t *testing.T) {
	if restoreArgsFromShow("", "main") != nil {
		t.Error("expected nil for empty show output")
	}
}

func TestSelectNexthops(t *testing.T) {
	link := func(name, iface, gw, status string, loss, lat float64) storage.Link {
		return storage.Link{ID: name, Name: name, Interface: iface, Gateway: gw, Weight: 100,
			Enabled: true, Status: status, PacketLoss: loss, LatencyMs: lat}
	}
	names := func(nhs []Nexthop) []string {
		out := []string{}
		for _, n := range nhs {
			out = append(out, n.Name)
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	weightOf := func(nhs []Nexthop, name string) int {
		for _, n := range nhs {
			if n.Name == name {
				return n.Weight
			}
		}
		return -1
	}
	allUp := map[string]bool{"eth0": true, "eth1": true}

	t.Run("both online -> balance both, full weight", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "online", 0, 12),
		}, allUp)
		if !eq(names(c), []string{"A", "B"}) {
			t.Fatalf("chosen=%v, want [A B]", names(c))
		}
		if weightOf(c, "A") <= demotedWeight || weightOf(c, "B") <= demotedWeight {
			t.Errorf("both healthy should carry full weight, got A=%d B=%d", weightOf(c, "A"), weightOf(c, "B"))
		}
	})

	t.Run("one degraded -> healthy primary, degraded demoted (stays for self-heal)", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "degraded", 40, 500),
		}, allUp)
		if !eq(names(c), []string{"A", "B"}) {
			t.Fatalf("chosen=%v, want [A B] (B kept, demoted)", names(c))
		}
		if weightOf(c, "B") != demotedWeight {
			t.Errorf("degraded B weight=%d, want %d (demoted)", weightOf(c, "B"), demotedWeight)
		}
		if weightOf(c, "A") <= demotedWeight {
			t.Errorf("healthy A should carry traffic, weight=%d", weightOf(c, "A"))
		}
	})

	t.Run("both degraded -> least-loss primary, other demoted", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "degraded", 60, 200),
			link("B", "eth1", "10.0.1.1", "degraded", 30, 400),
		}, allUp)
		if weightOf(c, "B") <= demotedWeight || weightOf(c, "A") != demotedWeight {
			t.Errorf("B (less loss) should be primary, A demoted; got A=%d B=%d", weightOf(c, "A"), weightOf(c, "B"))
		}
	})

	t.Run("both degraded equal loss -> least-latency primary", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "degraded", 30, 600),
			link("B", "eth1", "10.0.1.1", "degraded", 30, 250),
		}, allUp)
		if weightOf(c, "B") <= demotedWeight || weightOf(c, "A") != demotedWeight {
			t.Errorf("B (lower latency) should be primary; got A=%d B=%d", weightOf(c, "A"), weightOf(c, "B"))
		}
	})

	t.Run("offline-but-up demoted when a healthy link exists", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "offline", 100, 0),
		}, allUp)
		if !eq(names(c), []string{"A", "B"}) {
			t.Fatalf("chosen=%v, want [A B] (B demoted, kept for self-heal)", names(c))
		}
		if weightOf(c, "B") != demotedWeight {
			t.Errorf("offline B weight=%d, want %d", weightOf(c, "B"), demotedWeight)
		}
	})

	t.Run("interface down is never a nexthop (rejoins when up)", func(t *testing.T) {
		c, ex := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "online", 0, 10),
			link("B", "eth1", "10.0.1.1", "online", 0, 10),
		}, map[string]bool{"eth0": true}) // eth1 down
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A] (eth1 down)", names(c))
		}
		if !eq(names(ex), []string{"B"}) {
			t.Errorf("excluded=%v, want [B]", names(ex))
		}
	})

	t.Run("safety net: up interface, failing probe -> still used, never empty", func(t *testing.T) {
		c, _ := selectNexthops([]storage.Link{
			link("A", "eth0", "10.0.0.1", "offline", 100, 0),
		}, map[string]bool{"eth0": true})
		if !eq(names(c), []string{"A"}) {
			t.Errorf("chosen=%v, want [A] (safety net, must not be empty)", names(c))
		}
	})
}

func TestParseUpInterfaces(t *testing.T) {
	out := "lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n" +
		"enp5s0           UP             b8:ca:3a:fc:d6:03 <BROADCAST,MULTICAST,UP,LOWER_UP>\n" +
		"tun0             UNKNOWN        00:00:00:00:00:00 <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>\n" +
		"enp3s0           DOWN           f4:f2:6d:05:e2:f0 <BROADCAST,MULTICAST>"
	up := parseUpInterfaces(out)
	if !up["enp5s0"] {
		t.Error("enp5s0 should be up")
	}
	if up["enp3s0"] {
		t.Error("enp3s0 is DOWN, must not be up")
	}
	// UNKNOWN counts as up: tun/ppp/VPN WAN devices report operstate UNKNOWN even
	// when working, so excluding them would drop a healthy link. The up-map is
	// only consulted for real WAN interfaces, so a UNKNOWN lo appearing is
	// harmless.
	if !up["tun0"] {
		t.Error("tun0 is UNKNOWN (working tunnel) and must count as up")
	}
}

func TestRouteSignatureDetectsGatewayChange(t *testing.T) {
	base := []Nexthop{{LinkID: "a", Gateway: "192.168.15.1", Interface: "enp5s0", Weight: 100}}
	gwChanged := []Nexthop{{LinkID: "a", Gateway: "192.168.15.254", Interface: "enp5s0", Weight: 100}}
	ifChanged := []Nexthop{{LinkID: "a", Gateway: "192.168.15.1", Interface: "enp6s0", Weight: 100}}

	if routeSignature(base) == routeSignature(gwChanged) {
		t.Error("a gateway change (e.g. DHCP renewal) must change the signature so the route is re-applied")
	}
	if routeSignature(base) == routeSignature(ifChanged) {
		t.Error("an interface change must change the signature")
	}
	if routeSignature(base) != routeSignature(base) {
		t.Error("signature must be stable for the same nexthops")
	}
	if routeSignature(nil) == emptySig {
		t.Error("routeSignature([]) must differ from the empty-state sentinel")
	}
}

func TestConfigNormalize(t *testing.T) {
	c := Config{}
	c.normalize()
	if c.Mode != ModeFailover {
		t.Errorf("default mode = %q, want %q", c.Mode, ModeFailover)
	}
	if c.Table != defaultTable {
		t.Errorf("default table = %q, want %q", c.Table, defaultTable)
	}
	if c.ArmSeconds != defaultArmSecs {
		t.Errorf("default arm = %d, want %d", c.ArmSeconds, defaultArmSecs)
	}
	// Regression: Schedules must never be nil, or it marshals to JSON null and
	// crashes the Links page (schedules.length on null).
	if c.Schedules == nil {
		t.Error("normalize must leave Schedules as a non-nil slice")
	}

	c2 := Config{Mode: "bogus"}
	c2.normalize()
	if c2.Mode != ModeFailover {
		t.Errorf("bogus mode should fall back to failover, got %q", c2.Mode)
	}
}

func TestRebuildSkipsRedundantRouteReplace(t *testing.T) {
	exec := &recExec{
		linkOut: "enp5s0 UP\nenp3s0 UP",
		ipv4:    map[string]string{"enp5s0": "3: enp5s0 inet 192.168.15.20/24 scope global enp5s0"},
	}
	linkA := storage.Link{ID: "a", Name: "WAN1", Interface: "enp5s0", Gateway: "192.168.15.1", Weight: 100, Enabled: true, Status: links.StatusOnline}
	linkB := storage.Link{ID: "b", Name: "WAN2", Interface: "enp3s0", Gateway: "192.168.18.1", Weight: 100, Enabled: true, Status: links.StatusOnline}
	svc := newEvictService(t, exec, false, []storage.Link{linkA, linkB})

	ctx := context.Background()
	if err := svc.Rebuild(ctx); err != nil {
		t.Fatalf("first Rebuild: %v", err)
	}
	firstCount := len(exec.writes)
	if firstCount == 0 {
		t.Fatal("expected the first Rebuild to issue at least one write (ip route replace)")
	}

	// Nothing about the links or config changed — a second Rebuild with an
	// identical nexthop set must be a no-op, not a second "ip route replace".
	if err := svc.Rebuild(ctx); err != nil {
		t.Fatalf("second Rebuild: %v", err)
	}
	if got := len(exec.writes); got != firstCount {
		t.Fatalf("second Rebuild issued %d more write(s) — expected 0 (no-op), the nexthop set did not change", got-firstCount)
	}
}

func TestContarFixadosCasaAMarcaPorNumeroENaoPorTexto(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE. O nft imprime a marca preenchida com
	// zeros e a configuração guarda a forma curta. Comparadas como texto, elas
	// nunca casam — o contador daria zero sempre, o alerta seria suprimido
	// mesmo com aparelhos fixados, e o silêncio se pareceria com conserto.
	//
	// A saída abaixo é a da máquina de produção.
	const saida = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
		elements = { 192.168.3.17 : 0x0000012c,
			     192.168.3.35 : 0x0000012c,
			     192.168.3.47 : 0x00000065 }
	}
}`
	casos := []struct {
		marca string
		quer  int
	}{
		{"0x12c", 2},      // forma curta, como a configuração guarda
		{"0x0000012c", 2}, // forma longa, como o nft imprime
		{"0x65", 1},
		{"0x999", 0},
	}
	for _, c := range casos {
		alvo, err := strconv.ParseUint(strings.TrimPrefix(c.marca, "0x"), 16, 32)
		if err != nil {
			t.Fatalf("%s: %v", c.marca, err)
		}
		var n int
		for _, m := range reMarcaDoMap.FindAllStringSubmatch(saida, -1) {
			if v, err := strconv.ParseUint(m[1], 16, 32); err == nil && v == alvo {
				n++
			}
		}
		if n != c.quer {
			t.Errorf("marca %s: contei %d, esperado %d", c.marca, n, c.quer)
		}
	}
}

func TestInterfaceComMaeEhReconhecidaComoNoAr(t *testing.T) {
	// O DEFEITO QUE ESTE TESTE PRENDE, e ele é de produção.
	//
	// O iproute2 acrescenta "@mãe" ao nome de toda interface que tem
	// interface-mãe: VLAN, veth, macvlan, ipvlan. Só a física sai com o nome
	// limpo. Sem tirar o sufixo, a chave do mapa nunca casava com o nome do
	// link, selectNexthops lia isso como link CAÍDO, e uma WAN em VLAN — o
	// arranjo mais comum em firewall de borda — sumia do balanceamento sem uma
	// linha de log, aparecendo no painel como excluída por estar fora do ar.
	//
	// A saída abaixo é a do iproute2 de verdade, copiada da máquina de teste.
	const saida = `lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
enp0s2           UP             52:54:00:12:34:56 <BROADCAST,MULTICAST,UP,LOWER_UP> 
enp0s2.100@enp0s2 UP            52:54:00:12:34:56 <BROADCAST,MULTICAST,UP,LOWER_UP> 
lg-wana@if38     UP             aa:d7:00:fb:3c:b3 <BROADCAST,MULTICAST,UP,LOWER_UP> 
lg-caida@if40    DOWN           aa:d7:00:fb:3c:b4 <BROADCAST,MULTICAST> `

	up := parseUpInterfaces(saida)
	for _, iface := range []string{"lo", "enp0s2", "enp0s2.100", "lg-wana"} {
		if !up[iface] {
			t.Errorf("%s devia estar no ar; o mapa tem %v", iface, up)
		}
	}
	if up["lg-caida"] {
		t.Error("interface DOWN entrou como no ar")
	}
	// E o nome sujo NÃO pode continuar no mapa: quem consulta usa o nome do
	// link, e uma chave a mais só esconde o defeito de quem for depurar.
	for _, sujo := range []string{"enp0s2.100@enp0s2", "lg-wana@if38"} {
		if up[sujo] {
			t.Errorf("o nome com @mãe ficou no mapa: %s", sujo)
		}
	}
}

func TestOMapVazioNaoContaNinguem(t *testing.T) {
	// Map sem elemento nenhum é o estado de quem soltou todos os aparelhos, e é
	// exatamente quando o alerta NÃO pode aparecer.
	const vazio = `table inet linkguard {
	map host_wan {
		type ipv4_addr : mark
	}
}`
	if got := len(reMarcaDoMap.FindAllStringSubmatch(vazio, -1)); got != 0 {
		t.Errorf("map vazio casou %d marca(s)", got)
	}
}

func TestUmaWANEmVLANEntraNoPlano(t *testing.T) {
	// A consequência do defeito acima, no lugar onde ela custa: selectNexthops
	// joga em `excluded` todo link cuja interface não está na lista de no-ar.
	const saida = `enp3s0.100@enp3s0 UP           aa:bb:cc:dd:ee:01 <BROADCAST,MULTICAST,UP,LOWER_UP> 
enp4s0           UP             aa:bb:cc:dd:ee:02 <BROADCAST,MULTICAST,UP,LOWER_UP> `

	todos := []storage.Link{
		{ID: "a", Name: "WAN VLAN", Interface: "enp3s0.100", Gateway: "10.1.0.1", Weight: 50, Enabled: true, Status: links.StatusOnline},
		{ID: "b", Name: "WAN física", Interface: "enp4s0", Gateway: "10.2.0.1", Weight: 50, Enabled: true, Status: links.StatusOnline},
	}
	escolhidos, excluidos := selectNexthops(todos, parseUpInterfaces(saida))
	if len(escolhidos) != 2 {
		t.Fatalf("o balanceamento ficou com %d caminho(s), esperado 2; excluídos: %v", len(escolhidos), excluidos)
	}
	if len(excluidos) != 0 {
		t.Errorf("link excluído sem motivo: %v", excluidos)
	}
}
