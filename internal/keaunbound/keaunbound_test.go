package keaunbound

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/netsvc"
)

func TestGenerateKeaConfigValidJSON(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	res := []netsvc.Reservation{{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.3.50", Hostname: "pc-joao"}}
	out := GenerateKeaConfig(cfg, res)

	// Strip the leading // comment line, the rest must be valid JSON.
	jsonPart := out[strings.Index(out, "{"):]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("kea config is not valid JSON: %v\n%s", err, out)
	}
	dhcp4, ok := parsed["Dhcp4"].(map[string]any)
	if !ok {
		t.Fatal("missing Dhcp4 root")
	}
	subnets := dhcp4["subnet4"].([]any)
	sn := subnets[0].(map[string]any)
	if sn["subnet"] != "192.168.3.0/24" {
		t.Errorf("wrong subnet: %v", sn["subnet"])
	}
	pool := sn["pools"].([]any)[0].(map[string]any)["pool"]
	if pool != "192.168.3.10 - 192.168.3.100" {
		t.Errorf("wrong pool: %v", pool)
	}
	rs := sn["reservations"].([]any)[0].(map[string]any)
	if rs["hw-address"] != "aa:bb:cc:dd:ee:ff" || rs["ip-address"] != "192.168.3.50" {
		t.Errorf("wrong reservation: %v", rs)
	}
	if dhcp4["valid-lifetime"].(float64) != 43200 { // 12h
		t.Errorf("wrong valid-lifetime: %v", dhcp4["valid-lifetime"])
	}
}

func TestGenerateUnboundConfigRecursiveByDefault(t *testing.T) {
	cfg := netsvc.DefaultConfig() // empty upstreams = recursive
	out := GenerateUnboundConfig(cfg, []string{"ads.example.com"})
	wants := []string{
		"server:",
		"interface: 192.168.3.3",
		"interface: 127.0.0.1",
		"access-control: 192.168.3.0/24 allow",
		"num-threads: 2",
		"local-zone: \"ads.example.com.\" always_nxdomain",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("unbound config missing %q\n--- got ---\n%s", w, out)
		}
	}
	if strings.Contains(out, "forward-zone") {
		t.Errorf("default should be recursive (no forward-zone)\n%s", out)
	}
	if strings.Contains(out, "log-queries") {
		t.Errorf("log-queries should be off by default")
	}
}

func TestGenerateUnboundConfigForwarding(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "8.8.8.8"}
	out := GenerateUnboundConfig(cfg, nil)
	for _, w := range []string{"forward-zone:", "forward-addr: 1.1.1.1", "forward-addr: 8.8.8.8"} {
		if !strings.Contains(out, w) {
			t.Errorf("forwarding config missing %q\n%s", w, out)
		}
	}
}

func TestParseKeaLeases(t *testing.T) {
	sample := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.3.50,aa:bb:cc:dd:ee:ff,,43200,1782500000,1,0,0,pc-joao,0,,0
192.168.3.61,11:22:33:44:55:66,,43200,1782500100,1,0,0,,0,,0
192.168.3.99,99:99:99:99:99:99,,43200,1782400000,1,0,0,old,1,,0
`
	got := ParseKeaLeases(sample)
	if len(got) != 2 { // the state=1 row is excluded
		t.Fatalf("expected 2 active leases, got %d: %+v", len(got), got)
	}
	if got[0].IP != "192.168.3.50" || got[0].Hostname != "pc-joao" || got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("lease 0 wrong: %+v", got[0])
	}
	if got[1].IP != "192.168.3.61" || got[1].Hostname != "" {
		t.Errorf("lease 1 wrong: %+v", got[1])
	}
}
