package netif

import "testing"

func TestValidateIfaceStaticRequiresValidCIDR(t *testing.T) {
	cases := []struct {
		name    string
		iface   Iface
		wantErr bool
	}{
		{"static com CIDR válido", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24"}, false},
		{"static sem CIDR", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: ""}, true},
		{"static com CIDR malformado", Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "not-a-cidr"}, true},
		{"dhcp não exige CIDR", Iface{Name: "eth0", AddrMode: AddrModeDHCP, CIDR: ""}, false},
		{"none não exige CIDR", Iface{Name: "eth0", AddrMode: AddrModeNone, CIDR: ""}, false},
		{
			"gateway dentro da rede",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "192.168.3.1"},
			false,
		},
		{
			"gateway fora da rede",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "10.0.0.1"},
			true,
		},
		{
			"gateway malformado",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: "not-an-ip"},
			true,
		},
		{
			"sem gateway é válido (rede sem rota padrão por essa interface)",
			Iface{Name: "eth0", AddrMode: AddrModeStatic, CIDR: "192.168.3.3/24", Gateway: ""},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateIface(c.iface)
			if c.wantErr && err == nil {
				t.Errorf("esperava erro, não teve nenhum")
			}
			if !c.wantErr && err != nil {
				t.Errorf("não esperava erro, teve: %v", err)
			}
		})
	}
}
