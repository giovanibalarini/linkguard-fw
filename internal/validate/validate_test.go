package validate

import "testing"

// Domain guards values concatenated into unbound.conf. It must accept the
// legitimate shapes (single-label names, underscore labels, sub.domains) while
// rejecting anything that could break out of the config token.
func TestValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"lan",          // single-label DHCP suffix
		"localhost",    // single-label blocklist entry
		"ads",          // single-label blocklist entry
		"_dmarc.x.com", // underscore label
		"a-b.example.com",
	}
	for _, d := range valid {
		if !Domain(d) {
			t.Errorf("Domain(%q) = false, want true", d)
		}
	}

	invalid := []string{
		"",
		"a b",                         // space
		"evil\"; bad",                 // quote + semicolon (config injection)
		"a\nb",                        // newline
		"a/b",                         // slash
		".leading",                    // leading dot
		"trailing.",                   // trailing dot
		"-lead",                       // leading hyphen
		"UPPER.com is not lowercased", // space (also asserts we validate post-lowercase)
	}
	for _, d := range invalid {
		if Domain(d) {
			t.Errorf("Domain(%q) = true, want false", d)
		}
	}
}

// TestValidIface: o nome de interface é interpolado em kea-dhcp4.conf e em
// unidades do networkd; o charset é o do kernel (IFNAMSIZ-1 = 15 bytes), sem
// espaço, aspas ou quebra de linha.
func TestValidIface(t *testing.T) {
	for _, s := range []string{"eth0", "br10", "lg-wan-giga", "enp3s0.100", "a"} {
		if !Iface(s) {
			t.Errorf("Iface(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"",
		"this-interface-name-is-way-too-long", // > 15 bytes
		"eth0 extra",                          // espaço
		"eth0\nbad",                           // quebra de linha
		"eth0/../x",                           // barra
	} {
		if Iface(s) {
			t.Errorf("Iface(%q) = true, want false", s)
		}
	}
}

// TestValidNTPServer: o valor vai para o drop-in do chrony via formatação de
// string — hostname ou IP, sem espaço, aspas ou controle.
func TestValidNTPServer(t *testing.T) {
	for _, s := range []string{"pool.ntp.br", "a.st1.ntp.br", "192.168.3.3", "2001:db8::1"} {
		if !NTPServer(s) {
			t.Errorf("NTPServer(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"",
		"pool.ntp.br extra",        // espaço
		"pool.ntp.br\nserver evil", // injeção de diretiva
		"pool.ntp.br#comment",
	} {
		if NTPServer(s) {
			t.Errorf("NTPServer(%q) = true, want false", s)
		}
	}
}

// TestNormalizeMAC: normaliza para minúsculas e devolve "" no que não é MAC —
// o "" é o sinal de rejeição que os chamadores comparam.
func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF":   "aa:bb:cc:dd:ee:ff",
		"  aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff":   "aa-bb-cc-dd-ee-ff",
		"":                    "",
		"não-é-mac":           "",
		"aa:bb:cc:dd:ee":      "",
	} {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
