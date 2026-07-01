package handlers

import "testing"

// validDomain guards values concatenated into unbound.conf. It must accept the
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
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
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
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}
