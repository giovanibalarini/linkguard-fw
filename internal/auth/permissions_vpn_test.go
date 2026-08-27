package auth

import "testing"

func TestVPNPermissionsAreCataloguedAndNotGrantedToNonAdminDefaults(t *testing.T) {
	for _, p := range []Permission{PermVPNRead, PermVPNWrite, PermVPNEnroll} {
		if !IsValidPermission(string(p)) {
			t.Errorf("VPN permission %q is not assignable through the catalog", p)
		}
	}
	for _, role := range DefaultRoles {
		if role.ID == "role-admin" {
			continue
		}
		for _, got := range role.Permissions {
			if got == PermVPNRead || got == PermVPNWrite || got == PermVPNEnroll {
				t.Errorf("existing default role %q gained sensitive VPN permission %q", role.Name, got)
			}
		}
	}
}
