package stresstest

import "testing"

func TestFinalizeSummary(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{
		Samples: []Sample{
			{Phase: "baseline", Ping: true, DNS: true}, // excluded from summary
			{Phase: "fault", Ping: true, DNS: true},
			{Phase: "fault", Ping: false, DNS: true}, // 1 ping loss
			{Phase: "recovery", Ping: true, DNS: false}, // 1 dns loss
			{Phase: "recovery", Ping: true, DNS: true},
		},
	}
	s.finalize(test, false)

	// 4 non-baseline samples; 1 ping fail = 25%, 1 dns fail = 25%.
	if test.PingLossPct != 25 {
		t.Errorf("ping loss = %.0f, want 25", test.PingLossPct)
	}
	if test.DNSLossPct != 25 {
		t.Errorf("dns loss = %.0f, want 25", test.DNSLossPct)
	}
	if test.State != "done" || !test.Restored {
		t.Errorf("state=%q restored=%v, want done/true", test.State, test.Restored)
	}
}

func TestFinalizeAborted(t *testing.T) {
	s := &Service{nowFn: func() string { return "00:00:00" }}
	test := &Test{Samples: []Sample{{Phase: "fault", Ping: true, DNS: true}}}
	s.finalize(test, true)
	if test.State != "aborted" {
		t.Errorf("state=%q, want aborted", test.State)
	}
}
