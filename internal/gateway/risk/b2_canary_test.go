package risk

import "testing"

// B2 security canary: every supported delete spelling and the Windows
// recursive/force flags must remain non-green on an outside-temp target.
func TestCanary_B2_DeleteAliasesAndFlags(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		rule string
	}{
		{"rm", "rm -rf /var/lib/postgresql", "rm-recursive-outside-temp"},
		{"ri", "ri -r -f C:\\Users\\alice\\Documents", "remove-item-recursive-outside-temp"},
		{"Remove-Item", "Remove-Item -Recurse -Force C:\\Users\\alice\\Documents", "remove-item-recursive-outside-temp"},
		{"del", "del /s /q C:\\Data", "remove-item-recursive-outside-temp"},
		{"erase", "erase /S /Q C:\\Data", "remove-item-recursive-outside-temp"},
		{"rmdir", "rmdir /s /q C:\\Data", "remove-item-recursive-outside-temp"},
		{"rd", "RD /S /Q C:\\Data", "remove-item-recursive-outside-temp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.cmd)
			if got.Level != Red {
				t.Fatalf("%s canary: level=%s rule=%q reason=%q; want red", tc.name, got.Level, got.Rule, got.Reason)
			}
			if got.Rule != tc.rule {
				t.Fatalf("%s canary: rule=%q; want %q", tc.name, got.Rule, tc.rule)
			}
		})
	}
}

func TestCanary_B2_WindowsFlagsDoNotHideLaterPath(t *testing.T) {
	got := Classify(`rmdir /s /q C:\Temp\cache C:\Data`)
	if got.Level != Red {
		t.Fatalf("Windows multi-path canary: level=%s rule=%q reason=%q; want red", got.Level, got.Rule, got.Reason)
	}
	if got.Rule != "remove-item-recursive-outside-temp" {
		t.Fatalf("Windows multi-path canary: rule=%q; want remove-item-recursive-outside-temp", got.Rule)
	}
}
