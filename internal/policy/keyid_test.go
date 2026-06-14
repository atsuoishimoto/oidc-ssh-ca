package policy

import (
	"strings"
	"testing"
)

func TestExpandKeyID(t *testing.T) {
	claims := map[string]any{
		"repository":  "your-org/your-repo",
		"run_id":      "123456789",
		"run_attempt": "1",
	}
	got, err := ExpandKeyID("gha:${repository}:${run_id}:${run_attempt}", claims)
	if err != nil {
		t.Fatalf("ExpandKeyID: %v", err)
	}
	if got != "gha:your-org/your-repo:123456789:1" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandKeyIDDenies(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		errSub string
	}{
		{"missing claim", map[string]any{}, "not present"},
		{"non-string claim", map[string]any{"repository": 42}, "not a string"},
		{"newline injection", map[string]any{"repository": "a\nb"}, "outside"},
		{"space", map[string]any{"repository": "a b"}, "outside"},
		{"quote", map[string]any{"repository": `a"b`}, "outside"},
		{"empty value", map[string]any{"repository": ""}, "outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExpandKeyID("gha:${repository}", tc.claims)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("expected error containing %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestExpandKeyIDLengthLimit(t *testing.T) {
	claims := map[string]any{"repository": strings.Repeat("a", 300)}
	if _, err := ExpandKeyID("gha:${repository}", claims); err == nil {
		t.Fatal("expected length error")
	}
	claims["repository"] = strings.Repeat("a", MaxKeyIDLength-4)
	if _, err := ExpandKeyID("gha:${repository}", claims); err != nil {
		t.Fatalf("expected ok at limit, got %v", err)
	}
}

func TestTemplateVars(t *testing.T) {
	vars, err := templateVars("gha:${repository}:${run_id}")
	if err != nil {
		t.Fatalf("templateVars: %v", err)
	}
	if len(vars) != 2 || vars[0] != "repository" || vars[1] != "run_id" {
		t.Fatalf("vars = %v", vars)
	}
	for _, bad := range []string{"x:$repo", "x:${}", "x:${RePo!}", "x:${a b}"} {
		if _, err := templateVars(bad); err == nil {
			t.Errorf("templateVars(%q): expected error", bad)
		}
	}
}

func TestTemplateVarsRejectsBadLiterals(t *testing.T) {
	for _, bad := range []string{
		"gha:${repository}\nspoofed:${run_id}", // newline in literal
		"gha ${repository}",                    // space in literal
		"gha:${repository}#frag",               // disallowed punctuation
		"gha:${repository}\t",                  // tab
	} {
		if _, err := templateVars(bad); err == nil {
			t.Errorf("templateVars(%q): expected literal error", bad)
		}
	}
	// A template made entirely of variables has empty literals and is fine.
	if _, err := templateVars("${repository}${run_id}"); err != nil {
		t.Errorf("all-variable template should be valid: %v", err)
	}
}
