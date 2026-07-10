package gre

import "testing"

func TestValidName(t *testing.T) {
	valid := []string{"grem", "grem0", "gremlin-a", "wg0", "a", "A_b-9", "abcdefghijklmno"}
	for _, n := range valid {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false, want true", n)
		}
	}
	invalid := []string{
		"",                 // empty
		"abcdefghijklmnop", // 16 chars, over IFNAMSIZ-1
		"gremlin/a",        // path separator
		"gremlin a",        // space
		"gremlin.a",        // dot
		"-eth",             // leading dash
		"_eth",             // leading underscore
		"eth$",             // shell metacharacter
	}
	for _, n := range invalid {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true, want false", n)
		}
	}
}
