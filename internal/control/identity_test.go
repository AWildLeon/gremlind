package control

import "testing"

func TestValidClientID(t *testing.T) {
	valid := []string{"site-a", "SITE_1", "client.42", "a"}
	for _, id := range valid {
		if !ValidClientID(id) {
			t.Errorf("ValidClientID(%q) = false", id)
		}
	}

	invalid := []string{"", "bad id", "bad\nid", "bad\x1bid", "slash/id", "colon:id", string(make([]byte, 65))}
	for _, id := range invalid {
		if ValidClientID(id) {
			t.Errorf("ValidClientID(%q) = true", id)
		}
	}
}
