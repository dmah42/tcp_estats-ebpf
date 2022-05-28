package tcp_estats

import (
	"encoding/json"
	"testing"
)

func TestTableMarshal(t *testing.T) {
	// setup
	tab := Table{M: make(map[string]uint32)}
	tab.RLock()
	tab.M[EXTRAS_TABLE_PRIORITY.String()] = 42
	defer tab.RUnlock()

	got, err := json.Marshal(tab)
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	want := "{\"M\":{\"EXTRAS_TABLE_PRIORITY\":42}}"

	if string(got) != want {
		t.Errorf("want\n%q\ngot\n%q", want, got)
	}
}
