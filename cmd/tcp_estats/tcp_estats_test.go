package main

import "testing"

func TestTableString(t *testing.T) {
	// setup
	tab := Table[ExtrasVar]{M: make(map[ExtrasVar]uint32)}
	tab.RLock()
	tab.M[EXTRAS_TABLE_PRIORITY] = 42
	tab.RUnlock()

	got := tableString(tab)

	want := "+-----------------------+----------+\n" +
		"| EXTRAS_TABLE_PRIORITY |       42 |\n" +
		"+-----------------------+----------+"

	if got != want {
		t.Errorf("want\n%q\ngot\n%q", want, got)
	}
}
