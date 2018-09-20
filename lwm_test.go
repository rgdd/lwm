package lwm

import (
	"bytes"
	"github.com/golang/example/stringutil"
	"testing"
)

var (
	twc = []byte{0xff}
)

func TestRadix(t *testing.T) {
	wt := NewWildcardTree(twc, hash, testData())

	// check in-order traversal (should be sorted)
	last := ""
	wt.r.WalkPrefix("", func(k string, v interface{}) bool {
		if last != "" && last < k {
			t.Errorf("radix order => found %v < %v", last, k)
		}
		return false
	})

	// check output of wildcard queries
	for _, table := range []struct {
		wildcard string   // matching criteria
		match    []string // list of in-order matching keys
	}{
		// no matches
		{stringutil.Reverse("net"), []string{}},
		{stringutil.Reverse("foo.net"), []string{}},
		{stringutil.Reverse("sub.baz.gov"), []string{}},
		// one match
		{stringutil.Reverse("gov"), []string{"vog.zab"}},
		{stringutil.Reverse("baz.gov"), []string{"vog.zab"}},
		{stringutil.Reverse("sub.qux.se"), []string{"es.xuq.bus"}},
		{stringutil.Reverse("sub.bar.edu"), []string{"ude.rab.bus"}},
		// many matches
		{stringutil.Reverse("qux.se"), []string{"es.xuq", "es.xuq.bus"}},
		{stringutil.Reverse("foo.com"), []string{
			"moc.oof", "moc.oof.1bus", "moc.oof.2bus"}},
	} {
		var match []string
		wt.r.WalkPrefix(table.wildcard, func(k string, v interface{}) bool {
			match = append(match, k)
			return false
		})

		if len(match) != len(table.match) {
			t.Errorf("radix tree => got %v, want %v", len(match), len(table.match))
			continue
		}

		for i, n := 0, len(match); i < n; i++ {
			if match[i] != table.match[i] {
				t.Errorf("radix tree => got %v, want %v", match[i], table.match[i])
			}
		}
	}
}

type wtExpect struct {
	key   string // query key
	index int    // expected left index
	n     int    // expected number of matches
	ll    bool   // expect left leaf
	rl    bool   // expect right leaf
}

func TestWildcardTree(t *testing.T) {
	// size == 0
	var m map[string]interface{} = nil
	wt := NewWildcardTree(twc, hash, m)
	snapshot := wt.Snapshot()
	for _, table := range []wtExpect{
		{"a", -1, 0, false, false},
		{"aa", -1, 0, false, false},
	} {
		answer, proof := wt.Get(table.key)
		wildcardTests(t, table, answer, proof, len(m), snapshot)
	}

	// size == 1
	m = make(map[string]interface{})
	m["b"] = [][]byte{[]byte("b cert")}
	wt = NewWildcardTree(twc, hash, m)
	snapshot = wt.Snapshot()
	for _, table := range []wtExpect{
		{"a", 0, 0, false, true},
		{"b", 0, 1, false, false},
		{"c", 0, 0, true, false},
		{"aa", 0, 0, false, true},
		{"bb", 0, 0, true, false},
		{"cc", 0, 0, true, false},
	} {
		answer, proof := wt.Get(table.key)
		wildcardTests(t, table, answer, proof, len(m), snapshot)
	}

	// size > 1
	m = testData()
	wt = NewWildcardTree(twc, hash, m)
	snapshot = wt.Snapshot()
	for _, table := range []wtExpect{
		{stringutil.Reverse("foo.com"), 1, 3, true, true},
		{stringutil.Reverse("sub1.foo.com"), 2, 1, true, true},
		{stringutil.Reverse("sub2.foo.com"), 3, 1, true, true},
		{stringutil.Reverse("sub0.foo.com"), 2, 0, true, true},
		{stringutil.Reverse("bar.se"), 0, 0, false, true},
		{stringutil.Reverse("foo.zzz"), 6, 0, true, false},
	} {
		answer, proof := wt.Get(table.key)
		wildcardTests(t, table, answer, proof, len(m), snapshot)
	}
}

func wildcardTests(t *testing.T, table wtExpect, answer Answer, proof Proof,
	size int, snapshot []byte) {
	// answer
	if n := len(answer.subject); n != table.n {
		t.Errorf("query matches (subject) => got %v, want %v", n, 0)
	}
	if n := len(answer.payload); n != table.n {
		t.Errorf("query matches (payload) => got %v, want %v", n, 0)
	}
	// twc
	if !bytes.Equal(twc, proof.twc) {
		t.Errorf("twc => got %v, want %v", proof.twc, twc)
	}
	// index
	if proof.index != table.index {
		t.Errorf("query index => got %v, want %v", proof.index, 0)
	}
	// left leaf
	if !table.ll && proof.ll != nil {
		t.Errorf("expected no left leaf")
	}
	if table.ll && proof.ll == nil {
		t.Errorf("expected left leaf but got none")
	}
	// right leaf
	if !table.rl && proof.rl != nil {
		t.Errorf("expected no right leaf")
	}
	if table.rl && proof.rl == nil {
		t.Errorf("expected right leaf but got none")
	}
	// range proof
	if !proof.Verify(table.key, answer, size, snapshot) {
		t.Errorf("Valid proof rejected for key %v and answer %v: ", table.key,
			answer.subject)
	}
}

// testData outputs test data according to the format that WildcardTree expects
func testData() map[string]interface{} {
	m := make(map[string]interface{})
	m[stringutil.Reverse("foo.com")] = [][]byte{
		[]byte("foo.com cert1"), []byte("foo.com cert2"),
	}
	m[stringutil.Reverse("sub1.foo.com")] = [][]byte{[]byte("sub1.foo.com cert")}
	m[stringutil.Reverse("sub2.foo.com")] = [][]byte{[]byte("sub2.foo.com cert")}
	m[stringutil.Reverse("sub.bar.edu")] = [][]byte{[]byte("sub.bar.edu cert")}
	m[stringutil.Reverse("baz.gov")] = [][]byte{[]byte("baz.gov cert")}
	m[stringutil.Reverse("qux.se")] = [][]byte{[]byte("qux.se cert")}
	m[stringutil.Reverse("sub.qux.se")] = [][]byte{[]byte("sub.qux.se cert")}
	return m
}
