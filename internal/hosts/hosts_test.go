package hosts

import (
	"testing"

	"github.com/tvbeat/tvbeat-ssh/internal/site"
)

func TestParse(t *testing.T) {
	s := &site.Default
	tests := []struct {
		in      string
		ok      bool
		cluster string
		node    string
	}{
		{"scoria.dev0-hetz", true, "dev0-hetz", "scoria"},
		{"SCORIA.dev0-hetz.", true, "dev0-hetz", "scoria"},
		{"dev0-hetz+scoria.node", true, "dev0-hetz", "scoria"},
		{"prod0-hetz+onix.node", true, "prod0-hetz", "onix"},
		{"dev0-hetz", true, "dev0-hetz", ""},
		{"jump.dev0-hetz.tvbeat.com", true, "dev0-hetz", ""},
		{"github.com", false, "", ""},
		{"a.b.dev0-hetz", false, "", ""},
		{"-x.dev0-hetz", false, "", ""},
		{"x;rm.dev0-hetz", false, "", ""},
		{".dev0-hetz", false, "", ""},
		{"dev0-hetz+", false, "", ""},
		{"scoria.dev9-hetz", false, "", ""},
		{"", false, "", ""},
	}
	for _, tt := range tests {
		got, ok := Parse(s, tt.in)
		if ok != tt.ok {
			t.Errorf("Parse(%q) ok=%v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Cluster.Name != tt.cluster || got.Node != tt.node {
			t.Errorf("Parse(%q) = %s/%q, want %s/%q", tt.in, got.Cluster.Name, got.Node, tt.cluster, tt.node)
		}
	}
}

func TestDialAddrAndPrincipals(t *testing.T) {
	s := &site.Default
	tg, _ := Parse(s, "scoria.dev0-hetz")
	if got := tg.DialAddr("22"); got != "scoria.node:22" {
		t.Errorf("DialAddr = %q", got)
	}
	p := Principals(tg.Cluster, "scoria")
	if p[0] != "scoria.dev0-hetz" || p[1] != "dev0-hetz+scoria.node" {
		t.Errorf("node principals = %v", p)
	}
	p = Principals(tg.Cluster, "")
	if p[0] != "jump.dev0-hetz.tvbeat.com" || p[1] != "dev0-hetz" {
		t.Errorf("jump principals = %v", p)
	}
}
