// Package hosts maps the host names users type to clusters and nodes.
//
// Accepted spellings, for a cluster "dev0-hetz" whose jump host is
// "jump.dev0-hetz.tvbeat.com":
//
//	scoria.dev0-hetz          node "scoria" via the dev0-hetz jump host
//	dev0-hetz+scoria.node     legacy spelling of the same node
//	dev0-hetz                 the jump host itself
//	jump.dev0-hetz.tvbeat.com the jump host itself
package hosts

import (
	"strings"

	"github.com/tvbeat/tvbeat-ssh/internal/site"
)

// Target is a parsed host name.
type Target struct {
	Cluster *site.Cluster
	// Node is the bare node name, empty when the target is the jump host.
	Node string
}

// IsJump reports whether the target is the cluster's jump host.
func (t Target) IsJump() bool { return t.Node == "" }

// DialAddr is the address the jump host should dial to reach the node.
func (t Target) DialAddr(port string) string {
	return t.Node + t.Cluster.NodeSuffix + ":" + port
}

// Principals are the host certificate principals a node or jump host must
// carry so every accepted spelling verifies.
func Principals(c *site.Cluster, node string) []string {
	if node == "" {
		return []string{c.JumpHost(), c.Name}
	}
	return []string{
		node + "." + c.Name,
		c.Name + "+" + node + c.NodeSuffix,
	}
}

// Parse resolves a host name. It never touches the network.
func Parse(s *site.Site, host string) (Target, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return Target{}, false
	}
	for i := range s.Clusters {
		c := &s.Clusters[i]
		name := strings.ToLower(c.Name)

		switch {
		case host == name || host == strings.ToLower(c.JumpHost()):
			return Target{Cluster: c}, true

		case strings.HasPrefix(host, name+"+"):
			// legacy: dev0-hetz+scoria.node
			node := strings.TrimPrefix(host, name+"+")
			node = strings.TrimSuffix(node, strings.ToLower(c.NodeSuffix))
			if validNode(node) {
				return Target{Cluster: c, Node: node}, true
			}

		case strings.HasSuffix(host, "."+name):
			node := strings.TrimSuffix(host, "."+name)
			if validNode(node) {
				return Target{Cluster: c, Node: node}, true
			}
		}
	}
	return Target{}, false
}

func validNode(n string) bool {
	if n == "" || len(n) > 63 {
		return false
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return n[0] != '-' && n[len(n)-1] != '-'
}

// KnownHostsPatterns returns the known_hosts host patterns covering every
// spelling for a cluster.
func KnownHostsPatterns(c *site.Cluster) []string {
	return []string{
		"*." + c.Name,
		c.Name + "+*",
		c.Name,
		c.JumpHost(),
	}
}
