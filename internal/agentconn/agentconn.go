// Package agentconn connects to the user's ssh-agent.
package agentconn

import (
	"errors"
	"io"

	"golang.org/x/crypto/ssh/agent"
)

// ErrNoAgent means no ssh-agent is reachable.
var ErrNoAgent = errors.New("no ssh-agent available")

// Agent is an agent client plus its connection.
type Agent struct {
	agent.ExtendedAgent
	conn io.Closer
}

// Close closes the connection to the agent.
func (a *Agent) Close() error { return a.conn.Close() }

// Connect connects to the user's agent.
func Connect() (*Agent, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	a := &Agent{ExtendedAgent: agent.NewClient(c), conn: c}
	// make sure it actually answers before we rely on it
	if _, err := a.List(); err != nil {
		c.Close()
		return nil, errors.Join(ErrNoAgent, err)
	}
	return a, nil
}
