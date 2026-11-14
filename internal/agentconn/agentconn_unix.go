//go:build !windows

package agentconn

import (
	"errors"
	"net"
	"os"
	"time"
)

func dial() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, ErrNoAgent
	}
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, errors.Join(ErrNoAgent, err)
	}
	return c, nil
}
