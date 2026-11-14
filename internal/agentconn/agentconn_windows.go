package agentconn

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

// the Windows OpenSSH agent service listens on this named pipe
const pipe = `\\.\pipe\openssh-ssh-agent`

func dial() (net.Conn, error) {
	p := pipe
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		p = s
	}
	timeout := 5 * time.Second
	c, err := winio.DialPipe(p, &timeout)
	if err != nil {
		return nil, errors.Join(ErrNoAgent, err)
	}
	return c, nil
}
