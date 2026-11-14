package proxy

import (
	"errors"
	"io"
	"net"
)

// pipe shuttles bytes between ssh (in/out) and conn. It returns once the
// remote side has finished sending; EOF from ssh only half-closes conn, so
// output still in flight is not cut off.
func pipe(conn net.Conn, in io.Reader, out io.Writer) error {
	go func() {
		io.Copy(conn, in)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			conn.Close()
		}
	}()
	_, err := io.Copy(out, conn)
	conn.Close()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
