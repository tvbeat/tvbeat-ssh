package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func hostCert(t *testing.T, ca ssh.Signer, principals []string) (ssh.PublicKey, *ssh.Certificate) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	c := &ssh.Certificate{
		Key: sp, CertType: ssh.HostCert, ValidPrincipals: principals,
		ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return sp, c
}

func TestHostKeyCallbackWithCA(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherPriv)

	kh := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(kh, []byte("@cert-authority *.dev0-hetz "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))+"\n"), 0o644)

	hk, err := hostKeyCallback(kh, "jump.dev0-hetz.tvbeat.com")
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}

	plain, good := hostCert(t, ca, []string{"jump.dev0-hetz.tvbeat.com", "dev0-hetz"})
	if err := hk.callback("jump.dev0-hetz.tvbeat.com:443", addr, good); err != nil {
		t.Errorf("valid host cert rejected: %v", err)
	}
	if err := hk.callback("jump.dev0-hetz.tvbeat.com:443", addr, plain); err == nil {
		t.Error("plain host key accepted although a host CA is configured")
	}
	_, wrongName := hostCert(t, ca, []string{"scoria.dev0-hetz"})
	if err := hk.callback("jump.dev0-hetz.tvbeat.com:443", addr, wrongName); err == nil {
		t.Error("host cert for another host accepted")
	}
	_, wrongCA := hostCert(t, other, []string{"jump.dev0-hetz.tvbeat.com"})
	if err := hk.callback("jump.dev0-hetz.tvbeat.com:443", addr, wrongCA); err == nil {
		t.Error("host cert from an unknown CA accepted")
	}
	if hk.algorithms[0] != ssh.CertAlgoED25519v01 {
		t.Error("certificate host key algorithms should be preferred")
	}
}

func TestHostKeyCallbackWithoutCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	hk, err := hostKeyCallback(filepath.Join(home, "missing"), "jump.x")
	if err != nil {
		t.Fatal(err)
	}
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	k1, _ := ssh.NewPublicKey(pub1)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	k2, _ := ssh.NewPublicKey(pub2)
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}

	if err := hk.callback("jump.x:443", addr, k1); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if !bytes.Contains(b, []byte("[jump.x]:443")) {
		t.Fatalf("not recorded: %s", b)
	}
	hk, _ = hostKeyCallback(filepath.Join(home, "missing"), "jump.x")
	if err := hk.callback("jump.x:443", addr, k1); err != nil {
		t.Errorf("known key rejected: %v", err)
	}
	if err := hk.callback("jump.x:443", addr, k2); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Errorf("changed key not refused: %v", err)
	}
}

func TestPipeHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// remote: read until our EOF, then answer and close
		data, _ := io.ReadAll(c)
		c.Write(append([]byte("echo:"), data...))
		c.Close()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- pipe(conn, strings.NewReader("hello"), &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipe did not finish")
	}
	if out.String() != "echo:hello" {
		t.Fatalf("got %q - output after our EOF was cut off", out.String())
	}
}
