package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// parentIsVaultLogin reports whether the vault command that ran us (vault
// runs the token helper through `sh -c`, which may or may not exec) is
// `vault login`.
func parentIsVaultLogin() bool {
	pid := os.Getppid()
	for range 3 {
		if pid <= 1 {
			return false
		}
		args := procArgs(pid)
		if len(args) > 0 {
			name := strings.TrimSuffix(filepath.Base(args[0]), "-wrapped")
			name = strings.TrimPrefix(name, ".")
			if name == "vault" {
				return vaultSubcommand(args[1:]) == "login"
			}
		}
		pid = procPPid(pid)
	}
	return false
}

func procArgs(pid int) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0}) {
		out = append(out, string(p))
	}
	return out
}

func procPPid(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// the command name in parentheses may contain spaces
	s := string(b)
	if i := strings.LastIndexByte(s, ')'); i >= 0 {
		f := strings.Fields(s[i+1:])
		if len(f) > 1 {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}
