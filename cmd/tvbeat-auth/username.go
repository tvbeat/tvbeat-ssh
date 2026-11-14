package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"

	"github.com/tvbeat/tvbeat-auth/internal/login"
	"github.com/tvbeat/tvbeat-auth/internal/site"
)

// usernameRe is what useradd accepts by default, minus the oddities. The
// name ends up in the generated ssh config, so anything else is refused.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

func validUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return fmt.Errorf("%q is not a valid linux username", u)
	}
	return nil
}

// discoverUsername signs in (reusing a valid token when there is one) and
// reads the person's linux username from their vault token: vault maps it
// from the Google Workspace custom attribute external.username at sign-in
// (claim_mappings "/external/username" = "username"). If the attribute is
// empty it asks, once, suggesting the local part of their email.
func discoverUsername(ctx context.Context, s *site.Settings) (string, error) {
	m := manager(s, login.Auto)
	m.Interactive = true // setup is run by a person
	v, err := m.EnsureToken(ctx)
	if err != nil {
		return "", err
	}
	ti, err := v.LookupSelf(ctx)
	if err != nil {
		return "", err
	}
	if u := strings.TrimSpace(ti.Meta["username"]); u != "" {
		if err := validUsername(u); err != nil {
			return "", fmt.Errorf("your account's linux username: %v - run `tvbeat-auth setup --username <name>`", err)
		}
		return u, nil
	}
	return askUsername(os.Stdin, os.Stderr, ti.Meta["email"], term.IsTerminal(int(os.Stdin.Fd())))
}

func askUsername(in io.Reader, out io.Writer, email string, tty bool) (string, error) {
	suggest := ""
	if i := strings.Index(email, "@"); i > 0 && validUsername(email[:i]) == nil {
		suggest = email[:i]
	}
	if !tty {
		return "", errors.New("your account has no linux username on record - run `tvbeat-auth setup --username <name>`")
	}
	r := bufio.NewReader(in)
	fmt.Fprintln(out, "Your account has no linux username on record (ask devops to add it).")
	for range 3 {
		fmt.Fprint(out, "Your username on tvbeat linux systems")
		if suggest != "" {
			fmt.Fprintf(out, " [%s]", suggest)
		}
		fmt.Fprint(out, ": ")
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			line = suggest
		}
		if line != "" {
			if verr := validUsername(line); verr == nil {
				return line, nil
			} else {
				fmt.Fprintf(out, "%v\n", verr)
			}
		}
		if err != nil {
			break
		}
	}
	return "", errors.New("no username given - run `tvbeat-auth setup --username <name>`")
}
