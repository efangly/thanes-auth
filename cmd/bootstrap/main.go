// Command bootstrap creates the first SUPER user and the hidden tenant it belongs to. A hidden
// tenant (and its users and departments) is visible to SUPER only. It refuses to run once a
// SUPER exists. The password is read without echo, or from BOOTSTRAP_PASSWORD when stdin is
// not a terminal.
//
//	DATABASE_URL=... bootstrap --username <name> [--tenant siamatic] [--display <text>]
package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/term"

	"github.com/efangly/smtrack-authentication/config"
	"github.com/efangly/smtrack-authentication/internal/adapters/driven/security"
	"github.com/efangly/smtrack-authentication/internal/bootstrap"
)

func main() {
	username := flag.String("username", "", "username of the SUPER user (required)")
	tenant := flag.String("tenant", "siamatic", "name of the hidden tenant to create")
	display := flag.String("display", "", "display name of the SUPER user")
	flag.Parse()
	if err := run(*username, *tenant, *display); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(username, tenant, display string) error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required")
	}
	if username == "" {
		return errors.New("--username is required")
	}
	cost := config.MinBcryptCost
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < config.MinBcryptCost || n > 31 {
			return fmt.Errorf("BCRYPT_COST must be between %d and 31", config.MinBcryptCost)
		}
		cost = n
	}
	password, err := readPassword()
	if err != nil {
		return err
	}

	db, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	res, err := bootstrap.Run(context.Background(), db, security.NewBcryptHasher(cost), tenant, username, display, password)
	if err != nil {
		return err
	}
	fmt.Printf("created hidden tenant %q (%s) and SUPER user %q (%s)\n", tenant, res.TenantID, res.Username, res.UserID)
	return nil
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		if p := os.Getenv("BOOTSTRAP_PASSWORD"); p != "" {
			return p, nil
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password: set BOOTSTRAP_PASSWORD or run from a terminal")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}
