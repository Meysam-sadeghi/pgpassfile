// Package pgpassfile is a parser PostgreSQL .pgpass files.
package pgpassfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	maxPassfileBytes     = 4 << 20   // 4 MiB upper bound on passfile size
	maxPassfileEntries   = 100_000   // maximum number of entries parsed
	maxPassfileLineBytes = 64 * 1024 // maximum line length
)

// Entry represents a line in a PG passfile.
type Entry struct {
	Hostname string
	Port     string
	Database string
	Username string
	Password string
}

// Passfile is the in memory data structure representing a PG passfile.
type Passfile struct {
	Entries []*Entry
}

// ReadPassfile reads the file at path and parses it into a Passfile.
func ReadPassfile(path string) (*Passfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("pgpassfile: file must be a regular file")
	}
	if err := checkPassfilePermissions(info); err != nil {
		return nil, err
	}
	if info.Size() > maxPassfileBytes {
		return nil, fmt.Errorf("pgpassfile: file size %d exceeds maximum %d bytes", info.Size(), maxPassfileBytes)
	}

	return ParsePassfile(f)
}

// ParsePassfile reads r and parses it into a Passfile.
func ParsePassfile(r io.Reader) (*Passfile, error) {
	if r == nil {
		return nil, errors.New("pgpassfile: reader must not be nil")
	}

	passfile := &Passfile{}
	lr := &io.LimitedReader{R: r, N: maxPassfileBytes + 1}

	scanner := bufio.NewScanner(lr)
	scanner.Buffer(make([]byte, 0, 4096), maxPassfileLineBytes)
	for scanner.Scan() {
		entry := parseLine(scanner.Text())
		if entry != nil {
			if len(passfile.Entries) >= maxPassfileEntries {
				return nil, fmt.Errorf("pgpassfile: entry count exceeds maximum %d", maxPassfileEntries)
			}
			passfile.Entries = append(passfile.Entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("pgpassfile: input exceeds maximum %d bytes", maxPassfileBytes)
	}

	return passfile, nil
}

// parseLine parses a line into an *Entry using a single-pass escape-aware scanner.
// It returns nil on comment lines, empty lines, or malformed lines.
func parseLine(line string) *Entry {
	line = strings.TrimSpace(line)

	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	var fields [5]string
	fieldIdx := 0
	var b strings.Builder
	b.Grow(len(line))

	for i := 0; i < len(line); {
		ch := line[i]
		if ch == '\\' && i+1 < len(line) {
			next := line[i+1]
			if next == '\\' || next == ':' {
				b.WriteByte(next)
				i += 2
				continue
			}
		}
		if ch == ':' {
			if fieldIdx >= 4 {
				// More than 5 colon-separated fields is invalid.
				return nil
			}
			fields[fieldIdx] = b.String()
			b.Reset()
			fieldIdx++
			i++
			continue
		}
		b.WriteByte(ch)
		i++
	}

	if fieldIdx != 4 {
		return nil
	}
	fields[4] = b.String()

	return &Entry{
		Hostname: fields[0],
		Port:     fields[1],
		Database: fields[2],
		Username: fields[3],
		Password: fields[4],
	}
}

// FindPassword finds the password for the provided hostname, port, database, and username. For a
// Unix domain socket hostname must be set to "localhost". An empty string will be returned if no
// match is found.
//
// See https://www.postgresql.org/docs/current/libpq-pgpass.html for more password file information.
func (pf *Passfile) FindPassword(hostname, port, database, username string) (password string) {
	if pf == nil {
		return ""
	}
	for _, e := range pf.Entries {
		if (e.Hostname == "*" || e.Hostname == hostname) &&
			(e.Port == "*" || e.Port == port) &&
			(e.Database == "*" || e.Database == database) &&
			(e.Username == "*" || e.Username == username) {
			return e.Password
		}
	}
	return ""
}
