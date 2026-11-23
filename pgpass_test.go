package pgpassfile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unescape(s string) string {
	s = strings.Replace(s, `\:`, `:`, -1)
	s = strings.Replace(s, `\\`, `\`, -1)
	return s
}

var passfile = [][]string{
	{"test1", "5432", "larrydb", "larry", "whatstheidea"},
	{"test1", "5432", "moedb", "moe", "imbecile"},
	{"test1", "5432", "curlydb", "curly", "nyuknyuknyuk"},
	{"test2", "5432", "*", "shemp", "heymoe"},
	{"test2", "5432", "*", "*", `test\\ing\:`},
	{"localhost", "*", "*", "*", "sesam"},
	{"test3", "*", "", "", "swordfish"}, // user will be filled later
}

func TestParsePassFile(t *testing.T) {
	buf := bytes.NewBufferString(`# A comment
	test1:5432:larrydb:larry:whatstheidea
	test1:5432:moedb:moe:imbecile
	test1:5432:curlydb:curly:nyuknyuknyuk
	test2:5432:*:shemp:heymoe
	test2:5432:*:*:test\\ing\:
	localhost:*:*:*:sesam
		`)

	passfile, err := ParsePassfile(buf)
	require.Nil(t, err)

	assert.Len(t, passfile.Entries, 6)

	assert.Equal(t, "whatstheidea", passfile.FindPassword("test1", "5432", "larrydb", "larry"))
	assert.Equal(t, "imbecile", passfile.FindPassword("test1", "5432", "moedb", "moe"))
	assert.Equal(t, `test\ing:`, passfile.FindPassword("test2", "5432", "something", "else"))
	assert.Equal(t, "sesam", passfile.FindPassword("localhost", "9999", "foo", "bare"))

	assert.Equal(t, "", passfile.FindPassword("wrong", "5432", "larrydb", "larry"))
	assert.Equal(t, "", passfile.FindPassword("test1", "wrong", "larrydb", "larry"))
	assert.Equal(t, "", passfile.FindPassword("test1", "5432", "wrong", "larry"))
	assert.Equal(t, "", passfile.FindPassword("test1", "5432", "larrydb", "wrong"))
}

func TestReadPassfilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bit checks do not apply on Windows")
	}

	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.pgpass")
	require.NoError(t, os.WriteFile(validPath, []byte("db.internal:5432:app:alice:s3cr3t\n"), 0o600))

	pf, err := ReadPassfile(validPath)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", pf.FindPassword("db.internal", "5432", "app", "alice"))

	for _, perm := range []os.FileMode{0o640, 0o644, 0o604, 0o777} {
		badPath := filepath.Join(dir, "bad.pgpass")
		_ = os.Remove(badPath)
		require.NoError(t, os.WriteFile(badPath, []byte("localhost:5432:db:u:p\n"), 0o600))
		require.NoError(t, os.Chmod(badPath, perm))
		_, err := ReadPassfile(badPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insecure file permissions")
	}

	_, err = ReadPassfile(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regular file")
}

func TestParsePassfileEscapesAndControlChars(t *testing.T) {
	// Ensure passwords containing literal \r or trailing extra colons behave safely.
	content := "h1:5432:db1:u1:pass\rword\n" +
		"h2:5432:db2:u2:a\\:b\\\\c\n" +
		"invalid:1:2:3:4:extra\n"
	pf, err := ParsePassfile(strings.NewReader(content))
	require.NoError(t, err)
	require.Len(t, pf.Entries, 2)
	assert.Equal(t, "pass\rword", pf.FindPassword("h1", "5432", "db1", "u1"))
	assert.Equal(t, `a:b\c`, pf.FindPassword("h2", "5432", "db2", "u2"))
}

func TestParsePassfileLimitsAndNilSafety(t *testing.T) {
	var nilPF *Passfile
	assert.Equal(t, "", nilPF.FindPassword("h", "5432", "d", "u"))

	_, err := ParsePassfile(nil)
	require.Error(t, err)

	oversized := strings.NewReader(strings.Repeat("a", maxPassfileBytes+64))
	_, err = ParsePassfile(oversized)
	require.Error(t, err)
}
