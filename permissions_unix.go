//go:build !windows

package pgpassfile

import (
	"fmt"
	"os"
)

// checkPassfilePermissions enforces PostgreSQL libpq security rules on Unix:
// .pgpass must not allow any access to group or world (mode & 0o077 == 0).
func checkPassfilePermissions(info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("pgpassfile: insecure file permissions %04o (must disallow group/world access, e.g. 0600)", perm)
	}
	return nil
}
