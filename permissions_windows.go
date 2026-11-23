//go:build windows

package pgpassfile

import "os"

// checkPassfilePermissions is a no-op on Windows, matching libpq behavior.
func checkPassfilePermissions(os.FileInfo) error {
	return nil
}
