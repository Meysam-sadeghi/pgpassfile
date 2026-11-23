# Security Patches & Optimizations (`Meysam-sadeghi/pgpassfile`)

Base Upstream: `github.com/jackc/pgpassfile@v1.0.0`

| ID | Severity | CWE | File / Symbol | Summary |
|---|---|---|---|---|
| SEC-PGPASS-01 | HIGH | CWE-732 | `pgpass.go` (`ReadPassfile`), `permissions_unix.go`, `permissions_windows.go` | Enforces regular-file check (`IsRegular()`) and Unix `0600` (`mode & 0o077 == 0`) permission validation via FD `Stat()` (TOCTOU-safe) matching `libpq` `.pgpass` security rules. |
| SEC-PGPASS-02 | MEDIUM | CWE-400 | `pgpass.go` (`ReadPassfile`, `ParsePassfile`) | Rejects `nil` readers, caps input size to 4 MiB (`maxPassfileBytes`), max line length to 64 KiB (`maxPassfileLineBytes`), and max entries to 100,000 (`maxPassfileEntries`). |
| SEC-PGPASS-03 | MEDIUM | CWE-172 / CWE-1333 | `pgpass.go` (`parseLine`) | Replaces sentinel `\r`/`\n` replacement trick with a single-pass escape-aware byte scanner, preventing `\r` password corruption and removing dead global `colonSplitterRegexp` + `"regexp"` import. |
| SEC-PGPASS-04 | LOW | CWE-476 | `pgpass.go` (`Passfile.FindPassword`) | Adds `nil` receiver guard returning `""` instead of panicking. |
