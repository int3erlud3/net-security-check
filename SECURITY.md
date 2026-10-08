# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- Read-only: only query commands are executed; no files are written and no settings
  are changed. A test verifies that no modifying sub-command is ever invoked.
- All host/port arguments are validated against strict patterns before use; commands are
  never built through `eval` or a shell string.
- CI runs ShellCheck, the bats suite and a gitleaks secret scan on every push and pull
  request; GitHub Actions are pinned to commit SHAs and run with `contents: read` only.
