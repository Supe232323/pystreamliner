# security policy

## supported versions

only the latest release is supported. older versions do not receive security updates.

| version   | supported          |
| --------- | ------------------ |
| v1.21.2   | :white_check_mark: |
| < v1.21.2 | :x:                |

## reporting a vulnerability

if you discover a security vulnerability, **do not open a public issue**.

please report it privately by contacting the maintainer directly. Include:

- a clear description of the issue
- steps to reproduce
- potential impact

once notified, the repository may be temporarily made private while a fix is prepared. always use the latest release.

## scope

pystreamliner is a local, zero-dependency source code analysis tool. it does not make network requests, execute analyzed code, or process untrusted input beyond reading the files you explicitly point it at. the main risks are the normal ones associated with any CLI tool that can rewrite files (use `--dry-run` when unsure).
