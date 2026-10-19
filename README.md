# pathdoctor

A small, dependency-free CLI that audits your `PATH` for common problems: missing directories, duplicate entries, empty entries, non-absolute entries, and shadowed binaries.

## Features

- Detects directories in `PATH` that do not exist.
- Flags duplicate `PATH` entries.
- Flags empty entries (often caused by trailing colons).
- Flags non-absolute entries.
- Optionally reports binaries that are shadowed by earlier `PATH` entries.
- JSON output for scripting.
- Zero external dependencies.

## Install

```sh
pip install pathdoctor
```

Or run directly from source:

```sh
python -m pathdoctor
```

## Usage

```sh
# Audit the current PATH
pathdoctor

# Audit a custom PATH string
pathdoctor --path "/usr/bin:/usr/local/bin:/usr/bin"

# Also detect shadowed binaries
pathdoctor --shadow

# Machine-readable output
pathdoctor --json
```

Exit code is `1` when issues are found, `0` otherwise.

## License

MIT
