# Just Command Quick Reference

Quick reference card for common `just` commands in this project.

## Installation

```bash
# Install just
brew install just        # macOS/Linux
cargo install just       # Via Rust/Cargo

# Verify installation
just --version
```

## First Time Setup

```bash
just setup    # Create virtual environment
source .venv/bin/activate
just install  # Install dependencies
just test     # Verify installation
```

## Daily Development

```bash
# Show all commands
just

# Run tests
just test

# Before committing
just format
just test
```

## Analysis & Reports

```bash
# Analyze excluded/ folder
just analyze

# Generate reports
just report-html        # Creates report.html
just report-json        # Creates report.json
just report-all         # Creates both

# With custom paths
just report-html my-security-audit.html
just report-all security-audit
```

## Code Quality

```bash
just quality    # Type check + lint (recommended)
just typecheck  # Type checking only
just lint       # Linting only
just format     # Format code
```

## Testing

```bash
just test                           # All tests
just test-cov                       # With coverage
just test-file tests/unit/test_*.py # Specific file
```

## Other Commands

```bash
just clean  # Clean build artifacts
just ci     # Full CI pipeline (test + quality)
```

## Tips

- All commands use the virtual environment automatically
- No need to activate `.venv` manually for just commands
- Reports use `--no-fail` flag (won't error on findings)
- Use `just <command> --help` for command-specific help

## Common Workflows

### Quick Security Audit
```bash
just analyze
```

### Generate Client Report
```bash
just analyze-group-by client > analysis.txt
just report-html client-report.html
```

### Pre-Commit Check
```bash
just format && just ci
```

### Full Report Package
```bash
just report-all security-audit-2024
# Creates: security-audit-2024.json and security-audit-2024.html
```

---

**Full documentation**: See [docs/justfile-reference.md](docs/justfile-reference.md)
