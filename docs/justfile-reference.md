# Justfile Command Reference

This project uses [just](https://github.com/casey/just) as a command runner for common development tasks.

## Installation

Install `just` if you haven't already:

```bash
# macOS/Linux
brew install just

# Cargo (Rust)
cargo install just

# Or download from: https://github.com/casey/just/releases
```

## Available Commands

Run `just` or `just --list` to see all available commands.

### Setup & Installation

```bash
# Set up virtual environment
just setup

# Install project with development dependencies
just install
```

**What it does:**
- `setup`: Creates `.venv` directory with uv
- `install`: Installs the project in editable mode with dev dependencies

### Testing

```bash
# Run all tests
just test

# Run tests with coverage report (terminal + HTML)
just test-cov

# Run specific test file
just test-file tests/unit/test_redirect_uri.py
```

**What it does:**
- `test`: Runs pytest on all test files
- `test-cov`: Runs pytest with coverage, generates `htmlcov/` directory
- `test-file FILE`: Runs pytest on a specific test file with verbose output

### Code Quality

```bash
# Type check with mypy
just typecheck

# Lint with ruff
just lint

# Format code with black
just format

# Run all quality checks (typecheck + lint)
just quality
```

**What it does:**
- `typecheck`: Runs mypy on `src/` directory
- `lint`: Runs ruff linter on `src/` directory
- `format`: Formats code in `src/` and `tests/` with black
- `quality`: Runs typecheck and lint in sequence

### Analysis & Reports

```bash
# Analyze local test files in excluded/
just analyze

# Analyze with specific grouping (severity, realm, or client)
just analyze-group-by client

# Generate HTML report
just report-html

# Generate HTML report with custom output path
just report-html my-report.html

# Generate JSON report
just report-json

# Generate JSON report with custom output path
just report-json my-report.json

# Generate all report formats (JSON + HTML)
just report-all

# Generate all reports with custom prefix
just report-all my-reports
```

**What it does:**
- `analyze`: Runs keycloak-analyzer on `excluded/` directory (console output)
- `analyze-group-by MODE`: Analyzes with specific grouping mode
- `report-html [OUTPUT]`: Generates HTML report (default: report.html)
- `report-json [OUTPUT]`: Generates JSON report (default: report.json)
- `report-all [PREFIX]`: Generates both JSON and HTML (default: report.json, report.html)

### Cleanup

```bash
# Clean up build artifacts, cache, and temporary files
just clean
```

**What it does:**
- Removes `.pytest_cache`, `.mypy_cache`, `.ruff_cache`
- Removes `htmlcov/` coverage reports
- Removes `build/`, `dist/`, `*.egg-info`
- Removes all `__pycache__` directories

### CI Pipeline

```bash
# Run full CI pipeline locally (test + quality)
just ci
```

**What it does:**
- Runs `just test` (all tests)
- Runs `just quality` (typecheck + lint)
- Useful for verifying all checks before pushing

## Common Workflows

### First Time Setup

```bash
just setup          # Create virtual environment
source .venv/bin/activate  # Activate environment
just install        # Install dependencies
just test           # Verify installation
```

### Before Committing

```bash
just format         # Format code
just ci             # Run tests + quality checks
```

### Adding a New Check

```bash
# 1. Write the check in src/keycloak_analyzer/checks/
# 2. Write tests in tests/unit/
just test-file tests/unit/test_my_new_check.py
just quality
just analyze
```

### Generating Reports

```bash
# Quick analysis
just analyze

# Generate all reports
just report-all security-audit

# This creates:
# - security-audit.json
# - security-audit.html
```

### Development Iteration

```bash
# Make code changes...
just format         # Format code
just test           # Run tests
just typecheck      # Check types
```

## Customizing Commands

The `justfile` is located at the project root. You can:

1. View the source: `cat justfile`
2. Edit to add custom commands
3. Use variables: `just report-html my-custom-report.html`

## Tips

- **Tab completion**: Enable shell completion for just commands
- **Parallel execution**: just doesn't run commands in parallel by default
- **Command chaining**: Use `&&` to chain commands: `just test && just quality`
- **Help**: Each command has comments in the justfile explaining what it does

## Troubleshooting

**"command not found: just"**
- Install just: `brew install just` or download from GitHub releases

**"No module named keycloak_analyzer"**
- Ensure virtual environment is activated: `source .venv/bin/activate`
- Run `just install` to install the project

**Tests fail**
- Ensure dependencies are installed: `just install`
- Clear cache: `just clean && pytest --cache-clear`

## Related Documentation

- [README.md](../README.md) - User-facing documentation
- [AGENTS.md](../AGENTS.md) - Development guidelines for AI agents
- [just documentation](https://github.com/casey/just)
