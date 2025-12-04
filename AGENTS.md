# Agent Guidelines for Keycloak Configuration Security Analyzer

This document provides guidelines for AI coding agents (like Claude Code, GitHub Copilot, etc.) working on this project.

## Project Overview

This is a Python CLI tool that performs static security analysis of Keycloak realm configurations against OAuth 2.0 and OpenID Connect security best practices.

**Key Technologies:**
- Python 3.9+ (tested with 3.14)
- Click (CLI framework)
- Pydantic (data validation)
- Rich (terminal output)
- Jinja2 (HTML report generation)

## Python Environment Setup

**IMPORTANT: Always use `uv` for Python package management in this project.**

```bash
# Create virtual environment
uv venv

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install development dependencies
uv pip install -e ".[dev]"
```

### Why uv?
- Faster package resolution and installation than pip
- Better dependency conflict resolution
- Consistent development environment across contributors

## Project Structure

```
met-keycloak-config-verifyer/
├── src/keycloak_analyzer/
│   ├── core/           # File discovery, loading, analysis orchestration
│   ├── models/         # Pydantic models (Realm, Client, Finding)
│   ├── checks/         # Security check implementations
│   ├── reports/        # Report generators (Console, JSON, HTML)
│   └── cli.py          # Click CLI entry point
├── tests/
│   ├── fixtures/       # Sample Keycloak realm exports
│   ├── unit/           # Unit tests for each module
│   └── integration/    # End-to-end integration tests
├── docs/               # Additional documentation
├── excluded/           # Local test files (gitignored)
└── pyproject.toml      # Project configuration
```

## Running the Analyzer

```bash
# Analyze a directory containing realm exports
keycloak-analyzer ./path/to/realms

# Generate HTML report
keycloak-analyzer ./path/to/realms --format html --output report.html

# Generate JSON report
keycloak-analyzer ./path/to/realms --format json --output report.json

# Test locally (excluded folder is gitignored)
keycloak-analyzer excluded/
```

## Just Command Runner

The project includes a `justfile` with common commands. Install [just](https://github.com/casey/just):

```bash
# Install just (if not already installed)
# macOS/Linux
brew install just
# Or: cargo install just

# Show all available commands
just

# Common commands
just test              # Run all tests
just test-cov          # Run tests with coverage
just quality           # Type check + lint
just analyze           # Analyze excluded/ folder
just report-html       # Generate HTML report
just ci                # Run full CI pipeline locally
```

## Grouping Findings

The analyzer supports three grouping modes:

```bash
# Group by severity (default) - findings grouped by Critical, High, Medium, Low, Info
keycloak-analyzer excluded/

# Group by realm - findings organized by realm, then severity within each realm
keycloak-analyzer excluded/ --group-by realm

# Group by client - hierarchical: Realm → Client → Findings
keycloak-analyzer excluded/ --group-by client

# Generate HTML report with client grouping
keycloak-analyzer excluded/ --format html --output report.html --group-by client
```

**Note:** When grouping by client, realm-level findings (where `client_id` is None) are excluded from the output. Use `--group-by severity` or `--group-by realm` to see all findings including realm-level issues.

## Testing

**With Just:**
```bash
just test              # Run all tests
just test-cov          # Run tests with coverage
just test-file tests/unit/test_checks.py  # Run specific test file
```

**Direct pytest:**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov

# Run specific test file
pytest tests/unit/test_checks.py

# Run specific test
pytest tests/unit/test_checks.py::test_pkce_enforcement
```

## Code Quality Tools

**With Just:**
```bash
just quality           # Type check + lint
just typecheck         # Type checking only
just lint              # Linting only
just format            # Format code
```

**Direct commands:**
```bash
# Type checking
mypy src/

# Linting
ruff check src/

# Code formatting
black src/ tests/
```

## Adding New Security Checks

When adding new security checks:

1. **Create check class** in `src/keycloak_analyzer/checks/`
   - Inherit from base check class
   - Implement check logic
   - Define severity, references, and remediation

2. **Add check ID** following the pattern:
   - `KC-CATEGORY-###` (e.g., `KC-PKCE-001`)
   - Categories: PKCE, FLOW, REDIR, TLS, TOKEN, AUTH, SEC, INFO, BP

3. **Include RFC/CVE references** in the check metadata

4. **Write unit tests** in `tests/unit/`

5. **Update check reference** in `docs/check-reference.md`

See `docs/adding-checks.md` for detailed instructions.

## Security Standards

This tool enforces security based on:
- **RFC 9700** - OAuth 2.0 Security Best Current Practice
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **OAuth 2.1** - Modern OAuth security requirements
- **OpenID Connect Core 1.0**
- **FAPI 2.0** - Financial-grade API security

When modifying checks, ensure they align with these standards.

## Code Style

- **Line length:** 100 characters
- **Python version:** 3.9+ (for compatibility)
- **Type hints:** Required for all functions
- **Docstrings:** Required for public APIs
- **Naming:** snake_case for functions/variables, PascalCase for classes

## Common Development Tasks

### Testing a New Check

```bash
# 1. Add check implementation in src/keycloak_analyzer/checks/
# 2. Add test fixture in tests/fixtures/ if needed
# 3. Write unit test in tests/unit/
# 4. Run specific test
pytest tests/unit/test_new_check.py -v

# 5. Test against real realm export
keycloak-analyzer excluded/
```

### Debugging Output

```bash
# Enable debug logging (if implemented)
export LOG_LEVEL=DEBUG
keycloak-analyzer ./realms

# Use Rich console for debugging
from rich.console import Console
console = Console()
console.print(data)
```

### Working with Realm Exports

- Realm exports are large JSON files (often 100KB+)
- Test files should be placed in `excluded/` (gitignored)
- Use sample fixtures in `tests/fixtures/` for unit tests
- Real realm exports may contain sensitive data - never commit them

## Git Workflow

```bash
# Create feature branch
git checkout -b feature/new-security-check

# Make changes, commit
git add .
git commit -m "Add KC-NEW-001: Description of check"

# Run tests before pushing
pytest

# Push and create PR
git push origin feature/new-security-check
```

## CI/CD

The project uses GitHub Actions for:
- Running tests on multiple Python versions
- Type checking with mypy
- Linting with ruff
- Code formatting verification with black

All checks must pass before merging.

## Performance Considerations

- Large realm exports can contain 100+ clients
- Each check runs against each client
- Use efficient Pydantic models for data access
- Avoid unnecessary iterations over large data structures

## Documentation

- Keep README.md updated with user-facing changes
- Update `docs/check-reference.md` when adding checks
- Add examples for new features
- Document breaking changes clearly

## Troubleshooting

### uv not found
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Module not found errors
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall in editable mode
uv pip install -e ".[dev]"
```

### Test failures
```bash
# Clear pytest cache
pytest --cache-clear

# Run with verbose output
pytest -vv

# Run single test for debugging
pytest tests/path/to/test.py::test_name -vv
```

## Additional Resources

- [README.md](README.md) - User-facing documentation
- [docs/check-reference.md](docs/check-reference.md) - Complete check documentation
- [docs/adding-checks.md](docs/adding-checks.md) - Guide for adding new checks
- [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) - OAuth 2.0 Security BCP
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

## Contact

For questions or issues, open a GitHub issue or contact hello@kristofferopsahl.com
