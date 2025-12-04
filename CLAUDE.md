# Claude Code Instructions

When working on this project, refer to the appropriate documentation:

## Documentation Overview

| Document | Purpose | Audience |
|----------|---------|----------|
| [AGENTS.md](AGENTS.md) | Development guide, architecture, adding checks | AI Agents & Developers |
| [README.md](README.md) | Quick start, overview, links | New Users |
| [docs/usage-guide.md](docs/usage-guide.md) | CLI usage, workflows, examples | End Users |
| [docs/check-reference.md](docs/check-reference.md) | Complete security check list | Security Auditors |
| [docs/reports.md](docs/reports.md) | Report format details | All Users |
| [JUSTFILE-QUICKSTART.md](JUSTFILE-QUICKSTART.md) | Just command reference | Developers |

## Quick Reference

**Setup:**
```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

**Common Tasks:**
```bash
just test              # Run tests
just quality           # Type check + lint
just analyze           # Analyze excluded/
just ci                # Full CI pipeline
```

**Direct Commands:**
```bash
pytest                 # Run tests
mypy src/              # Type check
ruff check src/        # Lint
black src/ tests/      # Format
```

**Key Principles:**
- Always use `uv` for Python package management
- Run tests before committing
- Follow security check patterns in `src/keycloak_analyzer/checks/`
- Document new checks in `docs/check-reference.md`

**Project Structure:**
- `src/keycloak_analyzer/checks/` - Security check implementations
- `src/keycloak_analyzer/models/` - Pydantic data models
- `src/keycloak_analyzer/reports/` - Console, JSON, HTML reporters
- `src/keycloak_analyzer/core/` - File discovery, analysis orchestration
- `tests/unit/` - Unit tests for checks and components

For comprehensive development guidelines, see [AGENTS.md](AGENTS.md).
