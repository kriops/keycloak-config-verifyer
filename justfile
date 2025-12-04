# Keycloak Configuration Security Analyzer - Just Commands
# See: https://github.com/casey/just

# Python executable (from virtual environment if available)
python := if path_exists(".venv/bin/python") == "true" { ".venv/bin/python" } else { "python3" }

# Keycloak analyzer executable
analyzer := if path_exists(".venv/bin/keycloak-analyzer") == "true" { ".venv/bin/keycloak-analyzer" } else { "keycloak-analyzer" }

# Default recipe - show available commands
default:
    @just --list

# Set up development environment
setup:
    @echo "Setting up development environment..."
    uv venv
    @echo "\nActivate virtual environment with:"
    @echo "  source .venv/bin/activate  # Linux/Mac"
    @echo "  .venv\\Scripts\\activate   # Windows"

# Install project in development mode
install:
    uv pip install -e ".[dev]"

# Run all tests
test:
    {{python}} -m pytest

# Run tests with coverage report
test-cov:
    {{python}} -m pytest --cov --cov-report=term-missing --cov-report=html

# Run specific test file
test-file FILE:
    {{python}} -m pytest {{FILE}} -v

# Type check with mypy
typecheck:
    {{python}} -m mypy src/

# Lint code with ruff
lint:
    {{python}} -m ruff check src/

# Format code with black
format:
    {{python}} -m black src/ tests/

# Run all quality checks (type, lint, format)
quality: typecheck lint
    @echo "✓ All quality checks passed"

# Analyze local test files in excluded/ directory
analyze:
    {{analyzer}} excluded/

# Analyze with specific grouping mode (severity|realm|client)
analyze-group-by MODE:
    {{analyzer}} excluded/ --group-by {{MODE}}

# Generate HTML report from excluded/ directory
report-html OUTPUT="report.html":
    {{analyzer}} excluded/ --format html --output {{OUTPUT}} --no-fail
    @echo "✓ Report generated: {{OUTPUT}}"

# Generate JSON report from excluded/ directory
report-json OUTPUT="report.json":
    {{analyzer}} excluded/ --format json --output {{OUTPUT}} --no-fail
    @echo "✓ Report generated: {{OUTPUT}}"

# Generate all report formats
report-all PREFIX="report":
    {{analyzer}} excluded/ --format all --output {{PREFIX}} --no-fail
    @echo "✓ Reports generated: {{PREFIX}}.json and {{PREFIX}}.html"

# Clean up build artifacts and cache
clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov
    rm -rf build dist *.egg-info
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    @echo "✓ Cleaned up build artifacts"

# Run the full CI pipeline locally (test + quality checks)
ci: test quality
    @echo "✓ All CI checks passed"
