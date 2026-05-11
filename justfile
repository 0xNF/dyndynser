# Install required dev tools (run this first)
setup:
    @command -v mise > /dev/null || { echo "Install mise first: https://mise.jdx.dev"; exit 1; }
    mise install


# Run all checks (CI-friendly)
check: fmt-check lint test
    @echo "All checks passed ✓"

fmt-check:
    cargo fmt -- --check

lint:
    cargo clippy -- -D warnings

test:
    cargo test
