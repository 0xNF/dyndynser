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

# Build a release binary and package it (format: deb)
package format="deb" arch="amd64":
    cargo build --release
    just make-{{format}} {{arch}}

# Build just the .deb package (requires a release binary)
make-deb arch="amd64":
    bash packaging/debian/build.sh {{arch}}
