#!/bin/bash

# Script to install git hooks for the ping-async project
# Run this script from the project root directory

set -e

echo "Installing git hooks for ping-async..."

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash

# Pre-commit hook to run formatting and clippy checks
# This mirrors the CI checks from .github/workflows/rust.yml

set -e

echo "Running pre-commit checks..."

# Check formatting
echo "Checking code formatting..."
if ! cargo fmt --all -- --check; then
    echo "Code formatting check failed!"
    echo "Run 'cargo fmt --all' to fix formatting issues."
    exit 1
fi
echo "Code formatting check passed!"

# Run clippy
echo "Running clippy checks..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    echo "Clippy check failed!"
    echo "Fix the clippy warnings before committing."
    exit 1
fi
echo "Clippy check passed!"

echo "All pre-commit checks passed!"
EOF

# Install pre-push hook
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash

# Pre-push hook to run tests
# This mirrors the test checks from .github/workflows/rust.yml

set -e

echo "Running pre-push checks..."

# Run tests
echo "Running tests..."
if ! cargo test --verbose; then
    echo "Tests failed!"
    echo "Fix the failing tests before pushing."
    exit 1
fi
echo "Tests passed!"

echo "All pre-push checks passed!"
EOF

# Make hooks executable
chmod +x .git/hooks/pre-commit .git/hooks/pre-push

echo "Git hooks installed successfully!"
echo ""
echo "The following hooks are now active:"
echo "  - pre-commit: Runs 'cargo fmt --check' and 'cargo clippy'"
echo "  - pre-push: Runs 'cargo test --verbose'"
echo ""
echo "These hooks mirror the CI checks and will help catch issues early."