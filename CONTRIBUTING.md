# Contributing to Purple AI Sandbox

First off, thank you for considering contributing to Purple! It's people like you that make open source such a great community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
  - [Git Commit Messages](#git-commit-messages)
  - [Rust Style Guide](#rust-style-guide)
  - [Documentation Style](#documentation-style)
- [Testing](#testing)
- [Release Process](#release-process)
- [Maintainers](#maintainers)

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the [issue list](https://github.com/your-org/purple/issues) to see if the issue has already been reported.

**Bug reports should include:**

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs. actual behavior
- Environment details (OS, Rust version, etc.)
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Provide the following information:

- A clear and descriptive title
- A detailed description of the proposed enhancement
- Use cases and benefits
- Any relevant examples or mockups

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies**: `cargo build`
3. **Make your changes** following our style guidelines
4. **Add tests** for your changes
5. **Update documentation** if applicable
6. **Run tests**: `cargo test`
7. **Create a Pull Request** with a clear title and description

## Development Setup

### Prerequisites

- Rust 1.60+ (recommended: latest stable)
- Linux kernel with namespace and cgroup support
- Git
- Cargo

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/purple.git
cd purple

# Build the project
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --no-deps --open
```

### Development Tools

- **Formatting**: `cargo fmt`
- **Linting**: `cargo clippy`
- **Testing**: `cargo test`
- **Benchmarking**: `cargo bench`

## Style Guidelines

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally

**Good commit message:**
```
Add seccomp filtering for syscall restrictions

Implement comprehensive seccomp integration with policy-based
syscall filtering. Includes 450+ syscall mappings and detailed
logging of filtering decisions.

Fixes #42
```

### Rust Style Guide

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `snake_case` for functions and variables
- Use `UpperCamelCase` for types and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefer idiomatic Rust patterns
- Use proper error handling with `Result` and `Option`

### Documentation Style

- Use Rustdoc comments (`///`) for public API documentation
- Include examples in documentation where possible
- Use clear, concise language
- Document safety requirements with `// Safety:` comments

## Testing

### Unit Tests

- Place unit tests in the same file as the code being tested
- Use `#[test]` attribute
- Follow the `test_*` naming convention
- Test both happy paths and error cases

### Integration Tests

- Place integration tests in the `tests/` directory
- Test interactions between components
- Use realistic scenarios

### Test Coverage

- Aim for 80%+ code coverage
- Focus on critical paths and edge cases
- Use `cargo tarpaulin` for coverage reports

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: Backwards-compatible features
- **PATCH**: Backwards-compatible bug fixes

### Release Checklist

1. Update `CHANGELOG.md`
2. Update version in `Cargo.toml`
3. Create GitHub release with notes
4. Publish crate to crates.io (if applicable)
5. Update documentation
6. Announce release

## Maintainers

- **Project Lead**: [Your Name](https://github.com/your-username)
- **Core Team**: [Team Members](https://github.com/orgs/your-org/teams/core)
- **Security Team**: [security@purple-sandbox.io](mailto:security@purple-sandbox.io)

## Questions?

If you have any questions about contributing, please:
- Check our [documentation](https://github.com/your-org/purple/wiki)
- Ask in our [Discussions](https://github.com/your-org/purple/discussions)
- Contact the maintainers

Thank you for contributing to Purple AI Sandbox! 🚀