# Contributing to Kalitelligence

Thank you for your interest in contributing to Kalitelligence! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and what behavior you expected**
* **Include screenshots if possible**
* **Include system information** (Kali version, Python version, etc.)

**Bug Report Template:**

```markdown
**Description:**
A clear and concise description of what the bug is.

**To Reproduce:**
Steps to reproduce the behavior:
1. Run command '...'
2. With options '....'
3. See error

**Expected behavior:**
A clear and concise description of what you expected to happen.

**Screenshots:**
If applicable, add screenshots to help explain your problem.

**System Information:**
- Kali Version: [e.g., 2024.3]
- Python Version: [e.g., 3.11.6]
- Script Version: [e.g., 2.0]

**Additional context:**
Add any other context about the problem here.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the suggested enhancement**
* **Explain why this enhancement would be useful**
* **List some examples of how this enhancement would be used**
* **Mention any similar features in other tools**

### Your First Code Contribution

Unsure where to begin contributing? You can start by looking through these `good first issue` and `help wanted` issues:

* **Good first issues** - Issues that should only require a few lines of code
* **Help wanted issues** - Issues that are more involved but still approachable

### Pull Requests

The process described here has several goals:

- Maintain project quality
- Fix problems that are important to users
- Engage the community in working toward the best possible product
- Enable a sustainable system for maintainers to review contributions

## Development Setup

### Prerequisites

- Kali Linux 2024.x or later
- Root access (for installation testing)
- Git
- Bash 5.x+
- Python 3.8+
- At least 10GB free disk space

### Fork & Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Kalitellingence.git
   cd Kalitellingence
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/Masriyan/Kalitellingence.git
   ```
4. Create a branch for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Development Environment

For development, use a test VM or container:

```bash
# Create a test directory
mkdir -p ~/test-kalitelligence
cd ~/test-kalitelligence

# Copy your modified script
cp /path/to/your/kalitelligence.sh .

# Test in isolated environment
sudo ./kalitelligence.sh --preset custom --debug
```

## Pull Request Process

### Before Submitting

1. **Test your changes thoroughly** in a clean Kali installation
2. **Ensure all existing tests pass** (if applicable)
3. **Update documentation** if you're changing functionality
4. **Add tests** for new features
5. **Run linting checks** on your code
6. **Squash commits** if you have multiple small commits

### PR Requirements

1. **Title**: Clear and descriptive (use conventional commits format)
   - `feat: add PDF report generation`
   - `fix: resolve race condition in parallel downloads`
   - `docs: update installation instructions`
   - `refactor: modularize tool installation functions`

2. **Description**: Include:
   - What changes were made
   - Why these changes were made
   - How to test the changes
   - Any breaking changes
   - Related issues (use "Fixes #123" syntax)

3. **Code Quality**:
   - Follow existing code style
   - Add comments for complex logic
   - No debug statements or TODOs
   - Proper error handling

### Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged
4. Congratulations! 🎉

## Coding Standards

### Bash Style Guide

1. **Use `shellcheck`** for linting:
   ```bash
   shellcheck kalitelligence.sh
   ```

2. **Function naming**: Use snake_case
   ```bash
   install_tools() {
       # ...
   }
   ```

3. **Variables**: Use UPPERCASE for global, lowercase for local
   ```bash
   readonly LOG_DIR="/var/log/ti-suite"
   local temp_file="$1"
   ```

4. **Error handling**: Always check return codes
   ```bash
   if ! command -v git &>/dev/null; then
       die "Git is required but not installed"
   fi
   ```

5. **Quotes**: Always quote variables
   ```bash
   echo "$variable"  # Good
   echo $variable    # Bad
   ```

6. **Comments**: Use clear, descriptive comments
   ```bash
   # Download threat intelligence feeds
   # Retries up to 3 times with exponential backoff
   download_feeds() {
       # ...
   }
   ```

### Security Best Practices

1. **Input sanitization**: Never trust user input
   ```bash
   # Sanitize domain input
   sanitize_domain() {
       local domain="$1"
       # Remove any characters that aren't alphanumeric, dots, or hyphens
       echo "$domain" | sed 's/[^a-zA-Z0-9.-]//g'
   }
   ```

2. **Avoid command injection**: Use arrays for commands
   ```bash
   # Good
   local cmd=("nmap" "-sV" "$target")
   "${cmd[@]}"

   # Bad
   nmap -sV "$target"  # If $target contains spaces or special chars
   ```

3. **Secure temporary files**: Use mktemp
   ```bash
   local temp_file
   temp_file=$(mktemp) || die "Failed to create temp file"
   trap "rm -f '$temp_file'" EXIT
   ```

## Testing

### Manual Testing

Test your changes in these scenarios:

1. **Clean installation**: Fresh Kali VM
2. **Upgrade**: Existing installation
3. **Different presets**: passive, darkweb, easm, dfir, full
4. **Edge cases**: No network, low disk space, non-root user

### Automated Testing

Create test scripts in the `tests/` directory:

```bash
#!/usr/bin/env bash
# tests/test_installation.sh

test_install_passive() {
    echo "Testing passive preset..."
    sudo ./kalitelligence.sh --preset passive --no-ufw
    # Verify key tools are installed
    command -v theharvester || return 1
    command -v subfinder || return 1
    return 0
}

test_install_passive
```

## Documentation

### README Updates

When adding features, update:

1. **Features section**: Describe the new capability
2. **Installation**: Add new flags or requirements
3. **Usage examples**: Show how to use the feature
4. **Quick reference**: Add to the quick reference card

### Inline Documentation

Add comments for:

- Complex algorithms
- Non-obvious workarounds
- Security considerations
- Performance optimizations

### External Documentation

For major features, consider:

- Separate HOWTO guides
- Video tutorials
- Architecture diagrams
- API documentation

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community discussions
- **Email**: For security issues (see SECURITY.md)

### Getting Help

- Check existing documentation
- Search closed issues
- Ask in GitHub Discussions
- Join the community chat (if available)

### Recognition

Contributors will be recognized in:

- The README.md contributors section
- Release notes
- Annual contributor highlights

---

## Thank You!

Your contributions make Kalitelligence better for everyone. We appreciate your time and effort in improving this project! 🙏

For any questions, feel free to open an issue or discussion on GitHub.
