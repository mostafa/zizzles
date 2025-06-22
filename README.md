# 🔥 Zizzles

**A comprehensive security scanner for GitHub Actions workflows**

Zizzles is a static analysis tool that helps you identify and fix security vulnerabilities in your GitHub Actions workflows. It is inspired by [zizmor](https://github.com/zizmorcore/zizmor), a security scanner for GitHub Actions workflows written in Rust.

> [!NOTE]
> Zizzles is a work in progress and is not yet ready for production use.

## ✨ Features

- 🛡️ **Supported Audit Rules**:
    - **Expression Injection**: Identifies dangerous uses of GitHub Actions expressions that could lead to command injection
    - **Output Handling**: Detects insecure output practices, sensitive data leaks, and deprecated output commands  
    - **Runs Version**: Detects deprecated, unsupported, or missing Node.js versions in GitHub Actions `runs` configuration
    - **Composite Action**: Analyzes composite actions for security vulnerabilities and best practice violations
    - **Docker Security**: Identifies security issues in containerized GitHub Actions
- 🎯 **Smart Risk Assessment**: Context-aware analysis with different severity levels (High, Medium, Low)
- 🔧 **Automated Fixes**: Suggests and applies secure alternatives to vulnerable patterns
- 📊 **Multiple Output Formats**: Human-readable reports and SARIF 2.2 for tool integration
- ⚡ **Fast Analysis**: Efficient AST-based scanning with accurate results
- 📚 **Interactive Documentation**: Built-in docs with detailed explanations and examples
- 🎨 **Beautiful CLI**: Modern terminal UI with colors and emojis

## 🛡️ Security Audit Rules

Zizzles detects various security vulnerabilities in GitHub Actions workflows. Each audit rule provides comprehensive coverage including vulnerability detection, examples, and security best practices:

- **[Expression Injection](docs/audit_rules/expression_injection.md)**: Prevents command injection through unsafe GitHub expression usage
- **[Output Handling](docs/audit_rules/output_handling.md)**: Detects insecure output practices and sensitive data leaks  
- **[Runs Version](docs/audit_rules/runs_version.md)**: Identifies deprecated or unsupported Node.js runtime versions
- **[Composite Action](docs/audit_rules/composite_action.md)**: Analyzes composite actions for security vulnerabilities
- **[Docker Security](docs/audit_rules/docker_security.md)**: Identifies security issues in containerized actions

Each documentation page includes detailed explanations, examples, vulnerability patterns, and recommended security practices.

## 🚀 Installation

### Download Pre-built Binary

Download the latest release from the [releases page](https://github.com/mostafa/zizzles/releases) and add it to your PATH.

### Build from Source

**Requirements:** Go 1.24.0 or later

```bash
git clone https://github.com/mostafa/zizzles.git
cd zizzles
make build-release-doc
```

This creates a `zizzles` binary in the current directory.

### Development Build

For development with documentation features:

```bash
make build-debug
```

## 📖 Quick Start

### Basic Usage

Scan a single workflow file:
```bash
zizzles run action.yml
```

Scan multiple files:
```bash
zizzles run action*.yml
```

### Filtering by Severity

Only show high and critical findings:
```bash
zizzles run --severity high action.yml
```

Available severity levels: `info`, `low`, `medium`, `high`, `critical`

### Export Results

Export findings to SARIF format for integration with security tools:
```bash
zizzles run --export results.sarif action*.yml
```

### Quiet Mode

Suppress banner and success messages (useful for CI):
```bash
zizzles run --quiet action*.yml
```

## 📚 Documentation

Zizzles includes comprehensive interactive documentation:

```bash
# Show documentation menu
zizzles doc

# View specific topic
zizzles doc expression-injection
zizzles doc output-handling
zizzles doc runs-version
```

**Navigation in documentation viewer:**
- `↑/k` - scroll up
- `↓/j` - scroll down  
- `b/pgup` - page up
- `f/pgdn` - page down
- `g/home` - go to top
- `G/end` - go to bottom
- `backspace` - go back to menu
- `q/esc` - quit

## 🛠️ CLI Reference

### Commands

```bash
zizzles run [files...]     # Run security audit on files
zizzles doc [topic]        # Show interactive documentation
zizzles --help            # Show help
```

### Options for `run` command

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--quiet` | `-q` | Suppress banner and success messages | `false` |
| `--severity` | `-s` | Filter by minimum severity level | `info` |
| `--export` | `-e` | Export to SARIF 2.2 format | - |
| `--fix` | | Auto-fix issues (not yet implemented) | `false` |

## 🔧 Integration

### GitHub Actions Integration

Add zizzles to your CI pipeline:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Download Zizzles
        run: |
          wget -O zizzles https://github.com/mostafa/zizzles/releases/latest/download/zizzles-linux-amd64
          chmod +x zizzles
      
      - name: Scan workflows
        run: ./zizzles run --quiet --export results.sarif action*.yml
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: zizzles
        name: Zizzles Security Scan
        entry: zizzles run --quiet action*.yml
        language: system
        files: '^\.github/workflows/.*\.ya?ml$'
```

## 🤝 Contributing

Contributions are welcome! Please see the project repository for contribution guidelines.

## 📄 License

This project is licensed under the terms specified in the [LICENSE](./LICENSE) file.

## 🆘 Support

- 📖 Built-in documentation: `zizzles doc`
- 🐛 Issues: [GitHub Issues](https://github.com/mostafa/zizzles/issues)
- 💬 Questions: [GitHub Discussions](https://github.com/mostafa/zizzles/discussions)

## 🔗 Related Projects

- [zizmor](https://github.com/zizmorcore/zizmor) - A static analysis tool for GitHub Actions workflows
- [actionlint](https://github.com/rhysd/actionlint) - A static analysis tool for GitHub Actions workflows
- [action-validator](https://github.com/mpalmer/action-validator) - Validate GitHub Action and Workflow YAML files
- [octoscan](https://github.com/synacktiv/octoscan) - A static vulnerability scanner for GitHub action workflows
- [hadolint](https://github.com/hadolint/hadolint) - A Dockerfile linter
- [JavaScript](https://github.com/analysis-tools-dev/static-analysis?tab=readme-ov-file#javascript) - A list of JavaScript static analysis tools
- [gitleaks](https://github.com/gitleaks/gitleaks) - A static analysis tool for GitHub Actions workflows

---

*Made with ❤️ for secure CI/CD pipelines*
