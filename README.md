# 🔥 Zizzles

**A comprehensive security scanner for GitHub Actions workflows**

Zizzles is a static analysis tool that helps you identify and fix security vulnerabilities in your GitHub Actions workflows. It is inspired by [zizmor](https://github.com/zizmorcore/zizmor), a security scanner for GitHub Actions workflows written in Rust.

> [!NOTE]
> Zizzles is a work in progress and is not yet ready for production use.

## ✨ Features

- 🛡️ **Supported Audit Rules**:
    - **Expression Injection**: Identifies dangerous uses of GitHub Actions expressions that could lead to command injection
- 🎯 **Smart Risk Assessment**: Context-aware analysis with different severity levels (High, Medium, Low)
- 🔧 **Automated Fixes**: Suggests and applies secure alternatives to vulnerable patterns
- 📊 **Multiple Output Formats**: Human-readable reports and SARIF 2.2 for tool integration
- ⚡ **Fast Analysis**: Efficient AST-based scanning with accurate results
- 📚 **Interactive Documentation**: Built-in docs with detailed explanations and examples
- 🎨 **Beautiful CLI**: Modern terminal UI with colors and emojis

## 🚨 What is Expression Injection?

Expression injection is a critical security vulnerability where untrusted user input is directly interpolated into shell commands through GitHub's expression syntax (`${{ ... }}`). This can allow attackers to execute arbitrary commands in your CI/CD environment.

For detailed information, examples, and mitigation strategies, see our comprehensive [Expression Injection Documentation](docs/audit_rules/expression_injection.md).

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

## 🎯 Best Practices

1. **Always use environment variables** for user-controllable data
2. **Quote your variables** in shell commands: `"$VARIABLE"` not `$VARIABLE`
3. **Validate input** when possible before using it
4. **Use safe contexts directly** - no need to wrap `github.repository` in env vars
5. **Review pull requests** from external contributors carefully
6. **Run zizzles in CI** to catch issues early

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

---

*Made with ❤️ for secure CI/CD pipelines*
