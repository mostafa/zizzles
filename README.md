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
- 🎯 **Smart Risk Assessment**: Context-aware analysis with different severity levels (High, Medium, Low)
- 🔧 **Automated Fixes**: Suggests and applies secure alternatives to vulnerable patterns
- 📊 **Multiple Output Formats**: Human-readable reports and SARIF 2.2 for tool integration
- ⚡ **Fast Analysis**: Efficient AST-based scanning with accurate results
- 📚 **Interactive Documentation**: Built-in docs with detailed explanations and examples
- 🎨 **Beautiful CLI**: Modern terminal UI with colors and emojis

## 🚨 Security Vulnerabilities Detected

### Expression Injection

Expression injection is a critical security vulnerability where untrusted user input is directly interpolated into shell commands through GitHub's expression syntax (`${{ ... }}`). This can allow attackers to execute arbitrary commands in your CI/CD environment.

**Example of vulnerable code:**
```yaml
- name: Process user input
  run: echo "Hello ${{ github.event.issue.title }}"  # Dangerous!
```

For detailed information, examples, and mitigation strategies, see our comprehensive [Expression Injection Documentation](docs/audit_rules/expression_injection.md).

### Output Handling

Output handling vulnerabilities occur when workflows improperly manage sensitive data, use deprecated output methods, or create outputs that could leak confidential information. These issues can expose secrets, tokens, and user-controlled data.

**Common output handling issues:**
- **Secret leakage**: Direct exposure of secrets or tokens in outputs
- **Deprecated commands**: Using old `::set-output` syntax instead of `$GITHUB_OUTPUT`
- **Missing descriptions**: Outputs without clear documentation
- **User input exposure**: Directly outputting user-controlled data without validation
- **Unsafe shell usage**: Unquoted output usage that could lead to injection

**Example of vulnerable code:**
```yaml
outputs:
  api_key:
    description: "API key"
    value: ${{ secrets.API_KEY }}  # Exposes secret!
  
steps:
  - name: Old output method
    run: echo "::set-output name=result::${{ inputs.user_data }}"  # Deprecated!
```

For detailed information, examples, and mitigation strategies, see our comprehensive [Output Handling Documentation](docs/audit_rules/output_handling.md).

### Runs Version

Runs version vulnerabilities occur when GitHub Actions use deprecated, unsupported, or missing Node.js runtime versions in their `runs` configuration. These issues can expose your workflows to security risks from end-of-life Node.js versions that no longer receive security updates.

**Common runs version issues:**
- **End-of-life versions**: Using Node.js 12 which no longer receives security updates
- **Deprecated versions**: Using Node.js 14 which is no longer supported by GitHub Actions
- **Very old versions**: Using Node.js 10, 8, 6, or 4 with known security vulnerabilities
- **Unknown versions**: Using unrecognized `nodeXX` versions
- **Missing specifications**: JavaScript actions without a `using` field declaration

**Example of vulnerable code:**
```yaml
# End-of-life Node.js version
runs:
  using: node12  # Critical: No longer supported!
  main: index.js

# Missing version specification
runs:
  main: index.js  # Should specify 'using: node16' or 'using: node20'
```

**Safe alternatives:**
```yaml
# Use supported Node.js versions
runs:
  using: node20  # Recommended (LTS)
  main: index.js

runs:
  using: node16  # Also supported
  main: index.js
```

For detailed information, examples, and mitigation strategies, see our comprehensive [Runs Version Documentation](docs/audit_rules/runs_version.md).

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

## 🎯 Best Practices

### Expression Injection Prevention
1. **Always use environment variables** for user-controllable data
2. **Quote your variables** in shell commands: `"$VARIABLE"` not `$VARIABLE`
3. **Validate input** when possible before using it
4. **Use safe contexts directly** - no need to wrap `github.repository` in env vars

### Output Handling Security
5. **Never expose secrets in outputs** - avoid `${{ secrets.* }}` in output values
6. **Use modern output syntax** - `echo "key=value" >> $GITHUB_OUTPUT` instead of `::set-output`
7. **Document your outputs** - always provide clear descriptions for action outputs
8. **Validate user input** before outputting - sanitize user-controlled data
9. **Quote output usage** - wrap step outputs in quotes when used in shell commands

### Runs Version Security
10. **Use supported Node.js versions** - stick to node16, node20, or node21
11. **Avoid deprecated versions** - never use node12 (critical) or node14 (deprecated)
12. **Specify version explicitly** - always include `using: nodeXX` for JavaScript actions
13. **Update regularly** - migrate to newer Node.js versions as they become available
14. **Test before upgrading** - verify your action works with newer Node.js versions

### General Security
15. **Review pull requests** from external contributors carefully
16. **Run zizzles in CI** to catch issues early
17. **Keep workflows minimal** - reduce the attack surface by limiting complexity

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
