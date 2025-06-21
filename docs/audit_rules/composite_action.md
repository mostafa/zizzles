# Composite Action Security

## Overview

Composite action security vulnerabilities in GitHub Actions occur when composite actions (`action.yml` files) are configured with insecure patterns that can lead to command injection, privilege escalation, and other security issues. These vulnerabilities are particularly dangerous because composite actions are reusable components that can be called by multiple workflows, amplifying the impact of any security flaws.

Zizzles' composite action security detection helps you identify and fix these vulnerabilities by analyzing your action definition files for insecure input handling, unpinned dependencies, credential exposure, and other security anti-patterns. **The detection covers input injection, unsafe defaults, unpinned actions, environment leakage, shell configuration, and checkout security.**

## What are Composite Action Security Issues?

Composite action security issues occur when reusable GitHub Actions are not properly secured against common attack vectors. These can include:

### 1. Input Injection
Direct use of user-controllable input in shell commands:

```yaml
# CRITICAL: Input can be used for command injection
runs:
  using: 'composite'
  steps:
    - name: Display message
      run: echo "${{ inputs.message }}"  # VULNERABLE
      shell: bash
```

This is critical because attackers can inject malicious commands through action inputs, potentially compromising the entire workflow environment.

### 2. Unsafe Input Defaults
Default values containing shell metacharacters:

```yaml
# MEDIUM RISK: Default contains dangerous metacharacters
inputs:
  command:
    description: 'Command to run'
    default: 'echo "test"; rm -rf /'  # VULNERABLE
```

Default values with shell metacharacters can lead to unexpected command execution even when inputs aren't explicitly provided.

### 3. Unpinned Actions
Using actions without version pinning or with floating tags:

```yaml
# HIGH RISK: Floating tag can be hijacked
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@main  # VULNERABLE - mutable tag
    - uses: actions/setup-node     # VULNERABLE - no version
```

Unpinned actions can be hijacked by attackers who gain control of the repository or registry, leading to supply chain attacks.

### 4. Environment Leakage
Writing sensitive values to persistent environment variables:

```yaml
# MEDIUM RISK: Input values leaked to environment
runs:
  using: 'composite'
  steps:
    - name: Set environment
      run: echo "VALUE=${{ inputs.value }}" >> $GITHUB_ENV  # VULNERABLE
      shell: bash
```

Writing input values directly to `$GITHUB_ENV` can expose sensitive data to subsequent steps and leave traces in logs.

### 5. Missing Shell Configuration
Run steps without explicit shell specification:

```yaml
# LOW RISK: Inconsistent behavior across runners
runs:
  using: 'composite'
  steps:
    - name: Run command
      run: echo "hello"  # POTENTIAL ISSUE - no shell specified
```

Missing shell specifications can lead to inconsistent behavior across different runner environments.

### 6. Unsafe Checkout
Using checkout actions without credential safety considerations:

```yaml
# MEDIUM RISK: Credentials persist by default
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4  # POTENTIAL ISSUE - credentials persist
```

Checkout actions with persistent credentials can be exploited in pull request contexts to access private repositories.

## How Detection Works

Zizzles analyzes your GitHub Actions action definition files (`action.yml`, `action.yaml`) and categorizes security issues based on their risk level:

### Critical Issues
- **Input injection with high-risk expressions**: Direct use of `${{ inputs.* }}` in shell commands
- **Very dangerous defaults**: Input defaults with multiple shell metacharacters

### High Risk Issues
- **Unversioned actions**: Actions used without any version specification
- **Direct credential exposure**: Patterns that directly expose sensitive information
- **Command injection vectors**: Contexts where user input can directly control command execution

### Medium Risk Issues
- **Floating tag usage**: Actions using mutable tags like `@main`, `@master`, `@develop`
- **Environment leakage**: Writing input values to persistent environment variables
- **Unsafe checkout patterns**: Checkout actions without credential safety considerations
- **Unsafe input defaults**: Default values containing shell metacharacters

### Low Risk Issues
- **Missing shell specifications**: Run steps without explicit shell configuration
- **Best practice violations**: Patterns that work but don't follow security best practices

## Understanding the Results

### Severity Levels

- **Critical**: Direct command injection vulnerabilities requiring immediate attention
- **High**: Unpinned actions and patterns that enable supply chain attacks
- **Medium**: Environment leakage and credential exposure risks
- **Low**: Configuration inconsistencies and best practice violations

### Finding Details

Each finding includes:
- **Location**: File, line, and column where the issue was found
- **Issue Type**: The specific security problem detected (input injection, unpinned action, etc.)
- **Risk Assessment**: Why this pattern is problematic and potential attack scenarios
- **Context**: Whether it's in input definitions, run steps, or action usage

### Context-Aware Risk Assessment

Zizzles provides specific guidance based on the context:
- **Input Handling**: Issues with how user inputs are processed and validated
- **Action Dependencies**: Problems with action version pinning and supply chain security
- **Environment Management**: Issues with environment variable handling and credential exposure
- **Shell Configuration**: Problems with shell specification and command execution

## Fixing Composite Action Security Issues

### Automatic Fixes (Future Enhancement)

While Zizzles currently provides detection and guidance, automatic fixes for composite action security issues are planned for future releases. The fixes would involve:

**Input Injection (Before):**
```yaml
steps:
  - name: Display message
    run: echo "${{ inputs.message }}"
    shell: bash
```

**Fixed:**
```yaml
steps:
  - name: Display message
    env:
      INPUT_MESSAGE: ${{ inputs.message }}
    run: echo "$INPUT_MESSAGE"
    shell: bash
```

### Manual Fixes

You can fix composite action security issues using these approaches:

#### 1. Secure Input Handling
Move unsafe expressions to environment variables:

```yaml
# BEFORE (Critical)
steps:
  - name: Process input
    run: echo "Processing: ${{ inputs.message }}"
    shell: bash

# AFTER (Secure)
steps:
  - name: Process input
    env:
      INPUT_MESSAGE: ${{ inputs.message }}
    run: echo "Processing: $INPUT_MESSAGE"
    shell: bash
```

#### 2. Pin Action Versions
Replace unpinned actions with specific versions or SHA hashes:

```yaml
# BEFORE (High Risk)
steps:
  - uses: actions/checkout@main
  - uses: actions/setup-node

# AFTER (Secure)
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
```

#### 3. Sanitize Input Defaults
Remove or escape dangerous characters in default values:

```yaml
# BEFORE (Medium Risk)
inputs:
  command:
    description: 'Command to run'
    default: 'echo "test"; rm -rf /'

# AFTER (Secure)
inputs:
  command:
    description: 'Command to run'
    default: 'echo "test"'
```

#### 4. Secure Environment Variable Usage
Namespace environment variables and avoid direct exposure:

```yaml
# BEFORE (Medium Risk)
steps:
  - name: Set environment
    run: echo "VALUE=${{ inputs.value }}" >> $GITHUB_ENV
    shell: bash

# AFTER (Secure)
steps:
  - name: Set environment
    env:
      INPUT_VALUE: ${{ inputs.value }}
    run: echo "MYACTION_VALUE=$INPUT_VALUE" >> $GITHUB_ENV
    shell: bash
```

#### 5. Configure Checkout Security
Disable credential persistence for enhanced security:

```yaml
# BEFORE (Medium Risk)
steps:
  - uses: actions/checkout@v4

# AFTER (Secure)
steps:
  - uses: actions/checkout@v4
    with:
      persist-credentials: false
```

#### 6. Specify Shell Explicitly
Add explicit shell specifications for consistency:

```yaml
# BEFORE (Low Risk)
steps:
  - name: Run command
    run: echo "hello"

# AFTER (Consistent)
steps:
  - name: Run command
    run: echo "hello"
    shell: bash
```

## Common Vulnerable Patterns

### 1. Direct Input Injection in Commands
```yaml
# CRITICAL: Direct command injection
steps:
  - name: Display message
    run: echo "${{ inputs.message }}"  # VULNERABLE
    shell: bash

# FIXED: Use environment variables
steps:
  - name: Display message
    env:
      INPUT_MESSAGE: ${{ inputs.message }}
    run: echo "$INPUT_MESSAGE"  # SAFE
    shell: bash
```

### 2. Unsafe Input Defaults
```yaml
# MEDIUM RISK: Dangerous default value
inputs:
  command:
    description: 'Command to run'
    default: 'echo "test"; rm -rf /'  # VULNERABLE

# FIXED: Safe default value
inputs:
  command:
    description: 'Command to run'
    default: 'echo "test"'  # SAFE
```

### 3. Unpinned Action Dependencies
```yaml
# HIGH RISK: Unpinned actions
steps:
  - uses: actions/checkout@main          # VULNERABLE - floating tag
  - uses: actions/setup-node             # VULNERABLE - no version

# FIXED: Pinned versions
steps:
  - uses: actions/checkout@v4                                       # SAFE - pinned version
  - uses: actions/setup-node@60edb5dd326ca084c43e5dd5b96dcaa4632daae  # SAFE - pinned SHA
```

### 4. Environment Variable Leakage
```yaml
# MEDIUM RISK: Input values leaked to environment
steps:
  - name: Set environment
    run: echo "VALUE=${{ inputs.value }}" >> $GITHUB_ENV  # VULNERABLE
    shell: bash

# FIXED: Namespaced and sanitized
steps:
  - name: Set environment
    env:
      INPUT_VALUE: ${{ inputs.value }}
    run: echo "MYACTION_VALUE=$INPUT_VALUE" >> $GITHUB_ENV  # SAFER
    shell: bash
```

### 5. Unsafe Checkout Configuration
```yaml
# MEDIUM RISK: Credentials persist by default
steps:
  - uses: actions/checkout@v4  # POTENTIAL ISSUE

# FIXED: Explicit credential management
steps:
  - uses: actions/checkout@v4
    with:
      persist-credentials: false  # SAFER for PR contexts
```

### 6. Missing Shell Specification
```yaml
# LOW RISK: Inconsistent behavior
steps:
  - name: Run command
    run: echo "hello"  # POTENTIAL ISSUE

# FIXED: Explicit shell
steps:
  - name: Run command
    run: echo "hello"
    shell: bash  # EXPLICIT
```

## Best Practices

1. **Always use environment variables** for user inputs in `run` steps
2. **Pin action versions** to specific releases or commit SHAs
3. **Validate and sanitize** all input values, especially defaults
4. **Namespace environment variables** to avoid conflicts
5. **Specify explicit shell** for consistent behavior
6. **Disable credential persistence** for checkout actions when appropriate
7. **Add conditional guards** for sensitive operations in PR contexts
8. **Use allow-lists** instead of deny-lists for access control
9. **Regularly audit** action dependencies for security updates
10. **Test with malicious inputs** during development

## Configuration

This rule automatically applies to all `action.yml` and `action.yaml` files in your repository. It does not apply to workflow files (`.github/workflows/*.yml`).

### File Scope
- **Included**: `action.yml`, `action.yaml`
- **Excluded**: `.github/workflows/*.yml`, `.github/workflows/*.yaml`

### Detection Coverage
- Input injection patterns in `run` steps
- Unsafe default values in input definitions
- Unpinned action references in `uses` statements
- Environment variable leakage patterns
- Missing shell specifications
- Checkout security configurations

## References

- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Composite Actions Documentation](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action)
- [Expression Injection Prevention](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [Action Version Pinning](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
- [Credential Handling](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access) 