# Expression Injection

## Overview

Expression injection is a critical security vulnerability in GitHub Actions where untrusted user input is directly interpolated into shell commands through GitHub's expression syntax (`${{ ... }}`). This can allow attackers to execute arbitrary commands in your CI/CD environment.

Zizzles' expression injection detection helps you identify and fix these vulnerabilities by analyzing your workflow files and providing automated fixes. **The detection covers multiple vulnerable contexts including shell commands, conditional logic, Docker configurations, and action inputs.**

## What is Expression Injection?

Expression injection occurs when user-controllable data is used directly in shell commands via GitHub Actions expressions. For example:

```yaml
# VULNERABLE: User can inject shell commands via issue title
- name: Process issue
  run: echo "Processing: ${{ github.event.issue.title }}"
```

If an attacker creates an issue with the title `"; rm -rf / #`, the resulting command becomes:
```bash
echo "Processing: "; rm -rf / #"
```

This allows the attacker to execute arbitrary commands (`rm -rf /`) in your runner environment.

## How Detection Works

Zizzles analyzes your GitHub Actions workflows and categorizes expressions based on their security risk:

### Safe Contexts (No Alerts)
These contexts are read-only or controlled by GitHub/the workflow author:
- **GitHub metadata**: `github.repository`, `github.sha`, `github.workspace`
- **Runner information**: `runner.os`, `runner.arch`, `runner.temp`
- **Workflow data**: `github.job`, `github.run_id`, `github.workflow`
- **Secrets**: `secrets.*` (sensitive but safe to interpolate)

### Medium Risk Contexts (Medium Severity)
These contexts have some structure but may contain user data:
- **URLs**: `github.event.*.html_url`, `github.event.*.avatar_url`
- **Step outputs**: `steps.*.outputs.*`
- **Matrix values**: `matrix.*`
- **Repository variables**: `vars.*`

### High Risk Contexts (High Severity)
These contexts are fully attacker-controllable:
- **User content**: Issue/PR titles and bodies, commit messages
- **User identifiers**: `github.actor`, user login names and emails
- **Branch names**: `github.head_ref`, `github.base_ref`
- **External inputs**: `inputs.*` parameters

## Understanding the Results

### Severity Levels

- **High Severity**: Expressions using fully attacker-controllable contexts in command execution fields
- **Medium Severity**: Expressions using partially controllable contexts or in logic control fields
- **No Alert**: Safe expressions that don't pose security risks

### Finding Details

Each finding includes:
- **Location**: File, line, and column where the expression was found
- **Expression**: The specific GitHub Actions expression that's problematic
- **Context**: What type of data the expression accesses and which field it's used in
- **Risk Level**: The specific type of risk (command injection, logic manipulation, etc.)

### Context-Aware Risk Assessment

Zizzles now provides context-specific risk messages:
- **Command Execution Risk**: For expressions in `run`, `shell`, `working-directory`, `entrypoint`, etc.
- **Logic Control Risk**: For expressions in `if` conditions that can manipulate workflow flow
- **Action Input Risk**: For expressions in `with` blocks where risk depends on action implementation

## Fixing Expression Injection

### Automatic Fixes

Zizzles can automatically fix expression injection vulnerabilities by moving unsafe expressions to environment variables:

**Before (Vulnerable):**
```yaml
steps:
  - name: Process user input
    run: |
      echo "Title: ${{ github.event.issue.title }}"
      echo "User: ${{ github.actor }}"
      echo "Repo: ${{ github.repository }}"
```

**After (Fixed):**
```yaml
steps:
  - name: Process user input
    env:
      GITHUB_EVENT_ISSUE_TITLE: ${{ github.event.issue.title }}
      GITHUB_ACTOR: ${{ github.actor }}
    run: |
      echo "Title: $GITHUB_EVENT_ISSUE_TITLE"
      echo "User: $GITHUB_ACTOR"
      echo "Repo: ${{ github.repository }}"  # Safe - remains unchanged
```

### Manual Fixes

You can also fix issues manually using the same approach:

1. **Move unsafe expressions to environment variables**
2. **Use the environment variables in your commands**
3. **Keep safe expressions as-is**

### Why This Approach Works

Environment variables are safely interpolated by the shell, preventing command injection. The expression `${{ github.event.issue.title }}` in the `env` section is evaluated safely by GitHub Actions, and the resulting value is passed to the shell as a regular environment variable.

## Common Vulnerable Patterns

### 1. Shell Command Injection (run)
```yaml
# VULNERABLE
run: echo "Issue: ${{ github.event.issue.title }}"

# FIXED
env:
  ISSUE_TITLE: ${{ github.event.issue.title }}
run: echo "Issue: $ISSUE_TITLE"
```

### 2. Shell Selection Vulnerability (shell)
```yaml
# VULNERABLE
shell: ${{ inputs.shell_type }}
run: echo "Hello World"

# FIXED
env:
  SHELL_TYPE: ${{ inputs.shell_type }}
shell: ${{ env.SHELL_TYPE }}  # Use with caution - validate input
run: echo "Hello World"
```

### 3. Path Traversal (working-directory)
```yaml
# VULNERABLE
working-directory: ${{ inputs.work_dir }}
run: ls -la

# FIXED
env:
  WORK_DIR: ${{ inputs.work_dir }}
working-directory: ${{ env.WORK_DIR }}  # Validate path is safe
run: ls -la
```

### 4. Docker Command Injection (entrypoint/args)
```yaml
# VULNERABLE
runs:
  using: docker
  image: alpine
  entrypoint: ${{ inputs.command }}
  args:
    - ${{ github.event.issue.title }}

# FIXED
runs:
  using: docker
  image: alpine
  entrypoint: /safe-wrapper.sh
  env:
    COMMAND: ${{ inputs.command }}
    ISSUE_TITLE: ${{ github.event.issue.title }}
```

### 5. Logic Manipulation (if conditions)
```yaml
# VULNERABLE - Attacker can bypass conditions
if: ${{ github.actor != 'blocked-user' }}
run: deploy-to-production

# BETTER - Use allow-list approach
if: contains(fromJSON('["trusted-user1", "trusted-user2"]'), github.actor)
run: deploy-to-production
```

### 6. Action Input Injection (with)
```yaml
# VULNERABLE - Depends on action implementation
uses: some/action@v1
with:
  user_script: ${{ github.event.comment.body }}

# SAFER
uses: some/action@v1
env:
  USER_SCRIPT: ${{ github.event.comment.body }}
with:
  user_script: ${{ env.USER_SCRIPT }}
```

## Safe Expressions (No Action Needed)

These expressions are safe to use directly and won't trigger alerts:

```yaml
# All of these are SAFE
run: |
  echo "Repository: ${{ github.repository }}"
  echo "SHA: ${{ github.sha }}"
  echo "Runner: ${{ runner.os }}"
  echo "Job: ${{ github.job }}"
  echo "Workspace: ${{ github.workspace }}"
```

## Special Cases and Warnings

### GitHub Actor Context
The `github.actor` context receives special attention because:
- It can be spoofed in certain scenarios
- Attackers may be able to control this value in fork-based workflows
- Always treat actor information as potentially untrusted

### Branch References
Branch names (`github.head_ref`, `github.base_ref`) are considered high-risk because:
- Attackers can control branch names in pull requests
- Branch names are commonly used in commands and file paths
- They're frequently overlooked as potential injection vectors

## Best Practices

1. **Always use environment variables** for user-controllable data
2. **Quote your variables** in shell commands: `"$VARIABLE"` not `$VARIABLE`
3. **Validate input** when possible before using it
4. **Use safe contexts directly** - no need to wrap `github.repository` in env vars
5. **Review pull requests** from external contributors carefully
6. **Consider using composite actions** for complex logic to reduce expression usage

## Configuration

The expression injection detection runs automatically on all workflow files (`*.yml`, `*.yaml`) in your repository. Currently, there are no configuration options to disable specific rules or contexts.

## Performance Notes

- Detection is fast and runs on the AST level for accuracy
- Large workflows with many expressions may take slightly longer to analyze
- Fix generation processes each run block independently for safety

## Vulnerable Fields Detected

Zizzles detects expression injection vulnerabilities across multiple GitHub Actions contexts:

### High Risk Fields (Command Execution)
These fields can lead to direct command injection vulnerabilities:
- **`run`**: Shell command execution - the primary injection vector
- **`shell`**: Shell type selection - can affect command interpretation  
- **`working-directory`**: Working directory path - can affect file operations and enable path traversal
- **`entrypoint`**: Docker container entrypoint - direct command execution in containers
- **`pre-entrypoint`**: Docker pre-execution hook - runs before main container
- **`post-entrypoint`**: Docker post-execution hook - runs after main container
- **`args`**: Docker container arguments - command line arguments passed to containers

### Medium Risk Fields (Logic & Action Control)
These fields can enable workflow manipulation or have action-dependent risks:
- **`if`**: Conditional logic - can manipulate workflow execution flow and bypass security controls
- **`with`**: Action inputs - security risk depends on how the specific action processes the input data

### Detection Coverage
- **Comprehensive AST Analysis**: Analyzes the complete workflow structure, not just pattern matching
- **Context-Aware Filtering**: Only flags expressions that pose actual security risks
- **Smart Risk Classification**: Different severity levels based on field type and expression content

## Limitations

- **Dynamic Expressions**: Does not analyze dynamically generated expressions or runtime-computed values
- **Custom Actions**: Cannot detect injection vulnerabilities within custom action implementations (only workflow files)
- **Complex Expressions**: Some complex nested expressions may not be fully analyzed
- **Action-Specific Risks**: Risk assessment for `with` fields depends on how the specific action processes input data
- **False Negatives**: May miss some edge cases involving complex expression syntax or unusual field usage

## Getting Help

If you encounter false positives or have questions about specific findings:

1. **Review the context classification** - ensure the flagged expression is actually using user-controllable data
2. **Check the field context** - understand which field contains the expression and its associated risk level
3. **Consider the attack scenario** - could an attacker control the flagged data in your specific use case?
4. **Validate the risk level** - high-risk fields like `run` and `shell` require immediate attention, while `with` fields may be action-dependent

For technical issues or feature requests, please refer to the project's issue tracker.

## Related Security Resources

- [GitHub Security Lab: Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [GitHub Docs: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
