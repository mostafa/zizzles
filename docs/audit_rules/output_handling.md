# Output Handling and Sensitive Data

## Overview

Output handling vulnerabilities in GitHub Actions occur when workflows improperly manage sensitive data, use deprecated commands, or expose user-controlled input without proper sanitization. These issues can lead to information disclosure, credential leaks, and security bypasses in your CI/CD pipeline.

Zizzles' output handling detection helps you identify and fix these vulnerabilities by analyzing your workflow files for insecure output patterns, deprecated commands, and potential data exposure risks. **The detection covers output definitions, shell command usage, secret handling, and user input processing.**

## What are Output Handling Issues?

Output handling issues occur when GitHub Actions workflows don't properly manage data flow, leading to potential security risks. These can include:

### 1. Deprecated Commands
Using the old `::set-output` command that has been deprecated:

```yaml
# VULNERABLE: Using deprecated set-output command
- name: Set result
  run: echo "::set-output name=result::${{ github.actor }}"
```

This is problematic because the deprecated command may not receive security updates and could be removed in future GitHub Actions versions.

### 2. Secret Exposure
Directly exposing secrets or tokens in outputs:

```yaml
# VULNERABLE: Direct secret exposure
outputs:
  api_token:
    description: "API token"
    value: ${{ secrets.API_TOKEN }}
```

If an attacker gains access to your workflow outputs, they can extract your secrets.

### 3. User Input Exposure
Outputting user-controlled data without validation:

```yaml
# VULNERABLE: Direct user input exposure
outputs:
  issue_title:
    description: "Issue title"
    value: ${{ github.event.issue.title }}
```

Attackers can craft malicious issue titles that could be used in downstream processes.

## How Detection Works

Zizzles analyzes your GitHub Actions workflows and categorizes output handling based on security risk:

### Critical Issues
- **Direct secret exposure**: Raw secrets or tokens in outputs
- **Unescaped secret usage**: Secrets used without proper transformation

### High Risk Issues
- **Deprecated commands**: Using `::set-output` instead of `$GITHUB_OUTPUT`
- **Sensitive data leaks**: GitHub tokens, passwords, or keys in outputs

### Medium Risk Issues
- **Unsafe shell usage**: Unquoted outputs in shell commands
- **User input exposure**: Direct user-controlled data in outputs
- **Poor sanitization**: Missing escaping of special characters

### Low Risk Issues
- **Missing documentation**: Outputs without descriptions
- **Vague documentation**: Descriptions like "string" or "value"

## Understanding the Results

### Severity Levels

- **Critical**: Direct secret exposure that immediately compromises security
- **High**: Deprecated commands or sensitive data leaks requiring immediate attention
- **Medium**: Unsafe practices that could lead to security issues
- **Low**: Documentation and best practice issues

### Finding Details

Each finding includes:
- **Location**: File, line, and column where the issue was found
- **Issue Type**: The specific output handling problem detected
- **Risk Level**: Why this pattern is problematic
- **Context**: Whether it's in outputs, shell commands, or action definitions

### Context-Aware Risk Assessment

Zizzles provides specific guidance based on context:
- **Output Definitions**: Issues with how outputs are structured and documented
- **Shell Commands**: Problems with how outputs are used in shell execution
- **Secret Handling**: Issues with credential and sensitive data management

## Fixing Output Handling Issues

### Automatic Fixes

Zizzles can automatically fix many output handling issues:

**Deprecated set-output (Before):**
```yaml
steps:
  - name: Set output old way
    run: echo "::set-output name=result::${{ github.actor }}"
```

**Fixed:**
```yaml
steps:
  - name: Set output new way
    run: echo "result=${{ github.actor }}" >> $GITHUB_OUTPUT
```

**Unsafe shell usage (Before):**
```yaml
steps:
  - name: Use output unsafely
    run: echo ${{ steps.build.outputs.result }}
```

**Fixed:**
```yaml
steps:
  - name: Use output safely
    run: echo "${{ steps.build.outputs.result }}"
```

### Manual Fixes

You can also fix issues manually using these approaches:

#### 1. Replace Deprecated Commands
Move from `::set-output` to `$GITHUB_OUTPUT`:

```yaml
# OLD WAY (deprecated)
run: echo "::set-output name=version::1.2.3"

# NEW WAY (recommended)
run: echo "version=1.2.3" >> $GITHUB_OUTPUT
```

#### 2. Secure Secret Handling
Never expose secrets directly in outputs:

```yaml
# VULNERABLE
outputs:
  database_url:
    value: ${{ secrets.DATABASE_URL }}

# SECURE
outputs:
  database_configured:
    description: "Boolean indicating if database is configured"
    value: ${{ secrets.DATABASE_URL != '' }}
```

#### 3. Validate User Input
Process user-controlled data before outputting:

```yaml
# VULNERABLE
outputs:
  user_input:
    value: ${{ github.event.issue.title }}

# SECURE
steps:
  - name: Process user input
    id: process
    run: |
      TITLE="${{ github.event.issue.title }}"
      # Sanitize input (remove special characters, limit length)
      CLEAN_TITLE=$(echo "$TITLE" | tr -cd '[:alnum:][:space:]._-' | cut -c1-100)
      echo "clean_title=$CLEAN_TITLE" >> $GITHUB_OUTPUT

outputs:
  user_input:
    description: "Sanitized issue title (max 100 chars, alphanumeric only)"
    value: ${{ steps.process.outputs.clean_title }}
```

## Common Vulnerable Patterns

### 1. Deprecated set-output Command
```yaml
# VULNERABLE
run: echo "::set-output name=result::value"

# FIXED
run: echo "result=value" >> $GITHUB_OUTPUT
```

### 2. Direct Secret Exposure
```yaml
# VULNERABLE
outputs:
  token:
    description: "API token"
    value: ${{ secrets.API_TOKEN }}

# FIXED
outputs:
  api_configured:
    description: "Boolean indicating if API is configured"
    value: ${{ secrets.API_TOKEN != '' }}
```

### 3. Unquoted Output in Shell
```yaml
# VULNERABLE
run: echo ${{ steps.build.outputs.filename }}

# FIXED
run: echo "${{ steps.build.outputs.filename }}"
```

### 4. Missing Output Documentation
```yaml
# VULNERABLE
outputs:
  result:
    value: ${{ steps.compute.outputs.data }}

# FIXED
outputs:
  result:
    description: "JSON object containing computation results with 'status' and 'data' fields"
    value: ${{ steps.compute.outputs.data }}
```

### 5. User Input Without Validation
```yaml
# VULNERABLE
outputs:
  branch_name:
    description: "Branch name"
    value: ${{ github.head_ref }}

# FIXED
steps:
  - name: Validate branch name
    id: validate
    run: |
      BRANCH="${{ github.head_ref }}"
      # Validate branch name format
      if [[ "$BRANCH" =~ ^[a-zA-Z0-9/_-]+$ ]] && [[ ${#BRANCH} -le 50 ]]; then
        echo "valid_branch=$BRANCH" >> $GITHUB_OUTPUT
      else
        echo "valid_branch=invalid-branch-name" >> $GITHUB_OUTPUT
      fi

outputs:
  branch_name:
    description: "Validated branch name (alphanumeric, slash, underscore, hyphen only, max 50 chars)"
    value: ${{ steps.validate.outputs.valid_branch }}
```

### 6. Unsafe Output Interpolation
```yaml
# VULNERABLE
run: |
  echo "Processing: ${{ steps.input.outputs.data }}"; echo "Done"

# FIXED
env:
  DATA: ${{ steps.input.outputs.data }}
run: |
  echo "Processing: $DATA"
  echo "Done"
```

## Safe Output Patterns

These patterns are secure and won't trigger alerts:

```yaml
# All of these are SAFE
outputs:
  repository:
    description: "Repository name"
    value: ${{ github.repository }}
  
  run_id:
    description: "Workflow run ID"
    value: ${{ github.run_id }}
  
  computed_hash:
    description: "SHA256 hash of build artifacts"
    value: ${{ steps.hash.outputs.sha256 }}

steps:
  - name: Safe shell usage
    run: |
      echo "Repository: ${{ github.repository }}"
      echo "SHA: ${{ github.sha }}"
      echo "Workspace: ${{ github.workspace }}"
```

## Special Cases and Warnings

### GitHub Token Handling
The `github.token` context requires special attention:
- Never expose it directly in outputs
- Use it only for API calls within the workflow
- Consider if downstream consumers actually need it

### User-Controlled Data
Always treat these contexts as potentially malicious:
- `github.actor` (can be spoofed in certain scenarios)
- `github.event.*.title`, `github.event.*.body` (user-provided content)
- `github.head_ref`, `github.base_ref` (branch names)
- Any `inputs.*` from workflow dispatch

### Output Visibility
Remember that outputs are visible in:
- Workflow logs
- Downstream jobs and workflows
- API responses
- Third-party integrations

## Best Practices

1. **Use modern commands**: Replace `::set-output` with `$GITHUB_OUTPUT`
2. **Never expose secrets directly**: Use derived values or boolean flags
3. **Validate user input**: Sanitize before outputting user-controlled data
4. **Quote shell variables**: Always use quotes in shell commands
5. **Document outputs clearly**: Provide detailed descriptions with format information
6. **Minimize sensitive data**: Only output what's actually needed
7. **Test with malicious input**: Verify your validation handles edge cases

## Configuration

The output handling detection runs automatically on all workflow files. Currently, there are no configuration options to disable specific checks, as all detected issues represent potential security risks.

## Performance Notes

- Detection analyzes the complete workflow structure for comprehensive coverage
- Large workflows with many outputs may take slightly longer to process
- The analysis is performed at the AST level for accuracy

## Detected Issue Types

### Output Definition Issues
- **Missing descriptions**: Outputs without documentation
- **Vague descriptions**: Generic terms like "string" or "value"
- **Direct secret exposure**: Raw secrets in output values

### Shell Command Issues
- **Unquoted outputs**: Missing quotes around output references
- **Deprecated commands**: Using `::set-output` instead of `$GITHUB_OUTPUT`
- **Unsafe interpolation**: Expressions that could enable injection

### Data Handling Issues
- **User input exposure**: Direct user-controlled data in outputs
- **Sensitive data leaks**: Tokens, passwords, or keys in outputs
- **Poor sanitization**: Missing validation of special characters

## Limitations

- **Dynamic Values**: Cannot analyze runtime-computed values or complex expressions
- **Action Internals**: Cannot detect issues within custom action implementations
- **Context Dependencies**: Some risks depend on how outputs are consumed downstream
- **Complex Validation**: May not detect sophisticated input validation patterns

## Getting Help

If you encounter false positives or have questions about specific findings:

1. **Check the context** - Ensure the flagged pattern actually poses a risk
2. **Review the fix suggestions** - Most issues have clear resolution paths
3. **Consider the data flow** - Understand how the output will be used
4. **Test with edge cases** - Verify your fixes handle malicious input

For technical issues or feature requests, please refer to the project's issue tracker.

## Related Security Resources

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Workflow Commands for GitHub Actions](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions)
- [OWASP: Information Exposure](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [GitHub Security Lab: Actions Security](https://securitylab.github.com/research/github-actions-untrusted-input/)