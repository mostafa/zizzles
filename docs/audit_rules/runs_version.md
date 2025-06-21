# Runs Version

**Category:** `runs_version`  
**Severity:** High (Critical for very old versions)  
**Type:** AST + Pattern-based detection

## Overview

The Runs Version audit rule detects deprecated, unsupported, or missing Node.js versions in GitHub Actions `runs` configuration. This rule helps ensure that your actions use secure, supported Node.js runtime versions.

## Why This Matters

Using deprecated or unsupported Node.js versions poses significant security risks:

1. **End-of-life versions** (like Node.js 12) no longer receive security updates
2. **Deprecated versions** (like Node.js 14) will stop receiving support
3. **Very old versions** (Node.js 10, 8, 6, 4) have known security vulnerabilities
4. **Missing version specifications** can lead to unpredictable runtime behavior

## Detection Rules

### Critical Severity

- **Node.js 12**: End-of-life, no longer supported by GitHub Actions
- **Node.js 10, 8, 6, 4**: Very old versions with known security issues

### High Severity

- **Node.js 14**: Deprecated, support ended

### Medium Severity

- **Unknown Node.js versions**: Any `nodeXX` version not in the supported list
- **Missing `using` field**: JavaScript actions without version specification

### Safe (No Alerts)

- **Node.js 16, 20, 21**: Currently supported versions
- **Docker actions**: Using `docker` runtime
- **Composite actions**: Using `composite` runtime

## Examples

### ❌ Vulnerable (Critical)

```yaml
# End-of-life Node.js 12
runs:
  using: node12
  main: index.js

# Very old unsupported version
runs:
  using: node8
  main: index.js
```

### ❌ Vulnerable (High)

```yaml
# Deprecated Node.js 14
runs:
  using: node14
  main: index.js
```

### ❌ Vulnerable (Medium)

```yaml
# Unknown Node.js version
runs:
  using: node99
  main: index.js

# Missing using field
runs:
  main: index.js  # Should specify 'using: node16' or 'using: node20'
```

### ✅ Safe

```yaml
# Supported Node.js versions
runs:
  using: node16
  main: index.js

runs:
  using: node20
  main: index.js

# Docker action
runs:
  using: docker
  image: Dockerfile

# Composite action
runs:
  using: composite
  steps:
    - run: echo "Safe composite action"
```

## Remediation

### Upgrade to Supported Versions

Replace deprecated versions with supported ones:

```yaml
# Before (Critical)
runs:
  using: node12
  main: index.js

# After (Safe)
runs:
  using: node20
  main: index.js
```

### Add Missing Version Specification

Add the `using` field to JavaScript actions:

```yaml
# Before (Medium)
runs:
  main: index.js

# After (Safe)
runs:
  using: node20
  main: index.js
```

### Update Dependencies

When upgrading Node.js versions, also update your dependencies:

1. Update `package.json` engines field:
   ```json
   {
     "engines": {
       "node": ">=16"
     }
   }
   ```

2. Test your action with the new Node.js version
3. Update GitHub Actions workflow files that test your action

## Current Support Status

| Version | Status | Recommendation |
|---------|---------|----------------|
| node21 | ✅ Supported | Safe to use |
| node20 | ✅ Supported | **Recommended** (LTS) |
| node16 | ✅ Supported | Safe to use |
| node14 | ❌ Deprecated | Upgrade to node20 |
| node12 | ❌ End-of-life | **Critical: Upgrade immediately** |
| node10 | ❌ Unsupported | **Critical: Upgrade immediately** |
| node8 | ❌ Unsupported | **Critical: Upgrade immediately** |

## Configuration

This rule is enabled by default and cannot be disabled as it addresses critical security concerns.

## Related Rules

- `output_handling`: Ensures secure output handling in actions
- `expression_injection`: Prevents command injection in workflow expressions

## References

- [GitHub Actions: Node.js version support](https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#runs-for-javascript-actions)
- [Node.js Release Schedule](https://nodejs.org/en/about/releases/)
- [GitHub Actions Runner Images](https://github.com/actions/runner-images) 