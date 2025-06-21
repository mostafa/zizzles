# Runs Version

## Overview

Runs version vulnerabilities in GitHub Actions occur when workflows use deprecated, unsupported, or missing Node.js runtime versions in their `runs` configuration. These issues expose your custom actions to security risks from end-of-life Node.js versions that no longer receive security updates, potentially compromising your CI/CD pipeline's integrity and security.

Zizzles' runs version detection helps you identify and remediate these vulnerabilities by analyzing your action definition files and providing clear guidance on upgrading to supported Node.js versions. **The detection covers JavaScript action configurations, version specifications, and runtime environment settings.**

## What are Runs Version Issues?

Runs version issues occur when GitHub Actions don't specify appropriate Node.js runtime versions, leading to potential security and compatibility problems. These can include:

### 1. End-of-Life Versions
Using Node.js versions that no longer receive security updates:

```yaml
# CRITICAL: Node.js 12 is end-of-life
runs:
  using: node12
  main: index.js
```

This is critical because Node.js 12 reached end-of-life and GitHub Actions no longer supports it, leaving your action vulnerable to unpatched security issues.

### 2. Deprecated Versions
Using Node.js versions that are deprecated but not yet removed:

```yaml
# HIGH RISK: Node.js 14 is deprecated
runs:
  using: node14
  main: index.js
```

While still functional, deprecated versions will eventually be removed from GitHub Actions, and they receive limited security support.

### 3. Missing Version Specifications
JavaScript actions without explicit runtime version declarations:

```yaml
# MEDIUM RISK: Missing version specification
runs:
  main: index.js  # Should specify 'using: node20'
```

Without explicit version specifications, the action may behave unpredictably or fail when default versions change.

### 4. Unknown Versions
Using unrecognized or very old Node.js versions:

```yaml
# CRITICAL: Unsupported version
runs:
  using: node8
  main: index.js
```

Very old versions like Node.js 8, 10, 6, or 4 have known security vulnerabilities and are not supported by GitHub Actions.

## How Detection Works

Zizzles analyzes your GitHub Actions action definition files (`action.yml`, `action.yaml`) and categorizes runs configurations based on their security and support status:

### Critical Issues
- **Node.js 12**: End-of-life, no longer supported by GitHub Actions
- **Node.js 10, 8, 6, 4**: Very old versions with known security vulnerabilities

### High Risk Issues
- **Node.js 14**: Deprecated, support officially ended

### Medium Risk Issues
- **Unknown versions**: Any `nodeXX` version not in the known supported list
- **Missing specifications**: JavaScript actions without a `using` field

### Safe (No Alerts)
- **Node.js 16, 20, 21**: Currently supported versions
- **Docker actions**: Using `docker` runtime (different security model)
- **Composite actions**: Using `composite` runtime (doesn't require Node.js)

## Understanding the Results

### Severity Levels

- **Critical**: End-of-life or unsupported versions requiring immediate upgrade
- **High**: Deprecated versions needing scheduled migration
- **Medium**: Missing specifications or unknown versions requiring clarification

### Finding Details

Each finding includes:
- **Location**: File, line, and column where the version issue was found
- **Current Version**: The problematic Node.js version detected
- **Issue Type**: Whether it's deprecated, unsupported, or missing
- **Recommendation**: Specific supported version to upgrade to

### Context-Aware Risk Assessment

Zizzles provides specific guidance based on the detected issue:
- **Version-Specific Risks**: Tailored messages for each problematic Node.js version
- **Upgrade Paths**: Clear recommendations for which version to migrate to
- **Support Status**: Current GitHub Actions support status for each version

## Fixing Runs Version Issues

### Automatic Fixes (Future Enhancement)

While Zizzles currently provides detection and guidance, automatic fixes for runs version issues are planned for future releases. The fixes would involve:

**Deprecated Version (Before):**
```yaml
runs:
  using: node12
  main: index.js
```

**Fixed:**
```yaml
runs:
  using: node20
  main: index.js
```

### Manual Fixes

You can fix runs version issues using these approaches:

#### 1. Upgrade to Supported Versions
Replace deprecated or unsupported versions with current ones:

```yaml
# BEFORE (Critical)
runs:
  using: node12
  main: index.js

# AFTER (Safe)
runs:
  using: node20  # LTS version recommended
  main: index.js
```

#### 2. Add Missing Version Specifications
Add explicit version declarations to JavaScript actions:

```yaml
# BEFORE (Medium Risk)
runs:
  main: index.js

# AFTER (Safe)
runs:
  using: node20
  main: index.js
```

#### 3. Update Package Dependencies
When upgrading Node.js versions, also update your action's dependencies:

```json
{
  "name": "my-action",
  "engines": {
    "node": ">=16"
  },
  "dependencies": {
    "@actions/core": "^1.10.0",
    "@actions/github": "^5.1.1"
  }
}
```

## Common Vulnerable Patterns

### 1. End-of-Life Node.js 12
```yaml
# CRITICAL: No longer supported
runs:
  using: node12
  main: index.js

# FIXED: Use supported version
runs:
  using: node20
  main: index.js
```

### 2. Deprecated Node.js 14
```yaml
# HIGH RISK: Deprecated
runs:
  using: node14
  main: index.js

# FIXED: Upgrade to current version
runs:
  using: node20
  main: index.js
```

### 3. Very Old Unsupported Versions
```yaml
# CRITICAL: Multiple security vulnerabilities
runs:
  using: node8
  main: index.js

# FIXED: Use modern version
runs:
  using: node20
  main: index.js
```

### 4. Missing Version Specification
```yaml
# MEDIUM RISK: Unpredictable behavior
runs:
  main: index.js

# FIXED: Explicit version
runs:
  using: node20
  main: index.js
```

### 5. Unknown/Future Versions
```yaml
# MEDIUM RISK: Unknown support status
runs:
  using: node99
  main: index.js

# FIXED: Use known supported version
runs:
  using: node20
  main: index.js
```

## Safe Patterns

These patterns are secure and won't trigger alerts:

```yaml
# All of these are SAFE
runs:
  using: node20  # LTS and recommended
  main: index.js

runs:
  using: node16  # Still supported
  main: index.js

runs:
  using: node21  # Latest version
  main: index.js

# Docker actions (different runtime)
runs:
  using: docker
  image: Dockerfile

# Composite actions (no Node.js required)
runs:
  using: composite
  steps:
    - run: echo "Safe composite action"
      shell: bash
```

## Special Cases and Warnings

### GitHub Actions Runner Support
Node.js version support in GitHub Actions is tied to:
- **GitHub's support policy**: Versions are removed when GitHub stops supporting them
- **Node.js release schedule**: Versions reach end-of-life based on Node.js foundation decisions
- **Security considerations**: Unsupported versions pose security risks

### Migration Timing
When planning upgrades:
- **Critical fixes**: End-of-life versions should be upgraded immediately
- **Deprecated versions**: Plan migration before support ends
- **Testing**: Always test your action with new Node.js versions before releasing

### Compatibility Considerations
Upgrading Node.js versions may require:
- **Dependency updates**: Older packages may not work with newer Node.js versions
- **Code changes**: Some APIs or behaviors may have changed
- **Testing**: Verify functionality across different environments

## Best Practices

1. **Use LTS versions**: Prefer Node.js 20 (current LTS) for stability
2. **Stay current**: Regularly update to supported versions
3. **Test thoroughly**: Verify your action works with new Node.js versions
4. **Update dependencies**: Keep npm packages current when upgrading Node.js
5. **Monitor support status**: Track GitHub Actions version support announcements
6. **Plan migrations**: Schedule upgrades before versions become deprecated
7. **Document requirements**: Clearly specify Node.js version requirements in README

## Configuration

The runs version detection is enabled by default and cannot be disabled, as it addresses critical security and compatibility concerns. The detection runs automatically on all action definition files (`action.yml`, `action.yaml`) in your repository.

## Performance Notes

- Detection is fast and runs at the AST level for accuracy
- Analysis focuses only on `runs` configuration blocks
- No network calls are made during detection
- Large repositories with many actions are processed efficiently

## Detected Issue Types

### Version-Specific Detection
- **node12**: End-of-life, critical security risk
- **node14**: Deprecated, high priority for migration
- **node10, node8, node6, node4**: Unsupported, critical vulnerabilities

### Configuration Issues
- **Missing `using` field**: JavaScript actions without version specification
- **Unknown versions**: Unrecognized `nodeXX` patterns

### Safe Configurations
- **Supported versions**: node16, node20, node21
- **Alternative runtimes**: docker, composite

## Current Support Status

| Version | Status | GitHub Actions Support | Recommendation |
|---------|---------|----------------------|----------------|
| node21 | ✅ Supported | Current | Safe to use |
| node20 | ✅ Supported | **LTS (Recommended)** | **Best Choice** |
| node16 | ✅ Supported | Stable | Safe to use |
| node14 | ❌ Deprecated | Ended | Upgrade to node20 |
| node12 | ❌ End-of-life | **Removed** | **Critical: Upgrade immediately** |
| node10 | ❌ Unsupported | Never supported | **Critical: Upgrade immediately** |
| node8 | ❌ Unsupported | Never supported | **Critical: Upgrade immediately** |

## Limitations

- **Action Internals**: Cannot analyze the JavaScript code within actions for compatibility
- **Dynamic Versions**: Cannot detect runtime version switching or dynamic configuration
- **Dependency Compatibility**: Cannot verify if npm packages work with target Node.js versions
- **Custom Runtimes**: Cannot assess security of custom Docker-based runtimes
- **Future Versions**: Cannot predict support for unreleased Node.js versions

## Getting Help

If you encounter issues or have questions about specific findings:

1. **Check the support status** - Verify the current GitHub Actions support for your Node.js version
2. **Review the upgrade path** - Understand what changes are needed for migration
3. **Test incrementally** - Upgrade in development environments first
4. **Consult action logs** - Check for runtime errors that might indicate compatibility issues

For technical issues or feature requests, please refer to the project's issue tracker.

## Related Security Resources

- [GitHub Actions: Node.js version support](https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#runs-for-javascript-actions)
- [Node.js Release Schedule](https://nodejs.org/en/about/releases/)
- [GitHub Actions Runner Images](https://github.com/actions/runner-images)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [GitHub Security Lab: Actions Security](https://securitylab.github.com/research/github-actions-building-blocks/) 