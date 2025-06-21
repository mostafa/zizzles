# Docker Security

## Overview

Docker security vulnerabilities in GitHub Actions occur when custom actions use insecure Docker configurations, unpinned images, or poor containerization practices. These issues can expose your CI/CD pipeline to supply chain attacks, privilege escalation, and compromise through malicious container configurations.

Zizzles' Docker security detection helps you identify and fix these vulnerabilities by analyzing your action definition files for insecure Docker patterns, unpinned images, and dangerous configurations. **The detection covers Docker image specifications, user configurations, base image choices, and container security practices.**

## What are Docker Security Issues?

Docker security issues occur when GitHub Actions use Docker containers without proper security considerations, leading to potential vulnerabilities. These can include:

### 1. Unpinned Dangerous Tags
Using mutable tags that can be updated maliciously:

```yaml
# CRITICAL: Latest tag can be updated by attackers
runs:
  using: docker
  image: docker://ubuntu:latest
```

This is critical because `latest`, `main`, `master`, and `develop` tags are mutable and can be replaced by attackers to inject malicious code into your build process.

### 2. Unpinned Images Without SHA256
Using specific version tags without digest pinning:

```yaml
# HIGH RISK: Version can still be overwritten
runs:
  using: docker
  image: docker://node:18.16.0-alpine
```

Even specific versions can be overwritten in some registries, making SHA256 digest pinning the only reliable way to ensure image integrity.

### 3. Root User Execution
Running containers as root without explicit user configuration:

```yaml
# HIGH RISK: Missing USER directive runs as root
runs:
  using: docker
  dockerfile: |
    FROM node:18-alpine
    COPY . /app
    # Missing USER directive - runs as root
    CMD ["node", "index.js"]
```

Running as root increases the attack surface and potential impact of container compromise.

### 4. Secrets Exposure
Commands that may leak sensitive information:

```yaml
# HIGH RISK: Secret may be exposed in logs
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN echo "Debug token: $INPUT_SECRET_TOKEN"
```

Secrets can be exposed through logs, process lists, or error messages if not handled properly.

### 5. Non-Minimal Base Images
Using full operating system images instead of minimal alternatives:

```yaml
# MEDIUM RISK: Large attack surface
runs:
  using: docker
  image: docker://ubuntu:20.04
```

Full OS images contain many unnecessary packages and services that increase the attack surface.

### 6. Development Tools in Production
Including development tools in production containers:

```yaml
# MEDIUM RISK: Unnecessary tools increase attack surface
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN apk add --no-cache curl wget git build-essential
```

Development tools provide additional attack vectors and are unnecessary in production containers.

## How Detection Works

Zizzles analyzes your GitHub Actions action definition files (`action.yml`, `action.yaml`) and categorizes Docker configurations based on their security risk:

### Critical Issues
- **Dangerous mutable tags**: `latest`, `main`, `master`, `develop` - can be replaced by attackers
- **Very old base images**: Severely outdated images with known vulnerabilities

### High Risk Issues
- **Unpinned images**: Specific versions without SHA256 digest verification
- **Root user execution**: Missing `USER` directive in Dockerfiles
- **Secrets exposure**: Commands that may leak sensitive information in logs or output

### Medium Risk Issues
- **Non-minimal base images**: Full OS images like `ubuntu`, `debian`, `centos`, `fedora` without `-slim` variants
- **Development tools**: Installation of unnecessary development packages in production images

### Low Risk Issues
- **Documentation issues**: Missing or unclear action descriptions
- **Best practice violations**: Configurations that work but don't follow security best practices

## Understanding the Results

### Severity Levels

- **Critical**: Mutable tags or configurations that allow immediate supply chain attacks
- **High**: Unpinned images, root execution, or potential secrets exposure requiring immediate attention
- **Medium**: Non-minimal images or unnecessary tools that increase attack surface
- **Low**: Documentation and best practice issues

### Finding Details

Each finding includes:
- **Location**: File, line, and column where the issue was found
- **Issue Type**: The specific Docker security problem detected
- **Risk Level**: Why this pattern is problematic
- **Context**: Whether it's in image specifications, Dockerfile content, or action configuration

### Context-Aware Risk Assessment

Zizzles provides specific guidance based on context:
- **Image Specifications**: Issues with how Docker images are referenced and pinned
- **Dockerfile Analysis**: Problems within inline Dockerfile configurations
- **User Configuration**: Issues with container user and permission settings
- **Base Image Selection**: Recommendations for more secure base image choices

## Fixing Docker Security Issues

### Automatic Fixes (Future Enhancement)

While Zizzles currently provides detection and guidance, automatic fixes for Docker security issues are planned for future releases. The fixes would involve:

**Unpinned image (Before):**
```yaml
runs:
  using: docker
  image: docker://node:18.16.0-alpine
```

**Fixed:**
```yaml
runs:
  using: docker
  image: docker://node:18.16.0-alpine@sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890
```

### Manual Fixes

You can fix Docker security issues using these approaches:

#### 1. Pin Images with SHA256 Digests
Replace unpinned images with digest-pinned versions:

```yaml
# BEFORE (High Risk)
runs:
  using: docker
  image: docker://node:18.16.0-alpine

# AFTER (Secure)
runs:
  using: docker
  image: docker://node:18.16.0-alpine@sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890
```

To get the SHA256 digest:
```bash
docker pull node:18.16.0-alpine
docker inspect node:18.16.0-alpine | grep Id
```

#### 2. Add Non-Root User Configuration
Add USER directive to run containers as non-root:

```yaml
# BEFORE (High Risk)
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    COPY . /app
    CMD ["./app"]

# AFTER (Secure)
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN adduser -D -s /bin/sh appuser
    COPY . /app
    WORKDIR /app
    USER appuser
    CMD ["./app"]
```

#### 3. Use Minimal Base Images
Replace full OS images with minimal alternatives:

```yaml
# BEFORE (Medium Risk)
runs:
  using: docker
  image: docker://ubuntu:20.04

# AFTER (Better)
runs:
  using: docker
  image: docker://ubuntu:20.04-slim
  # or even better
  image: docker://alpine:3.18
  # or for static binaries
  image: docker://scratch
```

#### 4. Use Multi-Stage Builds for Development Tools
Separate build and runtime environments:

```yaml
# SECURE: Multi-stage build
runs:
  using: docker
  dockerfile: |
    # Build stage with dev tools
    FROM alpine:3.18 AS builder
    RUN apk add --no-cache build-base git
    COPY . /src
    WORKDIR /src
    RUN make build
    
    # Production stage - clean and minimal
    FROM alpine:3.18
    RUN adduser -D -s /bin/sh appuser
    COPY --from=builder /src/app /app/
    USER appuser
    CMD ["./app"]
```

#### 5. Secure Secret Handling
Avoid exposing secrets in logs or output:

```yaml
# BEFORE (High Risk)
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN echo "Token: $INPUT_SECRET"  # Exposed in logs

# AFTER (Secure)
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN adduser -D -s /bin/sh appuser
    COPY entrypoint.sh /entrypoint.sh
    RUN chmod +x /entrypoint.sh
    USER appuser
    ENTRYPOINT ["/entrypoint.sh"]
```

## Common Vulnerable Patterns

### 1. Dangerous Mutable Tags
```yaml
# CRITICAL: Can be replaced by attackers
image: docker://ubuntu:latest
image: docker://node:main
image: docker://python:develop

# FIXED: Use specific pinned versions
image: docker://ubuntu:20.04@sha256:digest
image: docker://node:18.16.0-alpine@sha256:digest
image: docker://python:3.11-alpine@sha256:digest
```

### 2. Unpinned Specific Versions
```yaml
# HIGH RISK: Still vulnerable to overwrites
image: docker://node:18.16.0-alpine

# FIXED: Pin with SHA256 digest
image: docker://node:18.16.0-alpine@sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890
```

### 3. Root User Execution
```yaml
# HIGH RISK: Missing USER directive
dockerfile: |
  FROM alpine:3.18
  COPY . /app
  CMD ["./app"]

# FIXED: Add non-root user
dockerfile: |
  FROM alpine:3.18
  RUN adduser -D -s /bin/sh appuser
  COPY . /app
  USER appuser
  CMD ["./app"]
```

### 4. Non-Minimal Base Images
```yaml
# MEDIUM RISK: Large attack surface
image: docker://ubuntu:20.04

# BETTER: Use slim variant
image: docker://ubuntu:20.04-slim

# BEST: Use minimal image
image: docker://alpine:3.18
```

### 5. Development Tools in Production
```yaml
# MEDIUM RISK: Unnecessary tools
dockerfile: |
  FROM alpine:3.18
  RUN apk add --no-cache curl wget git vim

# FIXED: Multi-stage build
dockerfile: |
  FROM alpine:3.18 AS builder
  RUN apk add --no-cache git build-base
  COPY . /src
  RUN cd /src && make build
  
  FROM alpine:3.18
  RUN adduser -D -s /bin/sh appuser
  COPY --from=builder /src/app /app/
  USER appuser
  CMD ["./app"]
```

## Safe Patterns

These patterns are secure and won't trigger alerts:

```yaml
# All of these are SAFE
runs:
  using: docker
  image: docker://alpine:3.18@sha256:digest

runs:
  using: docker
  image: docker://gcr.io/distroless/static:nonroot@sha256:digest

runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18@sha256:digest
    RUN adduser -D -s /bin/sh appuser
    COPY . /app
    WORKDIR /app
    USER appuser
    CMD ["./app"]

# Minimal images that don't need USER directive
runs:
  using: docker
  image: docker://scratch
  
runs:
  using: docker
  image: docker://gcr.io/distroless/static:nonroot
```

## Special Cases and Warnings

### Container Registry Considerations
Different registries have different security models:
- **Docker Hub**: Public images can be overwritten by repository owners
- **GitHub Container Registry**: Better access controls and security features
- **Cloud Provider Registries**: Often include vulnerability scanning and access controls

### Base Image Selection
Consider security implications of base image choices:
- **Alpine Linux**: Minimal, security-focused, but uses musl libc which may cause compatibility issues
- **Distroless**: Google's minimal images without package managers or shells
- **Ubuntu/Debian Slim**: Smaller versions of popular distributions
- **Scratch**: Empty base image for static binaries

### Multi-Architecture Considerations
When using digest pinning with multi-architecture images:
- Use manifest list digests when available
- Test across different architectures (amd64, arm64)
- Consider using platform-specific digests if needed

## Best Practices

1. **Always pin images with SHA256 digests** for supply chain security
2. **Use minimal base images** to reduce attack surface
3. **Run as non-root user** whenever possible
4. **Use multi-stage builds** to keep production images clean
5. **Regularly update base images** and re-pin with new digests
6. **Scan images for vulnerabilities** before use
7. **Avoid installing unnecessary packages** in production images
8. **Handle secrets securely** without exposing them in logs
9. **Use specific version tags** instead of mutable tags
10. **Document your security choices** in action README files

## Configuration

The Docker security detection is enabled by default and runs automatically on all action definition files (`action.yml`, `action.yaml`) in your repository. The rule performs both AST-based analysis for complex scenarios and pattern-based matching for common vulnerabilities.

### Customization Options (Future)
Future versions may include configuration options for:
- Approved base image registries
- Custom security policy enforcement
- Severity level adjustments
- Exclusion patterns for specific use cases

## Performance Notes

- Detection is fast and runs at the AST level for accuracy
- Analysis focuses only on Docker-related configuration blocks
- Dockerfile parsing handles inline configurations efficiently
- Large repositories with many Docker actions are processed quickly

## Detected Issue Types

### Image Security
- **Dangerous tags**: `latest`, `main`, `master`, `develop`
- **Unpinned versions**: Specific versions without digest pinning
- **Old base images**: Outdated images with known vulnerabilities

### Container Configuration
- **Root execution**: Missing `USER` directive in Dockerfiles
- **Secrets exposure**: Commands that may leak sensitive information
- **Non-minimal images**: Full OS images instead of minimal alternatives

### Development Practices
- **Development tools**: Unnecessary packages in production images
- **Multi-stage builds**: Missing separation of build and runtime environments

## Current Security Standards

| Pattern | Risk Level | GitHub Actions Impact | Recommendation |
|---------|------------|----------------------|----------------|
| `image:latest` | 🔴 Critical | **Supply chain attack vector** | **Pin with SHA256 immediately** |
| `node:18` | 🟠 High | Potential overwrite | Pin with digest |
| `ubuntu:20.04` | 🟡 Medium | Large attack surface | Use `ubuntu:20.04-slim` or Alpine |
| Missing `USER` | 🟠 High | **Privilege escalation risk** | **Add non-root user** |
| Dev tools | 🟡 Medium | Increased attack surface | Use multi-stage builds |

## Limitations

- **Dynamic Configurations**: Cannot analyze runtime-generated Dockerfile content
- **External Dockerfiles**: Limited analysis of Dockerfiles not inline in action.yml
- **Registry Security**: Cannot verify the security of external registries
- **Multi-Architecture**: Digest verification may vary across architectures
- **Custom Base Images**: Cannot assess security of private or custom base images

## Getting Help

If you encounter issues or have questions about specific findings:

1. **Verify the risk level** - Understand why the pattern is flagged as insecure
2. **Check pinning requirements** - Learn how to properly pin images with SHA256 digests
3. **Review base image options** - Explore minimal and secure base image alternatives
4. **Test security changes** - Validate that security improvements don't break functionality

For technical issues or feature requests, please refer to the project's issue tracker.

## Related Security Resources

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [GitHub Actions: Creating Docker container actions](https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action)
- [NIST Container Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Docker Official Images Security](https://docs.docker.com/docker-hub/official_images/)
- [Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [Alpine Linux Security](https://alpinelinux.org/about/)
