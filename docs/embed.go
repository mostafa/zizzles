//go:build doc

package docs

import _ "embed"

//go:embed audit_rules/expression_injection.md
var ExpressionInjectionDocs string

//go:embed audit_rules/output_handling.md
var OutputHandlingDocs string

//go:embed audit_rules/runs_version.md
var RunsVersionDocs string

//go:embed audit_rules/docker_security.md
var DockerSecurityDocs string
