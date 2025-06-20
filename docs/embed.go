//go:build doc

package docs

import _ "embed"

//go:embed audit_rules/expression_injection.md
var ExpressionInjectionDocs string
