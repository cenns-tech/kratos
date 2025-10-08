// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"net/http"
	"strings"

	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/x/jsonschemax"
)

type immutableIdentifierTraitsHookDependencies interface {
	schema.IdentitySchemaProvider
}

// ImmutableIdentifierTraitsHook collects identifier traits from the identity schema and marks them as immutable for the settings flow.
type ImmutableIdentifierTraitsHook struct {
	d immutableIdentifierTraitsHookDependencies
}

func NewImmutableIdentifierTraitsHook(d immutableIdentifierTraitsHookDependencies) *ImmutableIdentifierTraitsHook {
	return &ImmutableIdentifierTraitsHook{d: d}
}

func (h *ImmutableIdentifierTraitsHook) ExecuteSettingsPreHook(_ http.ResponseWriter, r *http.Request, flow *settings.Flow) error {
	if flow == nil || flow.Identity == nil {
		return nil
	}

	schemas, err := h.d.IdentityTraitsSchemas(r.Context())
	if err != nil {
		return err
	}

	identitySchema, err := schemas.GetByID(flow.Identity.SchemaID)
	if err != nil {
		return err
	}

	compiler := jsonschema.NewCompiler()
	compiler.ExtractAnnotations = true

	// Register the Kratos schema extension so `jsonschemax` exposes the custom properties we need to inspect.
	runner, err := schema.NewExtensionRunner(r.Context())
	if err != nil {
		return err
	}
	runner.Register(compiler)

	paths, err := jsonschemax.ListPaths(r.Context(), identitySchema.URL.String(), compiler)
	if err != nil {
		return err
	}

	var immutable []string
	for _, p := range paths {
		if !strings.HasPrefix(p.Name, "traits.") {
			continue
		}

		cfg, ok := p.CustomProperties[schema.ExtensionName]
		if !ok {
			continue
		}

		extensionConfig, ok := cfg.(*schema.ExtensionConfig)
		if !ok || extensionConfig == nil {
			continue
		}

		if hasIdentifierCredential(extensionConfig) {
			immutable = append(immutable, p.Name)
		}
	}

	return settings.SetImmutableIdentifierTraits(flow, immutable)
}

func hasIdentifierCredential(cfg *schema.ExtensionConfig) bool {
	if cfg == nil {
		return false
	}

	switch {
	case cfg.Credentials.Password.Identifier,
		cfg.Credentials.WebAuthn.Identifier,
		cfg.Credentials.Code.Identifier:
		return true
	}

	return false
}
