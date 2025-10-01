// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/kratos/identity"
	flowpkg "github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	passkeystrategy "github.com/ory/kratos/selfservice/strategy/passkey"
	webauthnstrategy "github.com/ory/kratos/selfservice/strategy/webauthn"
	"github.com/ory/kratos/ui/node"
)

type registrationMethodAllowListConfig struct {
	Allowed []string `json:"allowed"`
}

type RegistrationMethodAllowListHook struct {
	allowed map[identity.CredentialsType]struct{}
}

const internalContextAllowedMethodsKey = "registration_allowed_methods"

func NewRegistrationMethodAllowListHook(raw json.RawMessage) (*RegistrationMethodAllowListHook, error) {
	cfg := registrationMethodAllowListConfig{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if len(cfg.Allowed) == 0 {
		cfg.Allowed = []string{identity.CredentialsTypeCodeAuth.String()}
	}

	allowed := map[identity.CredentialsType]struct{}{
		identity.CredentialsTypeProfile: {},
	}

	for _, method := range cfg.Allowed {
		if method == "" {
			continue
		}

		if method == identity.CredentialsTypeProfile.String() {
			allowed[identity.CredentialsTypeProfile] = struct{}{}
			continue
		}

		ct, ok := identity.ParseCredentialsType(method)
		if !ok {
			return nil, errors.WithStack(fmt.Errorf("unknown registration method %q", method))
		}
		allowed[ct] = struct{}{}
	}

	return &RegistrationMethodAllowListHook{allowed: allowed}, nil
}

func (h *RegistrationMethodAllowListHook) ExecuteRegistrationPreHook(_ http.ResponseWriter, _ *http.Request, regFlow *registration.Flow) error {
	if err := setAllowedRegistrationMethods(regFlow, h.allowed); err != nil {
		return err
	}

	return PruneRegistrationFlow(regFlow)
}

func setAllowedRegistrationMethods(regFlow *registration.Flow, allowed map[identity.CredentialsType]struct{}) error {
	methods := make([]string, 0, len(allowed))
	for method := range allowed {
		methods = append(methods, method.String())
	}

	var err error
	regFlow.InternalContext, err = sjson.SetBytes(regFlow.InternalContext, internalContextAllowedMethodsKey, methods)
	return errors.WithStack(err)
}

func removeFlowArtifacts(regFlow *registration.Flow, ct identity.CredentialsType) error {
	group := ct.ToUiNodeGroup()
	if group != "" && group != node.DefaultGroup {
		filterNodesByGroup(regFlow, group)
	}

	if suffixes, ok := internalContextCleanupSuffixes[ct]; ok {
		var err error
		for _, suffix := range suffixes {
			regFlow.InternalContext, err = sjson.DeleteBytes(regFlow.InternalContext, flowpkg.PrefixInternalContextKey(ct, suffix))
			if err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}

var internalContextCleanupSuffixes = map[identity.CredentialsType][]string{
	identity.CredentialsTypePasskey: {
		passkeystrategy.InternalContextKeySessionData,
		passkeystrategy.InternalContextKeySessionOptions,
	},
	identity.CredentialsTypeWebAuthn: {
		webauthnstrategy.InternalContextKeySessionData,
		webauthnstrategy.InternalContextKeyWebauthnOptions,
	},
}

func filterNodesByGroup(regFlow *registration.Flow, group node.UiNodeGroup) {
	if regFlow.UI == nil {
		return
	}

	filtered := make(node.Nodes, 0, len(regFlow.UI.Nodes))
	for _, n := range regFlow.UI.Nodes {
		if n.Group == group {
			continue
		}
		filtered = append(filtered, n)
	}

	regFlow.UI.Nodes = filtered
}

// AllowedRegistrationMethods returns the set of credential types permitted for this flow.
func AllowedRegistrationMethods(regFlow *registration.Flow) map[identity.CredentialsType]struct{} {
	raw := gjson.GetBytes(regFlow.InternalContext, internalContextAllowedMethodsKey)
	if !raw.Exists() {
		return nil
	}

	values := raw.Array()
	allowed := make(map[identity.CredentialsType]struct{}, len(values))
	for _, v := range values {
		if v.String() == identity.CredentialsTypeProfile.String() {
			allowed[identity.CredentialsTypeProfile] = struct{}{}
			continue
		}

		ct, ok := identity.ParseCredentialsType(v.String())
		if !ok {
			continue
		}
		allowed[ct] = struct{}{}
	}
	return allowed
}

// PruneRegistrationFlow removes UI nodes and state belonging to disallowed strategies.
func PruneRegistrationFlow(regFlow *registration.Flow) error {
	allowed := AllowedRegistrationMethods(regFlow)
	if len(allowed) == 0 {
		return nil
	}

	for _, ct := range identity.AllCredentialTypes {
		if _, ok := allowed[ct]; ok {
			continue
		}

		if err := removeFlowArtifacts(regFlow, ct); err != nil {
			return err
		}
	}

	return nil
}
