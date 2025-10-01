package hook_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/kratos/identity"
	flowpkg "github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/hook"
	passkeystrategy "github.com/ory/kratos/selfservice/strategy/passkey"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
)

func TestRegistrationMethodAllowListHook(t *testing.T) {
	raw := json.RawMessage(`{"allowed":["code"]}`)
	h, err := hook.NewRegistrationMethodAllowListHook(raw)
	require.NoError(t, err)

	regFlow := &registration.Flow{
		UI: &container.Container{
			Nodes: node.Nodes{
				node.NewInputField("method", identity.CredentialsTypeCodeAuth.String(), node.CodeGroup, node.InputAttributeTypeHidden),
				node.NewInputField(node.PasskeyRegister, "", node.PasskeyGroup, node.InputAttributeTypeHidden),
				node.NewInputField("webauthn_node", "", node.WebAuthnGroup, node.InputAttributeTypeHidden),
			},
		},
		InternalContext: []byte("{}"),
	}

	var setErr error
	regFlow.InternalContext, setErr = sjson.SetBytes(regFlow.InternalContext, flowpkg.PrefixInternalContextKey(identity.CredentialsTypePasskey, passkeystrategy.InternalContextKeySessionData), map[string]string{"foo": "bar"})
	require.NoError(t, setErr)
	regFlow.InternalContext, setErr = sjson.SetBytes(regFlow.InternalContext, flowpkg.PrefixInternalContextKey(identity.CredentialsTypePasskey, passkeystrategy.InternalContextKeySessionOptions), map[string]string{"baz": "qux"})
	require.NoError(t, setErr)

	req := httptest.NewRequest("GET", "/", nil)
	err = h.ExecuteRegistrationPreHook(nil, req, regFlow)
	require.NoError(t, err)

	allowed := hook.AllowedRegistrationMethods(regFlow)
	require.Contains(t, allowed, identity.CredentialsTypeCodeAuth)
	require.Contains(t, allowed, identity.CredentialsTypeProfile)
	require.NotContains(t, allowed, identity.CredentialsTypePasskey)

	require.NotNil(t, regFlow.UI.Nodes.Find("method"))
	require.Nil(t, regFlow.UI.Nodes.Find(node.PasskeyRegister))
	require.Nil(t, regFlow.UI.Nodes.Find("webauthn_node"))

	require.False(t, gjson.GetBytes(regFlow.InternalContext, flowpkg.PrefixInternalContextKey(identity.CredentialsTypePasskey, passkeystrategy.InternalContextKeySessionData)).Exists())
	require.False(t, gjson.GetBytes(regFlow.InternalContext, flowpkg.PrefixInternalContextKey(identity.CredentialsTypePasskey, passkeystrategy.InternalContextKeySessionOptions)).Exists())

	// Simulate strategies hydrating passkey again and ensure pruning works when called manually.
	regFlow.UI.Nodes = append(regFlow.UI.Nodes,
		node.NewInputField(node.PasskeyRegisterTrigger, "", node.PasskeyGroup, node.InputAttributeTypeButton),
		node.NewInputField(node.PasskeyRegister, "", node.PasskeyGroup, node.InputAttributeTypeHidden),
	)

	require.NoError(t, hook.PruneRegistrationFlow(regFlow))
	require.Nil(t, regFlow.UI.Nodes.Find(node.PasskeyRegister))
}
