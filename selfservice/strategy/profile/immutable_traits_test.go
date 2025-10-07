package profile

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/stretchr/testify/require"
)

func TestSanitizeImmutableIdentifierTraits(t *testing.T) {
	flow := &settings.Flow{InternalContext: []byte(fmt.Sprintf(`{"%s":["traits.email"]}`, settings.InternalContextKeyImmutableIdentifierTraits))}
	identity := &identity.Identity{Traits: identity.Traits(`{"email":"foo@ory.sh","name":"Foo"}`)}

	sanitized, err := sanitizeImmutableIdentifierTraits(flow, identity, json.RawMessage(`{"name":"Bar"}`))
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"Bar","email":"foo@ory.sh"}`, string(sanitized))

	_, err = sanitizeImmutableIdentifierTraits(flow, identity, json.RawMessage(`{"email":"bar@ory.sh"}`))
	require.Error(t, err)
}
