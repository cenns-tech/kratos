package settings

import (
	"slices"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// InternalContextKeyImmutableIdentifierTraits stores the key used to persist immutable identifier traits on the flow.
const InternalContextKeyImmutableIdentifierTraits = "immutable_identifier_traits"

// SetImmutableIdentifierTraits persists the immutable identifier trait paths on the given flow.
func SetImmutableIdentifierTraits(flow *Flow, traits []string) error {
	if flow == nil {
		return nil
	}

	if len(traits) == 0 {
		var err error
		flow.InternalContext, err = sjson.DeleteBytes(flow.InternalContext, InternalContextKeyImmutableIdentifierTraits)
		return errors.WithStack(err)
	}

	flow.EnsureInternalContext()
	copyTraits := slices.Clone(traits)
	slices.Sort(copyTraits)
	copyTraits = slices.Compact(copyTraits)

	var err error
	flow.InternalContext, err = sjson.SetBytes(flow.InternalContext, InternalContextKeyImmutableIdentifierTraits, copyTraits)
	return errors.WithStack(err)
}

// ImmutableIdentifierTraits returns the immutable identifier traits stored on the flow.
func ImmutableIdentifierTraits(flow *Flow) []string {
	if flow == nil {
		return nil
	}

	raw := gjson.GetBytes(flow.InternalContext, InternalContextKeyImmutableIdentifierTraits)
	if !raw.Exists() {
		return nil
	}

	values := raw.Array()
	traits := make([]string, 0, len(values))
	for _, v := range values {
		if v.Str != "" {
			traits = append(traits, v.Str)
		}
	}
	return traits
}
