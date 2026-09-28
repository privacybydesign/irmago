package dcql

import (
	"bytes"
	"math"
	"reflect"
)

// ClaimValuesEqual compares one disclosed claim value against one value from a
// credential query's `values` constraint.
//
// It must not use ==. Both operands are decoded from untrusted documents into
// `any` — the claim value from the credential held by the wallet, the expected
// value from the verifier's authorization request — so either can hold a slice
// or a map. Go's == panics at runtime when two interface values share a dynamic
// type that is not comparable, and an array-valued claim compared against an
// array in `values` is exactly that case: both are []any, and the process dies
// with "comparing uncomparable type []interface {}". That happens while the
// permission screen is being rendered, so a verifier could crash the wallet
// with a single crafted request, before the user is asked anything.
//
// Numbers are compared across representations because these two values do not
// always arrive through the same decoder: JSON yields float64 for every number
// while CBOR yields uint64/int64, so a value constraint on an integer claim
// would otherwise never match. Integers keep full precision; a float equals an
// integer only when it is integral and converts back exactly. Values beyond
// float64's exact integer range fall through to the structural comparison,
// which still matches two identically-typed integers.
//
// Shared by the eudi_sdjwt_dcql and mdoc_dcql handlers: only the mdoc side can
// reach the CBOR cases, but the uncomparable-type panic was reachable from both,
// and it had already been fixed in one copy and not the other. One
// implementation and one set of tests keeps them from drifting again.
// irma_sdjwt_dcql does not use this — it compares idemix attributes, which are
// strings by construction, and asserts to string before comparing.
func ClaimValuesEqual(actual, expected any) bool {
	if ai, ok := claimValueAsInteger(actual); ok {
		ei, ok := claimValueAsInteger(expected)
		return ok && ai == ei
	}
	if af, ok := claimValueAsFloat(actual); ok {
		ef, ok := claimValueAsFloat(expected)
		return ok && af == ef
	}

	switch a := actual.(type) {
	case nil:
		return expected == nil
	case string:
		e, ok := expected.(string)
		return ok && a == e
	case bool:
		e, ok := expected.(bool)
		return ok && a == e
	case []byte:
		e, ok := expected.([]byte)
		return ok && bytes.Equal(a, e)
	case []any:
		e, ok := expected.([]any)
		if !ok || len(a) != len(e) {
			return false
		}
		for i := range a {
			if !ClaimValuesEqual(a[i], e[i]) {
				return false
			}
		}
		return true
	}

	if am, ok := claimValueAsMap(actual); ok {
		em, ok := claimValueAsMap(expected)
		if !ok || len(am) != len(em) {
			return false
		}
		for k, av := range am {
			ev, present := em[k]
			if !present || !ClaimValuesEqual(av, ev) {
				return false
			}
		}
		return true
	}

	// Anything left is a type neither decoder produces. reflect.DeepEqual is the
	// safe default here: unlike ==, it reports false for uncomparable types
	// instead of panicking.
	return reflect.DeepEqual(actual, expected)
}

// claimValueAsInteger reports v as an int64 when it holds an integral number,
// including a float that is exactly integral. Returns false for a uint64 above
// math.MaxInt64, which cannot be represented; such a value is handled by the
// structural comparison in ClaimValuesEqual instead.
func claimValueAsInteger(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float32:
		return integralFloatAsInt64(float64(n))
	case float64:
		return integralFloatAsInt64(n)
	}
	return 0, false
}

// integralFloatAsInt64 converts f to an int64 only when it is integral, within
// range, and converts back to exactly the same value.
func integralFloatAsInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	if f < math.MinInt64 || f >= math.MaxInt64 {
		return 0, false
	}
	i := int64(f)
	if float64(i) != f {
		return 0, false
	}
	return i, true
}

// claimValueAsFloat reports v as a float64 when it holds a non-integral number
// (the integral cases are taken by claimValueAsInteger first).
func claimValueAsFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// claimValueAsMap normalizes the two map shapes the decoders produce —
// map[string]any from JSON, map[any]any from CBOR — to one keyed by string, so
// a claim decoded from CBOR can be compared against a constraint decoded from
// JSON. A CBOR map with a non-string key cannot correspond to any JSON object
// and is reported as not a map.
func claimValueAsMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	}
	return nil, false
}
