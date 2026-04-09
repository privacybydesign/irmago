package sdjwtvc

import (
	"fmt"
	"reflect"
)

// GetClaimValue resolves a claims path pointer against the processed SD-JWT payload,
// as defined in Appendix C of the OpenID4VCI specification.
//
// Each element of pathPointer must be a string, a non-negative int, or nil:
//   - string: selects the value of the named key in the current object.
//   - int: selects the element at the given index in the current array.
//   - nil: asserts the current value is an array and keeps it as the selection.
//
// Navigation descends through nested ProcessedSdJwtPayload values and slices.
// Returns the value at the end of the path, or an error if:
//   - a path component has an unsupported type,
//   - an intermediate value is not an object when a string key is used,
//   - an intermediate value is not an array when an integer index or nil is used,
//   - a key is not present in the current object, or
//   - an index is out of range.
func (p *ProcessedSdJwtPayload) GetClaimValue(pathPointer []any) (any, error) {
	if p == nil && len(pathPointer) > 0 {
		return nil, fmt.Errorf("processed SD-JWT payload is nil")
	}
	if len(pathPointer) == 0 {
		return p, nil
	}

	var current any = *p
	for i, component := range pathPointer {
		switch key := component.(type) {
		case string:
			var m map[string]any
			switch v := current.(type) {
			case ProcessedSdJwtPayload:
				m = v
			case map[string]any:
				m = v
			default:
				return nil, fmt.Errorf("path component %d (%q): expected object, got %T", i, key, current)
			}
			val, exists := m[key]
			if !exists {
				return nil, fmt.Errorf("path component %d (%q): key not found", i, key)
			}
			current = val
		case int:
			rv := reflect.ValueOf(current)
			if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
				return nil, fmt.Errorf("path component %d (%d): expected array, got %T", i, key, current)
			}
			if key < 0 || key >= rv.Len() {
				return nil, fmt.Errorf("path component %d (%d): index out of range (length %d)", i, key, rv.Len())
			}
			current = rv.Index(key).Interface()
		case float64:
			// JSON numbers are decoded as float64; treat as an integer index.
			idx := int(key)
			rv := reflect.ValueOf(current)
			if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
				return nil, fmt.Errorf("path component %d (%v): expected array, got %T", i, key, current)
			}
			if idx < 0 || idx >= rv.Len() {
				return nil, fmt.Errorf("path component %d (%v): index out of range (length %d)", i, key, rv.Len())
			}
			current = rv.Index(idx).Interface()
		case nil:
			rv := reflect.ValueOf(current)
			if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
				return nil, fmt.Errorf("path component %d (null): expected array, got %T", i, current)
			}
			// current is already the selected array; no change needed.
		default:
			return nil, fmt.Errorf("path component %d: unsupported type %T, must be string, int, or nil", i, component)
		}
	}
	return current, nil
}
