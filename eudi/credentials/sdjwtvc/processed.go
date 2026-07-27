package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

type ProcessedSdJwtPayload map[string]any

// MarshalJSON ensures that the JSON encoding of the ProcessedSdJwtPayload is deterministic by sorting map keys, which is necessary for consistent hashing of the payload.
// In order to calculate the hash consistently, the entire payload structure has to be sorted.
// Fortunately, ProcessedSdJwtPayload is built up from map[string]any structures (where any is either a scalar value, a map, or an array), which we can sort by marshalling to JSON, which already sorts map keys.
func (p *ProcessedSdJwtPayload) MarshalJSON() ([]byte, error) {
	p.Sort()
	return json.Marshal(map[string]any(*p))
}

// Sort sorts the ProcessedSdJwtPayload in place, by sorting all arrays by their values (when the array is of a scalar type).
// This ensures that the JSON encoding of the payload is deterministic, which is necessary for consistent hashing of the payload.
// As the map is keyed, it cannot be sorted itself, but this is handled by the JSON marshalling.
func (p *ProcessedSdJwtPayload) Sort() {
	for _, v := range *p {
		rt := reflect.TypeOf(v)
		switch rt.Kind() {
		case reflect.Map:
			m, ok := v.(ProcessedSdJwtPayload)
			if ok {
				m.Sort()
			} else {
				panic(fmt.Errorf("unexpected map type in ProcessedSdJwtPayload: %v", rt))
			}
		case reflect.Slice, reflect.Array:
			kind := rt.Elem().Kind()
			switch kind {
			case reflect.Float32:
				slices.Sort(v.([]float32))
			case reflect.Float64:
				slices.Sort(v.([]float64))
			case reflect.Uint8:
				slices.Sort(v.([]uint8))
			case reflect.Uint16:
				slices.Sort(v.([]uint16))
			case reflect.Uint32:
				slices.Sort(v.([]uint32))
			case reflect.Uint64:
				slices.Sort(v.([]uint64))
			case reflect.Uint:
				slices.Sort(v.([]uint))
			case reflect.Int8:
				slices.Sort(v.([]int8))
			case reflect.Int16:
				slices.Sort(v.([]int16))
			case reflect.Int32:
				slices.Sort(v.([]int32))
			case reflect.Int64:
				slices.Sort(v.([]int64))
			case reflect.Int:
				slices.Sort(v.([]int))
			case reflect.String:
				slices.Sort(v.([]string))
			}
		}
	}
}

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
