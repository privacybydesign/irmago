package sdjwt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
)

type ProcessedPayload map[string]any

// MarshalJSON ensures that the JSON encoding of the ProcessedPayload is deterministic by sorting map keys, which is necessary for consistent hashing of the payload.
// In order to calculate the hash consistently, the entire payload structure has to be sorted.
// Fortunately, ProcessedPayload is built up from map[string]any structures (where any is either a scalar value, a map, or an array), which we can sort by marshalling to JSON, which already sorts map keys.
func (p *ProcessedPayload) MarshalJSON() ([]byte, error) {
	p.Sort()
	return json.Marshal(map[string]any(*p))
}

// Sort sorts the ProcessedPayload in place, by sorting all arrays by their values (when the array is of a scalar type).
// This ensures that the JSON encoding of the payload is deterministic, which is necessary for consistent hashing of the payload.
// As the map is keyed, it cannot be sorted itself, but this is handled by the JSON marshalling.
func (p *ProcessedPayload) Sort() {
	for k, v := range *p {
		rt := reflect.TypeOf(v)

		if rt == nil {
			continue
		}

		switch rt.Kind() {
		case reflect.Map:
			m, ok := v.(ProcessedPayload)
			if ok {
				m.Sort()
			} else {
				panic(fmt.Errorf("unexpected map type in ProcessedPayload: %v", rt))
			}
		case reflect.Slice, reflect.Array:
			var kind reflect.Kind

			// Find the kind of the slice or array, by iterating through the elements and checking their types.
			// If all types are equal, we can sort the slice or array by that type. If the types are not equal, we cannot sort the slice or array.
			if v != nil && reflect.ValueOf(v).Len() != 0 {
				kind = reflect.TypeOf(reflect.ValueOf(v).Index(0).Interface()).Kind()
				for i := 1; i < reflect.ValueOf(v).Len(); i++ {
					elemKind := reflect.TypeOf(reflect.ValueOf(v).Index(i).Interface()).Kind()
					if elemKind != kind {
						// Mixed types in the slice or array, cannot sort.
						kind = reflect.Invalid
						break
					}
				}
				if kind == reflect.Invalid {
					continue // Skip sorting this slice or array, as it has mixed types.
				}
			}

			im, err := json.Marshal(v)
			if err != nil {
				panic(fmt.Errorf("failed to marshal slice or array in ProcessedPayload: %v", err))
			}

			switch kind {
			case reflect.Float32:
				arr := []float32{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Float64:
				arr := []float64{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Uint8:
				arr := []uint8{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Uint16:
				arr := []uint16{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Uint32:
				arr := []uint32{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Uint64:
				arr := []uint64{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Uint:
				arr := []uint{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Int8:
				arr := []int8{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Int16:
				arr := []int16{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Int32:
				arr := []int32{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Int64:
				arr := []int64{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.Int:
				arr := []int{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
			case reflect.String:
				arr := []string{}
				err = json.Unmarshal(im, &arr)
				if err != nil {
					panic(fmt.Errorf("failed to unmarshal slice or array in ProcessedPayload: %v", err))
				}
				slices.Sort(arr)
				(*p)[k] = arr
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
// Navigation descends through nested ProcessedPayload values and slices.
// Returns the value at the end of the path, or an error if:
//   - a path component has an unsupported type,
//   - an intermediate value is not an object when a string key is used,
//   - an intermediate value is not an array when an integer index or nil is used,
//   - a key is not present in the current object, or
//   - an index is out of range.
func (p *ProcessedPayload) GetClaimValue(pathPointer []any) (any, error) {
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
			case ProcessedPayload:
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
