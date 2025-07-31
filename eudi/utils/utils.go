package utils

import "fmt"

func ToAnyMap(object any) (values map[string]any, err error) {
	values, ok := object.(map[string]any)
	if !ok {
		return values, fmt.Errorf("not a map[string]any: %v", object)
	}
	return values, nil
}

func ToAnyArray(object any) (values []any, err error) {
	values, ok := object.([]any)
	if !ok {
		return []any{}, fmt.Errorf("not a []any: %v", object)
	}
	return values, nil
}

func ExtractRequired[T any](claims map[string]any, key string) (T, error) {
	value, ok := claims[key].(T)
	if !ok {
		return value, fmt.Errorf("'%s' is required but was not set", key)
	}
	return value, nil
}

func ExtractOptionalWith[T any](claims map[string]any, key string, valueParser func(any) (T, error)) (T, error) {
	value, ok := claims[key]
	if !ok {
		var default_ T
		return default_, nil
	}
	return valueParser(value)
}

func ExtractOptional[T any](claims map[string]any, key string) T {
	value, _ := claims[key].(T)
	return value
}

func GetMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
