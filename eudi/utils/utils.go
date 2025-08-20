package utils

import (
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExtractOptionalWith[T any](claims map[string]any, key string, valueParser func(any) (T, error)) (T, error) {
	value, ok := claims[key]
	if !ok {
		var default_ T
		return default_, nil
	}
	return valueParser(value)
}

func GetMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func GetOptional[T any](token jwt.Token, key string) T {
	var value T
	err := token.Get(key, &value)
	if err != nil {
		return *new(T)
	}
	return value
}

func GetOptionalWithDefault[T any](token jwt.Token, key string, defaultValue T) (T, error) {
	var value T
	err := token.Get(key, &value)
	if err != nil {
		switch err {
		case jwt.ClaimNotFoundError():
			return defaultValue, nil
		default:
			return *new(T), err
		}
	}
	return value, nil
}
