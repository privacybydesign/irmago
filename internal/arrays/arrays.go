package arrays

func ConvertTo[T any](arr []any, convert func(any) (T, bool)) []T {
	if arr == nil {
		return nil
	}

	strArr := make([]T, len(arr))
	for i, v := range arr {
		str, ok := convert(v)
		if !ok {
			return nil
		}
		strArr[i] = str
	}
	return strArr
}
