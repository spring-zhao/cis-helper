package runtime

import "errors"

func ErrorCode(err error, fallback string) string {
	if err == nil {
		return ""
	}
	var target interface{ GetCode() string }
	if errors.As(err, &target) {
		return target.GetCode()
	}
	return fallback
}
