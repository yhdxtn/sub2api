package accountvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// UnmarshalJSON enforces the same exact JSON field contract for HTTP items,
// text import rows, and encrypted payloads. Semantic validation deliberately
// remains in Normalize so one invalid email can receive its own batch result.
func (input *Input) UnmarshalJSON(data []byte) error {
	if input == nil || !utf8.Valid(data) {
		return errors.New("JSON 账号数据必须是有效的 UTF-8 对象。")
	}
	fields, err := jsonObject(string(data))
	if err != nil {
		return err
	}
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	for key, value := range fields {
		switch key {
		case "email", "password", "secret", "issuer", "algorithm", "digits", "period", "note":
		default:
			return errors.New("JSON 行含有不支持的账号字段。")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("JSON 账号字段不能为 null。")
		}
	}
	// A distinct type prevents recursively calling this method. Assign only
	// after successful decoding so a bad field never leaves a partial record.
	type plainInput Input
	var decoded plainInput
	if json.Unmarshal(data, &decoded) != nil {
		return errors.New("JSON 账号字段的类型不正确。")
	}
	*input = Input(decoded)
	return nil
}
