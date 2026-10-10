package accountvault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var cardPrefix = regexp.MustCompile(`^\s*卡密\s*[0-9]+\s*[:：]\s*`)
var positiveInteger = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)

// ParseURI accepts only a TOTP provisioning URI. It never fetches its content
// or any extension parameter such as image, URL, or callback.
func ParseURI(value string) (Input, error) {
	bad := errors.New("二维码内容不是有效的 otpauth://totp/ 地址。")
	if len(value) == 0 || len(value) > MaxURIBytes || unsafeText(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.Contains(value, "#") {
		return Input{}, bad
	}
	u, err := url.Parse(value)
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") || !strings.EqualFold(u.Host, "totp") || u.User != nil || u.Opaque != "" {
		return Input{}, bad
	}
	path := u.EscapedPath()
	if len(path) < 2 || path[0] != '/' || strings.Contains(path[1:], "/") {
		return Input{}, bad
	}
	label, err := url.PathUnescape(path[1:])
	if err != nil || unsafeText(label) {
		return Input{}, bad
	}
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Input{}, bad
	}
	for _, values := range params {
		if len(values) > 1 {
			return Input{}, errors.New("二维码包含重复的 TOTP 参数。")
		}
	}
	input := Input{Email: label, Secret: params.Get("secret")}
	labelIssuer, hasIssuer := "", false
	if before, after, ok := strings.Cut(label, ":"); ok {
		labelIssuer, err = normalizeIssuer(before)
		if err != nil || labelIssuer == "" {
			return Input{}, bad
		}
		hasIssuer = true
		input.Email = strings.TrimSpace(after)
		input.Issuer = labelIssuer
	}
	if strings.TrimSpace(input.Email) == "" {
		return Input{}, bad
	}
	if params.Has("issuer") {
		issuer, issuerErr := normalizeIssuer(params.Get("issuer"))
		if issuerErr != nil {
			return Input{}, issuerErr
		}
		if hasIssuer && labelIssuer != issuer {
			return Input{}, errors.New("二维码标签与 issuer 参数的平台不一致。")
		}
		input.Issuer = issuer
	}
	if params.Has("algorithm") {
		input.Algorithm = params.Get("algorithm")
		if input.Algorithm == "" {
			return Input{}, errors.New("TOTP 算法参数不能为空。")
		}
	}
	for name, target := range map[string]*int{"digits": &input.Digits, "period": &input.Period} {
		if params.Has(name) {
			if !positiveInteger.MatchString(params.Get(name)) {
				return Input{}, errors.New("验证码位数或周期参数格式不正确。")
			}
			*target, _ = strconv.Atoi(params.Get(name))
		}
	}
	// A provider can put a username rather than an email in the QR label.
	// Preserve valid emails; otherwise leave it blank for the preview editor.
	if email, emailErr := normalizeEmail(input.Email); emailErr == nil {
		input.Email = email
	} else {
		input.Email = ""
	}
	return normalizeInput(input, false)
}

// jsonObject rejects duplicate fields and trailing values instead of accepting
// a last-write-wins interpretation of credentials. Errors never echo tokens.
func jsonObject(line string) (map[string]json.RawMessage, error) {
	bad := errors.New("JSON 行格式不正确，必须是一个字段不重复的对象。")
	decoder := json.NewDecoder(strings.NewReader(line))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, bad
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, tokenErr := decoder.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok {
			return nil, bad
		}
		if _, exists := fields[key]; exists {
			return nil, bad
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, bad
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, bad
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, bad
	}
	return fields, nil
}

func oauthCompanion(fields map[string]json.RawMessage) bool {
	var platform, name string
	if json.Unmarshal(fields["platform"], &platform) != nil || strings.TrimSpace(platform) == "" || json.Unmarshal(fields["name"], &name) != nil {
		return false
	}
	credentials := bytes.TrimSpace(fields["credentials"])
	return len(credentials) > 1 && credentials[0] == '{' && credentials[len(credentials)-1] == '}'
}

func parseLine(line string) (*Input, bool, error) {
	line = cardPrefix.ReplaceAllString(line, "")
	trimmed := strings.TrimSpace(line)
	var input Input
	if strings.HasPrefix(trimmed, "{") {
		fields, err := jsonObject(trimmed)
		if err != nil {
			return nil, false, err
		}
		defer func() {
			for _, value := range fields {
				clear(value)
			}
		}()
		if oauthCompanion(fields) {
			return nil, true, nil
		}
		if err := json.Unmarshal([]byte(trimmed), &input); err != nil {
			return nil, false, err
		}
	} else {
		first, last := strings.Index(line, "----"), strings.LastIndex(line, "----")
		if first < 1 || last < first+4 {
			return nil, false, errors.New("该行应为邮箱----密码----Secret，或标准账号 JSON。")
		}
		input = Input{
			Email:    strings.TrimSpace(line[:first]),
			Password: line[first+4 : last],
			Secret:   strings.TrimSpace(line[last+4:]),
		}
		// Preserve the existing delimiter-containing password format. When the
		// last field is not a seed, accept an optional note after a valid seed.
		if _, err := normalizeSecret(input.Secret); err != nil {
			previous := strings.LastIndex(line[:last], "----")
			if previous >= first+4 {
				if secret, seedErr := normalizeSecret(strings.TrimSpace(line[previous+4 : last])); seedErr == nil {
					input.Password, input.Secret, input.Note = line[first+4:previous], secret, line[last+4:]
				}
			}
		}
	}
	normalized, err := Normalize(input)
	if err != nil {
		return nil, false, err
	}
	return &normalized, false, nil
}

// ParseContent isolates individual line errors. OAuth companion objects are
// counted and discarded; their access/refresh tokens never become account rows.
// Limit failures return no partial rows, preventing accidental partial imports.
func ParseContent(content string) (ParseResult, error) {
	if len(content) > MaxContentBytes {
		return ParseResult{}, errors.New("导入文本不能超过 2 MiB。")
	}
	if !utf8.ValidString(content) {
		return ParseResult{}, errors.New("导入文本必须使用 UTF-8 编码。")
	}
	content = strings.TrimPrefix(content, "\ufeff")
	result := ParseResult{Rows: make([]ParsedRow, 0)}
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 4096), MaxContentBytes+1)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		input, ignored, err := parseLine(line)
		if ignored {
			result.Ignored++
			continue
		}
		if len(result.Rows) >= MaxRows {
			return ParseResult{}, errors.New("一次最多导入 500 条账号记录。")
		}
		row := ParsedRow{Line: lineNumber, Input: input}
		if err != nil {
			row.Error = err.Error()
		}
		result.Rows = append(result.Rows, row)
	}
	if scanner.Err() != nil {
		return ParseResult{}, errors.New("导入文本行读取失败。")
	}
	return result, nil
}
