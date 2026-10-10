// Package accountvault parses administrator-owned account records and protects
// their credentials. It performs no network requests or persistence itself.
package accountvault

import (
	"encoding/base32"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxContentBytes  = 2 * 1024 * 1024
	MaxRows          = 500
	MaxPasswordBytes = 1024
	MaxSecretBytes   = 1024
	MaxURIBytes      = 8192
)

type Input struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Note      string `json:"note,omitempty"`
}

type ParsedRow struct {
	Line  int    `json:"line"`
	Input *Input `json:"input,omitempty"`
	Error string `json:"error,omitempty"`
}

type ParseResult struct {
	Rows    []ParsedRow `json:"rows"`
	Ignored int         `json:"ignored"`
}

type Code struct {
	Code       string `json:"code"`
	Remaining  int    `json:"remaining"`
	Period     int    `json:"period"`
	ExpiresAt  int64  `json:"expires_at"`
	ServerTime int64  `json:"server_time"`
}

var base32Pattern = regexp.MustCompile(`^[A-Za-z2-7]+={0,6}$`)

func unsafeText(s string) bool {
	return !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
	}) >= 0
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	bad := errors.New("邮箱格式不正确，请填写完整邮箱地址。")
	if value == "" || len(value) > 320 || unsafeText(value) {
		return "", bad
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Name != "" || address.Address != value {
		return "", bad
	}
	local, domain, found := strings.Cut(value, "@")
	if !found || len(local) > 64 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", bad
	}
	// Reject display names, comments, literals and quoted mailbox spellings.
	// Bulk records contain a bare, unambiguous Internet email address.
	if strings.ContainsAny(local, " \t\r\n\"(),:;<>@[\\]") || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", bad
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", bad
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", bad
			}
		}
	}
	return value, nil
}

func normalizeSecret(value string) (string, error) {
	bad := errors.New("Secret 必须是有效且规范的 Base32 编码。")
	if len(value) == 0 || len(value) > MaxSecretBytes || !base32Pattern.MatchString(value) {
		return "", bad
	}
	upper := strings.ToUpper(value)
	unpadded := strings.TrimRight(upper, "=")
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := encoding.DecodeString(unpadded)
	if err != nil {
		clear(decoded)
		return "", bad
	}
	defer clear(decoded)
	// Go's decoder accepts some non-zero unused bits. Re-encoding enforces
	// canonical padding bits as required by RFC 4648 section 3.5.
	if len(decoded) == 0 || encoding.EncodeToString(decoded) != unpadded {
		return "", bad
	}
	if len(upper) != len(unpadded) && base32.StdEncoding.EncodeToString(decoded) != upper {
		return "", bad
	}
	return unpadded, nil
}

func normalizeIssuer(value string) (string, error) {
	if len(value) > 256 || unsafeText(value) || strings.Contains(value, ":") {
		return "", errors.New("平台名称格式不正确或超过长度限制。")
	}
	return strings.TrimSpace(value), nil
}

// Normalize returns a new value. Password whitespace and delimiter sequences
// are deliberately retained verbatim, including an empty optional password.
func Normalize(input Input) (Input, error) {
	return normalizeInput(input, true)
}

// URI previews may have no email until the administrator supplies one. Stored
// and imported records always use Normalize, which requires a real address.
func normalizeInput(input Input, requireEmail bool) (Input, error) {
	var err error
	if requireEmail || input.Email != "" {
		if input.Email, err = normalizeEmail(input.Email); err != nil {
			return Input{}, err
		}
	}
	if !utf8.ValidString(input.Password) || len(input.Password) > MaxPasswordBytes {
		return Input{}, errors.New("密码编码无效或超过 1024 字节。")
	}
	if input.Secret, err = normalizeSecret(input.Secret); err != nil {
		return Input{}, err
	}
	if len(input.Note) > 1024 || unsafeText(input.Note) || strings.Contains(input.Note, "----") {
		return Input{}, errors.New("备注必须为单行文本，不能包含分隔符，且最多 1024 字节。")
	}
	if input.Issuer, err = normalizeIssuer(input.Issuer); err != nil {
		return Input{}, err
	}
	input.Algorithm = strings.ToUpper(input.Algorithm)
	if input.Algorithm == "" {
		input.Algorithm = "SHA1"
	}
	if input.Algorithm != "SHA1" && input.Algorithm != "SHA256" && input.Algorithm != "SHA512" {
		return Input{}, errors.New("TOTP 算法仅支持 SHA1、SHA256 和 SHA512。")
	}
	if input.Digits == 0 {
		input.Digits = 6
	}
	if input.Digits != 6 && input.Digits != 8 {
		return Input{}, errors.New("验证码位数只能为 6 或 8。")
	}
	if input.Period == 0 {
		input.Period = 30
	}
	if input.Period < 1 || input.Period > 300 {
		return Input{}, errors.New("验证码周期必须为 1 到 300 秒。")
	}
	return input, nil
}
