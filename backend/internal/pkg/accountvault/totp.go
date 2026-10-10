package accountvault

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"
)

// GenerateCode implements RFC 6238 with a 64-bit counter. Times in the response
// are Unix milliseconds, independent of the process or browser time zone.
func GenerateCode(input Input, at time.Time) (Code, error) {
	input, err := normalizeInput(input, false)
	if err != nil {
		return Code{}, err
	}
	seconds, fraction := at.Unix(), int64(at.Nanosecond()/1_000_000)
	if seconds < 0 || seconds > (math.MaxInt64-fraction)/1000 {
		return Code{}, errors.New("验证码时间超出支持范围。")
	}
	step := seconds / int64(input.Period)
	expiresSeconds := (step + 1) * int64(input.Period)
	if expiresSeconds > math.MaxInt64/1000 {
		return Code{}, errors.New("验证码时间超出支持范围。")
	}
	serverTime, expiresAt := seconds*1000+fraction, expiresSeconds*1000
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(input.Secret)
	if err != nil {
		clear(key)
		return Code{}, errors.New("Secret 编码不正确。")
	}
	defer clear(key)
	var algorithm func() hash.Hash
	switch input.Algorithm {
	case "SHA256":
		algorithm = sha256.New
	case "SHA512":
		algorithm = sha512.New
	default:
		algorithm = sha1.New
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(algorithm, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1_000_000)
	if input.Digits == 8 {
		modulus = 100_000_000
	}
	return Code{
		Code:       fmt.Sprintf("%0*d", input.Digits, value%modulus),
		Remaining:  int((expiresAt - serverTime + 999) / 1000),
		Period:     input.Period,
		ExpiresAt:  expiresAt,
		ServerTime: serverTime,
	}, nil
}
