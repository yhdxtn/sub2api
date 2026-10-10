package accountvault

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestRFC6238All18Vectors(t *testing.T) {
	// Independent published expected values: RFC 6238 Appendix B.
	// https://www.rfc-editor.org/rfc/rfc6238#appendix-B
	vectors := []struct {
		seconds int64
		values  [3]string
	}{
		{59, [3]string{"94287082", "46119246", "90693936"}},
		{1111111109, [3]string{"07081804", "68084774", "25091201"}},
		{1111111111, [3]string{"14050471", "67062674", "99943326"}},
		{1234567890, [3]string{"89005924", "91819424", "93441116"}},
		{2000000000, [3]string{"69279037", "90698825", "38618901"}},
		{20000000000, [3]string{"65353130", "77737706", "47863826"}},
	}
	algorithms := []string{"SHA1", "SHA256", "SHA512"}
	seeds := []string{"12345678901234567890", "12345678901234567890123456789012", "1234567890123456789012345678901234567890123456789012345678901234"}
	for _, vector := range vectors {
		for index, algorithm := range algorithms {
			t.Run(fmt.Sprintf("%d/%s", vector.seconds, algorithm), func(t *testing.T) {
				input := sampleInput()
				input.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seeds[index]))
				input.Algorithm, input.Digits, input.Period = algorithm, 8, 30
				got, err := GenerateCode(input, time.Unix(vector.seconds, 0))
				if err != nil || got.Code != vector.values[index] {
					t.Fatalf("published RFC 6238 vector failed: %v", err)
				}
				if got.ServerTime != vector.seconds*1000 || got.ExpiresAt <= got.ServerTime || got.Remaining < 1 || got.Remaining > 30 {
					t.Fatal("invalid timing metadata")
				}
			})
		}
	}
}

func TestTOTPRolloverMillisecondsAndCustomPeriod(t *testing.T) {
	input := sampleInput()
	for _, row := range []struct {
		millis int64
		code   string
		left   int
		expiry int64
	}{{0, "755224", 30, 30000}, {29999, "755224", 1, 30000}, {30000, "287082", 30, 60000}, {59999, "287082", 1, 60000}, {60000, "359152", 30, 90000}} {
		got, err := GenerateCode(input, time.UnixMilli(row.millis))
		if err != nil || got.Code != row.code || got.Remaining != row.left || got.ServerTime != row.millis || got.ExpiresAt != row.expiry {
			t.Fatal("TOTP rollover or millisecond metadata is incorrect")
		}
	}
	input.Period, input.Digits = 60, 8
	got, err := GenerateCode(input, time.Unix(59, 0).In(time.FixedZone("fixture", 8*3600)))
	if err != nil || got.Code != "84755224" || got.Period != 60 || got.Remaining != 1 || got.ExpiresAt != 60000 {
		t.Fatal("custom period or time-zone independence failed")
	}
	encoded, _ := json.Marshal(got)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &fields)
	for _, key := range []string{"code", "remaining", "period", "expires_at", "server_time"} {
		if _, found := fields[key]; !found {
			t.Fatal("code JSON does not match the API contract")
		}
	}
}

func TestTOTPTimeBounds(t *testing.T) {
	for _, at := range []time.Time{time.Time{}, time.Unix(-1, 0), time.Unix(math.MaxInt64/1000, 0), time.Unix(math.MaxInt64, 0)} {
		if _, err := GenerateCode(sampleInput(), at); err == nil {
			t.Fatal("unsupported time was accepted")
		}
	}
}
