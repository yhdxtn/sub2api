package accountvault

import (
	"strings"
	"testing"
)

// This is the public ASCII "12345678901234567890" seed from RFC 6238.
const publicSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func sampleInput() Input {
	return Input{Email: "demo@example.test", Password: " example password----with delimiters ", Secret: publicSeed, Issuer: "Example"}
}

func TestNormalizePreservesPasswordAndCanonicalizesFields(t *testing.T) {
	input := sampleInput()
	input.Email, input.Secret, input.Issuer = "  DEMO@EXAMPLE.TEST ", strings.ToLower(publicSeed), " Example "
	got, err := Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "demo@example.test" || got.Secret != publicSeed || got.Issuer != "Example" || got.Password != input.Password || got.Algorithm != "SHA1" || got.Digits != 6 || got.Period != 30 {
		t.Fatal("normalization changed a credential or omitted TOTP defaults")
	}
	if input.Email != "  DEMO@EXAMPLE.TEST " {
		t.Fatal("normalization mutated the input")
	}
}

func TestCanonicalBase32(t *testing.T) {
	for _, pair := range [][2]string{{"MY======", "MY"}, {"mzxq====", "MZXQ"}, {"MZXW6===", "MZXW6"}, {"MZXW6YQ=", "MZXW6YQ"}, {"MZXW6YTB", "MZXW6YTB"}, {publicSeed, publicSeed}} {
		input := sampleInput()
		input.Secret = pair[0]
		got, err := Normalize(input)
		if err != nil || got.Secret != pair[1] {
			t.Fatalf("valid canonical Base32 case was rejected: %v", err)
		}
	}
	for _, value := range []string{"", "A", "ABC", "AAAAAA", "AB", "MZ======", "MZXW7===", "MY=", "MY=======", "MY======\n", " MY======", "M Y", "M0", "M1", "M8", "=MY=====", "M=Y", strings.Repeat("A", 1025)} {
		input := sampleInput()
		input.Secret = value
		if _, err := Normalize(input); err == nil {
			t.Fatal("noncanonical or malformed Base32 was accepted")
		}
	}
}

func TestStrictEmailAndTOTPParameters(t *testing.T) {
	for _, email := range []string{"", "octocat", "a@localhost", "a@@example.test", "Demo <a@example.test>", "a@example.test (comment)", "a..b@example.test", ".a@example.test", "a@-example.test", "a@example..test", "a@example.test.", "a@[127.0.0.1]", "a@ex ample.test", "a\x00@example.test", strings.Repeat("a", 65) + "@example.test"} {
		input := sampleInput()
		input.Email = email
		if _, err := Normalize(input); err == nil {
			t.Fatal("invalid or ambiguous email address was accepted")
		}
	}
	for _, algorithm := range []string{"SHA-1", "MD5", "sha3", " SHA1", "SHA256\n"} {
		input := sampleInput()
		input.Algorithm = algorithm
		if _, err := Normalize(input); err == nil {
			t.Fatal("invalid TOTP algorithm was accepted")
		}
	}
	for _, digits := range []int{-1, 5, 7, 9} {
		input := sampleInput()
		input.Digits = digits
		if _, err := Normalize(input); err == nil {
			t.Fatal("invalid TOTP digits were accepted")
		}
	}
	for _, period := range []int{-1, 301} {
		input := sampleInput()
		input.Period = period
		if _, err := Normalize(input); err == nil {
			t.Fatal("invalid TOTP period was accepted")
		}
	}
	input := sampleInput()
	input.Algorithm, input.Digits, input.Period = "sHa512", 8, 300
	got, err := Normalize(input)
	if err != nil || got.Algorithm != "SHA512" || got.Digits != 8 || got.Period != 300 {
		t.Fatal("valid non-default TOTP parameters were lost")
	}
}

func TestCredentialAndIssuerBoundaries(t *testing.T) {
	input := sampleInput()
	input.Password = strings.Repeat(" ", MaxPasswordBytes)
	if got, err := Normalize(input); err != nil || got.Password != input.Password {
		t.Fatal("a valid whitespace password was altered")
	}
	input.Password += "x"
	if _, err := Normalize(input); err == nil {
		t.Fatal("oversized password was accepted")
	}
	input = sampleInput()
	input.Password = ""
	if _, err := Normalize(input); err != nil {
		t.Fatal("optional empty password was rejected")
	}
	for _, issuer := range []string{"A:B", "A\x00B", "A\u202eB", strings.Repeat("a", 257)} {
		input.Issuer = issuer
		if _, err := Normalize(input); err == nil {
			t.Fatal("unsafe issuer was accepted")
		}
	}
}
