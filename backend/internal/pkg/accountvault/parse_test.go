package accountvault

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseURIParametersAndEmailFreePreview(t *testing.T) {
	uri := "otpauth://totp/Google%3AUSER%40EXAMPLE.TEST?secret=" + strings.ToLower(publicSeed) + "&issuer=Google&algorithm=SHA256&digits=8&period=60"
	input, err := ParseURI(uri)
	if err != nil || input.Email != "user@example.test" || input.Secret != publicSeed || input.Issuer != "Google" || input.Algorithm != "SHA256" || input.Digits != 8 || input.Period != 60 {
		t.Fatal("URI parameters did not survive parsing")
	}
	preview, err := ParseURI("otpauth://totp/GitHub%3Aoctocat?secret=" + publicSeed + "&issuer=GitHub")
	if err != nil || preview.Email != "" || preview.Issuer != "GitHub" {
		t.Fatal("a username QR must produce an email-free preview")
	}
	if _, err := Normalize(preview); err == nil {
		t.Fatal("an email-free preview must not be importable")
	}
	if code, err := GenerateCode(preview, time.Unix(59, 0)); err != nil || code.Code != "287082" {
		t.Fatal("an email-free QR preview must still show a correct TOTP")
	}
	preview.Email = "owner@example.test"
	if _, err := Normalize(preview); err != nil {
		t.Fatal("an administrator must be able to supply the missing email")
	}
	if input, err := ParseURI("OTPAUTH://TOTP/demo%40example.test?secret=" + publicSeed); err != nil || input.Email != "demo@example.test" {
		t.Fatal("URI scheme and authority must be case insensitive")
	}
}

func TestRejectsMalformedAndAmbiguousURIs(t *testing.T) {
	base := "otpauth://totp/Example%3Ademo%40example.test?secret=" + publicSeed
	bad := []string{
		"", "https://example.test/?secret=" + publicSeed,
		"otpauth://hotp/demo%40example.test?secret=" + publicSeed + "&counter=1",
		"otpauth-migration://offline?data=test",
		"otpauth://user@totp/demo%40example.test?secret=" + publicSeed,
		"otpauth://totp:443/demo%40example.test?secret=" + publicSeed,
		"otpauth://totp/a/b?secret=" + publicSeed,
		"otpauth://totp/%FF?secret=" + publicSeed,
		"otpauth://totp/%ZZ?secret=" + publicSeed,
		"otpauth://totp/%3Ademo%40example.test?secret=" + publicSeed,
		"otpauth://totp/%20?secret=" + publicSeed,
		"otpauth://totp/Example%3A?secret=" + publicSeed,
		base + "#", base + "#fragment", " " + base, base + "\n",
		base + "&secret=" + publicSeed, base + "&issuer=Wrong",
		base + "&issuer=Example&issuer=Example", base + "&issuer=%00",
		base + "&digits=0", base + "&digits=06", base + "&digits=7", base + "&digits=8&digits=8",
		base + "&period=0", base + "&period=301", base + "&period=1e2", base + "&period=+30",
		base + "&algorithm=", base + "&algorithm=SHA-1", base + "&algorithm=SHA1&algorithm=SHA1",
		base + "&image=one&image=two",
		strings.Replace(base, publicSeed, "AB", 1), base + ";invalid=value",
		strings.Repeat("x", MaxURIBytes+1),
	}
	for index, uri := range bad {
		if _, err := ParseURI(uri); err == nil {
			t.Errorf("malformed URI case %d was accepted", index)
		}
	}
	// URI extensions are retained nowhere and never fetched.
	if _, err := ParseURI(base + "&image=http%3A%2F%2F127.0.0.1%2Fprivate"); err != nil {
		t.Fatal("an unused URI extension should not trigger a fetch or fail valid TOTP parsing")
	}
}

func TestMixedBatchHasAccurateLinesAndDoesNotImportOAuthTokens(t *testing.T) {
	const discarded = "PUBLIC-OAUTH-FIXTURE-DO-NOT-RETURN"
	inputJSON, _ := json.Marshal(Input{Email: "JSON@EXAMPLE.TEST", Password: "  JSON ---- password  ", Secret: publicSeed, Issuer: "JSON", Algorithm: "SHA512", Digits: 8, Period: 60})
	content := "\ufeff卡密 1: FIRST@EXAMPLE.TEST---- first ---- password ----" + publicSeed + "\r\n" +
		`{"platform":"openai","credentials":{"access_token":"` + discarded + `","refresh_token":"` + discarded + `"},"name":"OAuth companion"}` + "\r\n\r\n" +
		"invalid-public-row-with-password\r\n" + string(inputJSON) + "\r\n" +
		"bad@example.test----PRIVATE-ERROR-FIXTURE----AB\r\n"
	result, err := ParseContent(content)
	if err != nil || len(result.Rows) != 4 || result.Ignored != 1 {
		t.Fatalf("mixed batch result mismatch: %v", err)
	}
	for index, line := range []int{1, 4, 5, 6} {
		if result.Rows[index].Line != line {
			t.Fatal("line numbers do not match the source file")
		}
	}
	if result.Rows[0].Input == nil || result.Rows[0].Input.Password != " first ---- password " || result.Rows[0].Input.Email != "first@example.test" {
		t.Fatal("delimiter parsing did not preserve the password")
	}
	if result.Rows[2].Input == nil || result.Rows[2].Input.Password != "  JSON ---- password  " || result.Rows[2].Input.Period != 60 || result.Rows[2].Input.Algorithm != "SHA512" {
		t.Fatal("JSON non-default parameters or password were lost")
	}
	for _, index := range []int{1, 3} {
		row := result.Rows[index]
		if row.Input != nil || row.Error == "" || strings.Contains(row.Error, "PRIVATE-ERROR-FIXTURE") || strings.Contains(row.Error, "invalid-public-row-with-password") || strings.Contains(row.Error, publicSeed) {
			t.Fatal("a bad line leaked its original content or produced an input")
		}
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), discarded) || strings.Contains(string(encoded), "access_token") || strings.Contains(string(encoded), "refresh_token") {
		t.Fatal("OAuth companion credentials escaped into the parse result")
	}
}

func TestDelimiterPasswordsAndOptionalEmptyPassword(t *testing.T) {
	for _, password := range []string{"", " ", "----", "part----middle----tail", "  ---- edge ----  ", "two--"} {
		result, err := ParseContent("卡密2： demo@example.test----" + password + "----" + publicSeed)
		if err != nil || len(result.Rows) != 1 || result.Rows[0].Input == nil || result.Rows[0].Input.Password != password {
			t.Fatal("first/last delimiter extraction changed a password")
		}
	}
}

func TestOverlappingDelimiterFragmentsProduceLineErrors(t *testing.T) {
	// Runs shorter than two complete delimiters must never create a reversed
	// password slice or abort the remaining rows in the administrator's batch.
	for hyphens := 4; hyphens < 8; hyphens++ {
		content := "broken@example.test" + strings.Repeat("-", hyphens) + publicSeed + "\n" +
			"valid@example.test----password----" + publicSeed
		result, err := ParseContent(content)
		if err != nil || len(result.Rows) != 2 || result.Rows[0].Input != nil || result.Rows[0].Error == "" || result.Rows[1].Input == nil {
			t.Fatal("an overlapping delimiter must remain an isolated line error")
		}
	}
}

func TestJSONLinesRejectUnknownFieldsDuplicatesAndWrongTypes(t *testing.T) {
	for _, line := range []string{
		`{"email":"demo@example.test","secret":"` + publicSeed + `","email":"other@example.test"}`,
		`{"email":"demo@example.test","secret":"` + publicSeed + `","access_token":"ignored?"}`,
		`{"Email":"demo@example.test","secret":"` + publicSeed + `"}`,
		`{"email":"demo@example.test","secret":"` + publicSeed + `","digits":"6"}`,
		`{"email":"demo@example.test","secret":"` + publicSeed + `","period":null}`,
		`{"email":"demo@example.test","secret":"` + publicSeed + `"} {}`,
		`{"platform":"openai","credentials":[],"name":"wrong shape"}`,
		`{"email":`, `[]`, `null`,
	} {
		result, err := ParseContent(line)
		if err != nil || len(result.Rows) != 1 || result.Rows[0].Error == "" || result.Rows[0].Input != nil {
			t.Fatal("invalid JSON line was accepted or disrupted the batch")
		}
	}
}

func TestBatchSizeAndRowLimits(t *testing.T) {
	var content strings.Builder
	for index := 0; index < MaxRows; index++ {
		fmt.Fprintf(&content, "user%d@example.test----p----%s\n", index, publicSeed)
		content.WriteString(`{"platform":"openai","credentials":{},"name":"companion"}` + "\n")
	}
	result, err := ParseContent(content.String())
	if err != nil || len(result.Rows) != MaxRows || result.Ignored != MaxRows {
		t.Fatal("OAuth companion and blank lines must not use account row slots")
	}
	if result, err := ParseContent(content.String() + "last@example.test----p----" + publicSeed); err == nil || len(result.Rows) != 0 {
		t.Fatal("a limit error must not return an importable partial batch")
	}
	if result, err := ParseContent(strings.Repeat("x", MaxContentBytes)); err != nil || len(result.Rows) != 1 || result.Rows[0].Error == "" {
		t.Fatal("a long invalid line within the size limit must receive one line error")
	}
	if result, err := ParseContent(strings.Repeat("x", MaxContentBytes+1)); err == nil || len(result.Rows) != 0 {
		t.Fatal("oversized text must fail before returning rows")
	}
	if _, err := ParseContent(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("non-UTF-8 text was accepted")
	}
	if result, err := ParseContent("\ufeff\r\n \r\n"); err != nil || len(result.Rows) != 0 || result.Ignored != 0 {
		t.Fatal("an empty text file should produce an empty result")
	}
}
