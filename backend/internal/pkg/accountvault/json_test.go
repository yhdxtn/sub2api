package accountvault

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestInputJSONRejectsAmbiguousFieldsAndWrongTypes(t *testing.T) {
	values := map[string]string{
		"email": `"demo@example.test"`, "password": `"password"`, "secret": `"` + publicSeed + `"`,
		"issuer": `"Example"`, "algorithm": `"SHA1"`, "digits": `6`, "period": `30`,
	}
	for field, value := range values {
		for _, data := range []string{
			fmt.Sprintf(`{%q:%s,%q:%s}`, field, value, field, value),
			fmt.Sprintf(`{%q:%s}`, strings.ToUpper(field), value),
			fmt.Sprintf(`{%q:null}`, field),
			fmt.Sprintf(`{%q:{}}`, field),
			fmt.Sprintf(`{%q:[]}`, field),
			fmt.Sprintf(`{%q:true}`, field),
		} {
			before := sampleInput()
			input := before
			if err := json.Unmarshal([]byte(data), &input); err == nil || input != before {
				t.Fatalf("invalid %s JSON should fail without partially changing the receiver", field)
			}
		}
	}
	for _, data := range []string{
		`{"email":"demo@example.test","\u0065mail":"other@example.test"}`,
		`{"email":"demo@example.test","Email":"other@example.test"}`,
		`{"password":123}`, `{"digits":"6"}`, `{"digits":6.5}`, `{"period":"30"}`,
		`{"period":99999999999999999999999999999999999999}`,
		`{"unknown":"PUBLIC-ERROR-FIXTURE"}`, `null`, `[]`, `"input"`, `{}` + `{}`,
	} {
		var input Input
		if err := json.Unmarshal([]byte(data), &input); err == nil {
			t.Fatal("ambiguous JSON or an incorrect field type was accepted")
		} else if strings.Contains(err.Error(), "PUBLIC-ERROR-FIXTURE") {
			t.Fatal("an invalid JSON field value escaped into an error")
		}
	}
}

func TestInputJSONPreservesValuesAndDefersSemanticValidation(t *testing.T) {
	want := Input{Email: " USER@EXAMPLE.TEST ", Password: "  password ---- part  ", Secret: strings.ToLower(publicSeed), Issuer: " Example ", Algorithm: "sha256", Digits: 8, Period: 60}
	encoded, _ := json.Marshal(want)
	var input Input
	if err := json.Unmarshal(encoded, &input); err != nil || input != want {
		t.Fatal("JSON decoding must preserve values before explicit normalization")
	}
	if err := json.Unmarshal([]byte(`{}`), &input); err != nil || input != (Input{}) {
		t.Fatal("omitted JSON fields should remain optional and start with zero values")
	}
	// HTTP items decode as one request, but invalid email/OTP values must be
	// reported by the service as individual record errors after decoding.
	request := `{"items":[{"email":"not-an-email","secret":"` + publicSeed + `"},{"email":"valid@example.test","secret":"` + publicSeed + `"}]}`
	var batch struct {
		Items []Input `json:"items"`
	}
	if err := json.Unmarshal([]byte(request), &batch); err != nil || len(batch.Items) != 2 {
		t.Fatal("one semantic email error must not reject an entire JSON request")
	}
	if _, err := Normalize(batch.Items[0]); err == nil {
		t.Fatal("the invalid email must still fail per-record normalization")
	}
	if _, err := Normalize(batch.Items[1]); err != nil {
		t.Fatal("the following valid item must remain importable")
	}
	for _, data := range []string{
		`{"email":"valid@example.test","secret":"AB"}`,
		`{"email":"valid@example.test","secret":"` + publicSeed + `","algorithm":"unsupported"}`,
		`{"email":"valid@example.test","secret":"` + publicSeed + `","digits":7}`,
		`{"email":"valid@example.test","secret":"` + publicSeed + `","period":301}`,
	} {
		if err := json.Unmarshal([]byte(data), &input); err != nil {
			t.Fatal("well-typed semantic errors belong to per-record normalization")
		}
		if _, err := Normalize(input); err == nil {
			t.Fatal("strict semantic validation must still reject invalid OTP settings")
		}
	}
}
