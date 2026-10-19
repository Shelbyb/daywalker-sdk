// Validate an incoming API token with Daywalker Auth, with an RFC 9421 signed request. Stdlib only.
// Env: DAYWALKER_API_KEY, DAYWALKER_SIGNING_KEY (base64 PKCS#8 Ed25519), DAYWALKER_KEY_ID,
// optional DAYWALKER_URL (default https://auth.daywalker.dev).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const path = "/api/v1/tokens/validate"

type Result struct {
	Valid     bool   `json:"valid"`
	Error     string `json:"error"`
	Message   string `json:"message"`
	UserID    string `json:"userId"`
	RateLimit struct {
		Remaining int `json:"remaining"`
	} `json:"rateLimit"`
}

func validateToken(token string) (*Result, error) {
	base := os.Getenv("DAYWALKER_URL")
	if base == "" {
		base = "https://auth.daywalker.dev"
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"token": token})
	sum := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	nonce := make([]byte, 12)
	rand.Read(nonce)
	params := fmt.Sprintf(`("@method" "@path" "@authority" "content-digest");created=%d;keyid="%s";alg="ed25519";nonce="%s"`,
		time.Now().Unix(), os.Getenv("DAYWALKER_KEY_ID"), hex.EncodeToString(nonce))
	sigBase := strings.Join([]string{
		`"@method": POST`, `"@path": ` + path, `"@authority": ` + u.Host,
		`"content-digest": ` + digest, `"@signature-params": ` + params,
	}, "\n")

	der, err := base64.StdEncoding.DecodeString(os.Getenv("DAYWALKER_SIGNING_KEY"))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(parsed.(ed25519.PrivateKey), []byte(sigBase))

	req, _ := http.NewRequest("POST", base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("DAYWALKER_API_KEY"))
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", "sig1="+params)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var out Result // 4xx/5xx still carry a JSON error body
	return &out, json.NewDecoder(res.Body).Decode(&out)
}

func main() {
	r, err := validateToken(os.Args[1])
	if err != nil {
		fmt.Println("request failed:", err)
		os.Exit(1)
	}
	if r.Valid {
		fmt.Printf("Authorized user: %s quota: %d\n", r.UserID, r.RateLimit.Remaining)
	} else {
		fmt.Printf("Rejected [%s]: %s\n", r.Error, r.Message)
	}
}
