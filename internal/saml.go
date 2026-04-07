package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// samlHTTPClient is a shared client with a conservative timeout for metadata fetches.
var samlHTTPClient = &http.Client{Timeout: 15 * time.Second}

// SAMLScanResult holds the outcome of fetching and parsing SAML metadata.
type SAMLScanResult struct {
	// Certs contains all certificates found in the metadata with their declared use.
	// Empty when the scan failed or the metadata contained no certificates.
	Certs []SAMLCertPayload
	// Err holds a human-readable error string if the scan failed.
	Err *string
}

// ---------------------------------------------------------------------------
// Minimal SAML metadata XML structures for certificate extraction.
// Namespace prefixes vary across IdPs so we match on local names only.
// ---------------------------------------------------------------------------

type xmlEntityDescriptor struct {
	XMLName      xml.Name        `xml:"EntityDescriptor"`
	RoleDescriptors []xmlRoleDescriptor `xml:",any"`
}

type xmlRoleDescriptor struct {
	KeyDescriptors []xmlKeyDescriptor `xml:"KeyDescriptor"`
}

type xmlKeyDescriptor struct {
	Use     string      `xml:"use,attr"`
	KeyInfo xmlKeyInfo  `xml:"KeyInfo"`
}

type xmlKeyInfo struct {
	X509Data []xmlX509Data `xml:"X509Data"`
}

type xmlX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

// ScanSAML fetches the SAML metadata at endpoint.URL, extracts signing and
// encryption certificates, and returns them with their declared use labels.
func ScanSAML(endpoint ScannerSAMLEndpoint) SAMLScanResult {
	resp, err := samlHTTPClient.Get(endpoint.URL) //nolint:noctx // best-effort, timeout set on client
	if err != nil {
		msg := fmt.Sprintf("failed to fetch SAML metadata: %s", err.Error())
		return SAMLScanResult{Err: &msg}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("SAML metadata returned HTTP %d", resp.StatusCode)
		return SAMLScanResult{Err: &msg}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
	if err != nil {
		msg := fmt.Sprintf("failed to read SAML metadata body: %s", err.Error())
		return SAMLScanResult{Err: &msg}
	}

	certs, err := extractSAMLCerts(body)
	if err != nil {
		msg := err.Error()
		return SAMLScanResult{Err: &msg}
	}
	if len(certs) == 0 {
		msg := "no certificates found in SAML metadata"
		return SAMLScanResult{Err: &msg}
	}

	return SAMLScanResult{Certs: certs}
}

// extractSAMLCerts parses raw SAML metadata XML and returns all certificates
// with their declared use labels (signing or encryption).
//
// KeyDescriptors with use="signing" are returned as-is. Those with
// use="encryption" are returned as-is. Those with no use attribute
// (unspecified / dual-use) are emitted twice — once as "signing" and once as
// "encryption" — so the server can track both roles correctly.
func extractSAMLCerts(data []byte) ([]SAMLCertPayload, error) {
	var entity xmlEntityDescriptor
	if err := xml.Unmarshal(data, &entity); err != nil {
		return nil, fmt.Errorf("failed to parse SAML metadata XML: %w", err)
	}

	// Use a fingerprint+use set to deduplicate across role descriptors.
	type certKey struct{ fp, use string }
	seen := make(map[certKey]bool)
	var results []SAMLCertPayload

	addCert := func(pemStr, use string) {
		key := certKey{pemFingerprint(pemStr), use}
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, SAMLCertPayload{PEM: pemStr, Use: use})
	}

	for _, role := range entity.RoleDescriptors {
		for _, kd := range role.KeyDescriptors {
			use := strings.ToLower(strings.TrimSpace(kd.Use))
			for _, x509data := range kd.KeyInfo.X509Data {
				raw := strings.TrimSpace(x509data.X509Certificate)
				if raw == "" {
					continue
				}
				pemStr, err := derBase64ToPEM(raw)
				if err != nil {
					continue // skip malformed certs
				}
				switch use {
				case "signing":
					addCert(pemStr, "signing")
				case "encryption":
					addCert(pemStr, "encryption")
				case "", "unspecified":
					// Dual-use cert — register for both roles.
					addCert(pemStr, "signing")
					addCert(pemStr, "encryption")
				}
			}
		}
	}

	return results, nil
}

// derBase64ToPEM converts a raw base64-encoded DER certificate (as found in
// SAML metadata) to a PEM-encoded string.
func derBase64ToPEM(b64 string) (string, error) {
	// SAML metadata may include whitespace inside the base64 block — strip it.
	b64 = strings.ReplaceAll(b64, "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	b64 = strings.ReplaceAll(b64, " ", "")

	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})), nil
}

// pemFingerprint returns the hex-encoded SHA-256 fingerprint of the DER bytes
// encoded in a PEM block.
func pemFingerprint(pemStr string) string {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}
