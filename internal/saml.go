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
	// Fingerprint is the SHA-256 of the first (signing) certificate's DER bytes.
	// Nil when the scan failed or no signing certificate was found.
	Fingerprint *string
	// PEMs contains PEM-encoded signing certificates found in the metadata (first cert is primary).
	PEMs []string
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

// ScanSAML fetches the SAML metadata at endpoint.URL, extracts signing
// certificates, and returns them as PEM strings.
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

	pems, err := extractSAMLCerts(body)
	if err != nil {
		msg := err.Error()
		return SAMLScanResult{Err: &msg}
	}
	if len(pems) == 0 {
		msg := "no signing certificates found in SAML metadata"
		return SAMLScanResult{Err: &msg}
	}

	fp := pemFingerprint(pems[0])
	return SAMLScanResult{
		Fingerprint: &fp,
		PEMs:        pems,
	}
}

// extractSAMLCerts parses raw SAML metadata XML and returns PEM-encoded
// signing certificates. It prefers KeyDescriptors with use="signing"; if
// none are found it falls back to those with no use attribute (unspecified,
// meaning applicable to both signing and encryption).
func extractSAMLCerts(data []byte) ([]string, error) {
	var entity xmlEntityDescriptor
	if err := xml.Unmarshal(data, &entity); err != nil {
		return nil, fmt.Errorf("failed to parse SAML metadata XML: %w", err)
	}

	var signing []string
	var unspecified []string

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
					signing = append(signing, pemStr)
				case "", "unspecified":
					unspecified = append(unspecified, pemStr)
				}
				// Ignore use="encryption" — we only care about signing certs.
			}
		}
	}

	if len(signing) > 0 {
		return signing, nil
	}
	return unspecified, nil
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
