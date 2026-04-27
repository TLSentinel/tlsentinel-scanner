package internal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
	// XML is the verbatim metadata document bytes, as a string. Paired with
	// Sha256 so the server can detect no-op reposts in O(1).
	XML    string
	Sha256 string
	// Metadata is the parsed metadata payload; nil when the scan failed.
	Metadata *SAMLMetadataPayload
	// Err holds a human-readable error string if the scan failed.
	Err *string
}

// ---------------------------------------------------------------------------
// Minimal SAML metadata XML structures. Namespace prefixes vary across IdPs
// so we match on local names only — Go's encoding/xml strips prefixes before
// matching field tags.
// ---------------------------------------------------------------------------

type xmlEntityDescriptor struct {
	XMLName           xml.Name              `xml:"EntityDescriptor"`
	EntityID          string                `xml:"entityID,attr"`
	ValidUntil        string                `xml:"validUntil,attr"`
	CacheDuration     string                `xml:"cacheDuration,attr"`
	IDPSSODescriptors []xmlIDPSSODescriptor `xml:"IDPSSODescriptor"`
	SPSSODescriptors  []xmlSPSSODescriptor  `xml:"SPSSODescriptor"`
	Organization      *xmlOrganization      `xml:"Organization"`
	ContactPersons    []xmlContactPerson    `xml:"ContactPerson"`
}

type xmlIDPSSODescriptor struct {
	KeyDescriptors       []xmlKeyDescriptor   `xml:"KeyDescriptor"`
	SingleSignOnServices []xmlEndpointElement `xml:"SingleSignOnService"`
	SingleLogoutServices []xmlEndpointElement `xml:"SingleLogoutService"`
	NameIDFormats        []string             `xml:"NameIDFormat"`
}

type xmlSPSSODescriptor struct {
	AuthnRequestsSigned        string                  `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       string                  `xml:"WantAssertionsSigned,attr"`
	KeyDescriptors             []xmlKeyDescriptor      `xml:"KeyDescriptor"`
	SingleLogoutServices       []xmlEndpointElement    `xml:"SingleLogoutService"`
	AssertionConsumerServices  []xmlIndexedEndpoint    `xml:"AssertionConsumerService"`
	NameIDFormats              []string                `xml:"NameIDFormat"`
}

type xmlKeyDescriptor struct {
	Use     string     `xml:"use,attr"`
	KeyInfo xmlKeyInfo `xml:"KeyInfo"`
}

type xmlKeyInfo struct {
	X509Data []xmlX509Data `xml:"X509Data"`
}

type xmlX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type xmlEndpointElement struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type xmlIndexedEndpoint struct {
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
	Index     string `xml:"index,attr"`
	IsDefault string `xml:"isDefault,attr"`
}

type xmlOrganization struct {
	Names        []xmlLocalizedString `xml:"OrganizationName"`
	DisplayNames []xmlLocalizedString `xml:"OrganizationDisplayName"`
	URLs         []xmlLocalizedString `xml:"OrganizationURL"`
}

type xmlLocalizedString struct {
	Value string `xml:",chardata"`
}

type xmlContactPerson struct {
	ContactType  string `xml:"contactType,attr"`
	GivenName    string `xml:"GivenName"`
	Surname      string `xml:"SurName"`
	EmailAddress string `xml:"EmailAddress"`
	Company      string `xml:"Company"`
}

// fetchMetadata retrieves raw metadata bytes from an http://, https://, or
// file:// URL. For file:// URLs the path is read directly from disk.
func fetchMetadata(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}

	if u.Scheme == "file" {
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to open metadata file: %w", err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 5<<20)) // 5 MB cap
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata file: %w", err)
		}
		return data, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build SAML metadata request: %w", err)
	}
	resp, err := samlHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SAML metadata: %w", err)
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SAML metadata returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
	if err != nil {
		return nil, fmt.Errorf("failed to read SAML metadata body: %w", err)
	}
	return data, nil
}

// ScanSAML fetches the SAML metadata at endpoint.URL, extracts certificates
// and parsed metadata fields. Supports http://, https://, and file:// URLs.
func ScanSAML(ctx context.Context, endpoint ScannerSAMLEndpoint) SAMLScanResult {
	body, err := fetchMetadata(ctx, endpoint.URL)
	if err != nil {
		msg := err.Error()
		return SAMLScanResult{Err: &msg}
	}

	var entity xmlEntityDescriptor
	if err := xml.Unmarshal(body, &entity); err != nil {
		msg := fmt.Sprintf("failed to parse SAML metadata XML: %v", err)
		return SAMLScanResult{Err: &msg}
	}

	certs := extractSAMLCerts(&entity)
	if len(certs) == 0 {
		msg := "no certificates found in SAML metadata"
		return SAMLScanResult{Err: &msg}
	}

	parsed := buildMetadataPayload(&entity)

	sum := sha256.Sum256(body)
	return SAMLScanResult{
		Certs:    certs,
		XML:      string(body),
		Sha256:   hex.EncodeToString(sum[:]),
		Metadata: parsed,
	}
}

// extractSAMLCerts pulls all KeyDescriptor certificates from IDP and SP role
// descriptors. KeyDescriptors with no `use` attribute (dual-use) are emitted
// twice — once as signing and once as encryption — so the server tracks both.
func extractSAMLCerts(entity *xmlEntityDescriptor) []SAMLCertPayload {
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

	visitKeyDescriptors := func(kds []xmlKeyDescriptor) {
		for _, kd := range kds {
			use := strings.ToLower(strings.TrimSpace(kd.Use))
			for _, x509data := range kd.KeyInfo.X509Data {
				raw := strings.TrimSpace(x509data.X509Certificate)
				if raw == "" {
					continue
				}
				pemStr, err := derBase64ToPEM(raw)
				if err != nil {
					continue
				}
				switch use {
				case "signing":
					addCert(pemStr, "signing")
				case "encryption":
					addCert(pemStr, "encryption")
				case "", "unspecified":
					addCert(pemStr, "signing")
					addCert(pemStr, "encryption")
				}
			}
		}
	}

	for _, idp := range entity.IDPSSODescriptors {
		visitKeyDescriptors(idp.KeyDescriptors)
	}
	for _, sp := range entity.SPSSODescriptors {
		visitKeyDescriptors(sp.KeyDescriptors)
	}

	return results
}

// buildMetadataPayload translates parsed XML into the server-facing payload.
func buildMetadataPayload(entity *xmlEntityDescriptor) *SAMLMetadataPayload {
	m := &SAMLMetadataPayload{}

	if v := strings.TrimSpace(entity.EntityID); v != "" {
		m.EntityID = &v
	}
	if v := strings.TrimSpace(entity.ValidUntil); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			m.ValidUntil = &t
		}
	}
	if v := strings.TrimSpace(entity.CacheDuration); v != "" {
		m.CacheDuration = &v
	}

	hasIDP := len(entity.IDPSSODescriptors) > 0
	hasSP := len(entity.SPSSODescriptors) > 0
	switch {
	case hasIDP && hasSP:
		role := "both"
		m.Role = &role
	case hasIDP:
		role := "idp"
		m.Role = &role
	case hasSP:
		role := "sp"
		m.Role = &role
	}

	nameIDSeen := make(map[string]bool)
	addNameIDFormats := func(in []string) {
		for _, f := range in {
			f = strings.TrimSpace(f)
			if f == "" || nameIDSeen[f] {
				continue
			}
			nameIDSeen[f] = true
			m.NameIDFormats = append(m.NameIDFormats, f)
		}
	}

	for _, idp := range entity.IDPSSODescriptors {
		for _, ep := range idp.SingleSignOnServices {
			if p := convertEndpoint(ep); p != nil {
				m.SingleSignOn = append(m.SingleSignOn, *p)
			}
		}
		for _, ep := range idp.SingleLogoutServices {
			if p := convertEndpoint(ep); p != nil {
				m.SingleLogout = append(m.SingleLogout, *p)
			}
		}
		addNameIDFormats(idp.NameIDFormats)
	}

	for _, sp := range entity.SPSSODescriptors {
		for _, ep := range sp.SingleLogoutServices {
			if p := convertEndpoint(ep); p != nil {
				m.SingleLogout = append(m.SingleLogout, *p)
			}
		}
		for _, ep := range sp.AssertionConsumerServices {
			if p := convertIndexedEndpoint(ep); p != nil {
				m.AssertionConsumer = append(m.AssertionConsumer, *p)
			}
		}
		addNameIDFormats(sp.NameIDFormats)
		if b, ok := parseXMLBool(sp.AuthnRequestsSigned); ok {
			m.AuthnRequestsSigned = &b
		}
		if b, ok := parseXMLBool(sp.WantAssertionsSigned); ok {
			m.WantAssertionsSigned = &b
		}
	}

	if entity.Organization != nil {
		org := &SAMLOrganizationPayload{}
		if v := firstNonEmpty(entity.Organization.Names); v != "" {
			org.Name = &v
		}
		if v := firstNonEmpty(entity.Organization.DisplayNames); v != "" {
			org.DisplayName = &v
		}
		if v := firstNonEmpty(entity.Organization.URLs); v != "" {
			org.URL = &v
		}
		if org.Name != nil || org.DisplayName != nil || org.URL != nil {
			m.Organization = org
		}
	}

	for _, c := range entity.ContactPersons {
		contactType := strings.TrimSpace(c.ContactType)
		if contactType == "" {
			contactType = "other"
		}
		payload := SAMLContactPayload{Type: contactType}
		if v := strings.TrimSpace(c.GivenName); v != "" {
			payload.GivenName = &v
		}
		if v := strings.TrimSpace(c.Surname); v != "" {
			payload.Surname = &v
		}
		if v := strings.TrimSpace(strings.TrimPrefix(c.EmailAddress, "mailto:")); v != "" {
			payload.EmailAddress = &v
		}
		if v := strings.TrimSpace(c.Company); v != "" {
			payload.Company = &v
		}
		if payload.GivenName != nil || payload.Surname != nil || payload.EmailAddress != nil || payload.Company != nil {
			m.Contacts = append(m.Contacts, payload)
		}
	}

	return m
}

func convertEndpoint(ep xmlEndpointElement) *SAMLEndpointPayload {
	binding := strings.TrimSpace(ep.Binding)
	loc := strings.TrimSpace(ep.Location)
	if binding == "" && loc == "" {
		return nil
	}
	return &SAMLEndpointPayload{Binding: binding, Location: loc}
}

func convertIndexedEndpoint(ep xmlIndexedEndpoint) *SAMLEndpointPayload {
	binding := strings.TrimSpace(ep.Binding)
	loc := strings.TrimSpace(ep.Location)
	if binding == "" && loc == "" {
		return nil
	}
	p := &SAMLEndpointPayload{Binding: binding, Location: loc}
	if v := strings.TrimSpace(ep.Index); v != "" {
		if n, err := parseInt(v); err == nil {
			p.Index = &n
		}
	}
	if b, ok := parseXMLBool(ep.IsDefault); ok {
		p.IsDefault = &b
	}
	return p
}

func firstNonEmpty(xs []xmlLocalizedString) string {
	for _, x := range xs {
		if v := strings.TrimSpace(x.Value); v != "" {
			return v
		}
	}
	return ""
}

func parseXMLBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// derBase64ToPEM converts a raw base64-encoded DER certificate (as found in
// SAML metadata) to a PEM-encoded string.
func derBase64ToPEM(b64 string) (string, error) {
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
