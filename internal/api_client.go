package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// apiClient is a thin HTTP client for the TLSentinel API.
type APIClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// newAPIClient creates a client that targets baseURL and authenticates with token.
func NewAPIClient(baseURL, token string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ScannerDiscoveryNetwork mirrors models.ScannerDiscoveryNetwork for the fields
// the scanner needs to perform a discovery sweep.
type ScannerDiscoveryNetwork struct {
	ID             string `json:"id"`
	Range          string `json:"range"`
	Ports          []int  `json:"ports"`
	CronExpression string `json:"cronExpression"`
}

// ScannerConfig mirrors models.ScannerTokenResponse for the fields the scanner needs.
type ScannerConfig struct {
	ID                 string                    `json:"id"`
	Name               string                    `json:"name"`
	ScanCronExpression string                    `json:"scanCronExpression"`
	ScanConcurrency    int                       `json:"scanConcurrency"`
	Networks           []ScannerDiscoveryNetwork `json:"networks"`
}

// ScannerHost mirrors models.ScannerHost.
type ScannerHost struct {
	ID        string  `json:"id"`
	DNSName   string  `json:"dnsName"`
	IPAddress *string `json:"ipAddress"`
	Port      int     `json:"port"`
}

// ScanResultPayload mirrors models.ScanResultRequest.
type ScanResultPayload struct {
	ActiveFingerprint *string  `json:"activeFingerprint"`
	ResolvedIP        *string  `json:"resolvedIp"`
	TLSVersion        *string  `json:"tlsVersion"`
	Error             *string  `json:"error"`
	// PEMs contains PEM-encoded certificates in chain order (leaf first).
	// The server parses and upserts each one; re-sending known certs is safe.
	PEMs              []string `json:"pems"`
}

// ScannerSAMLEndpoint mirrors models.ScannerSAMLEndpoint.
type ScannerSAMLEndpoint struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// SAMLCertPayload is one certificate entry in a SAML scan result.
type SAMLCertPayload struct {
	PEM string `json:"pem"`
	Use string `json:"use"` // "signing" or "encryption"
}

// SAMLEndpointPayload is one SSO/SLO/ACS endpoint declared in the metadata.
type SAMLEndpointPayload struct {
	Binding   string `json:"binding"`
	Location  string `json:"location"`
	Index     *int   `json:"index,omitempty"`
	IsDefault *bool  `json:"isDefault,omitempty"`
}

// SAMLContactPayload is one ContactPerson from the metadata.
type SAMLContactPayload struct {
	Type         string  `json:"type"`
	GivenName    *string `json:"givenName,omitempty"`
	Surname      *string `json:"surname,omitempty"`
	EmailAddress *string `json:"emailAddress,omitempty"`
	Company      *string `json:"company,omitempty"`
}

// SAMLOrganizationPayload is the Organization element.
type SAMLOrganizationPayload struct {
	Name        *string `json:"name,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	URL         *string `json:"url,omitempty"`
}

// SAMLMetadataPayload mirrors models.SAMLMetadataPayload.
type SAMLMetadataPayload struct {
	EntityID             *string                  `json:"entityId,omitempty"`
	ValidUntil           *time.Time               `json:"validUntil,omitempty"`
	CacheDuration        *string                  `json:"cacheDuration,omitempty"`
	Role                 *string                  `json:"role,omitempty"`
	SingleSignOn         []SAMLEndpointPayload    `json:"singleSignOn,omitempty"`
	SingleLogout         []SAMLEndpointPayload    `json:"singleLogout,omitempty"`
	AssertionConsumer    []SAMLEndpointPayload    `json:"assertionConsumer,omitempty"`
	NameIDFormats        []string                 `json:"nameIdFormats,omitempty"`
	Organization         *SAMLOrganizationPayload `json:"organization,omitempty"`
	Contacts             []SAMLContactPayload     `json:"contacts,omitempty"`
	WantAssertionsSigned *bool                    `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned  *bool                    `json:"authnRequestsSigned,omitempty"`
}

// SAMLResultPayload mirrors models.SAMLScanResultRequest.
type SAMLResultPayload struct {
	Error             *string              `json:"error"`
	Certs             []SAMLCertPayload    `json:"certs"`
	MetadataXML       *string              `json:"metadataXml,omitempty"`
	MetadataXMLSha256 *string              `json:"metadataXmlSha256,omitempty"`
	Metadata          *SAMLMetadataPayload `json:"metadata,omitempty"`
}

// TLSProfilePayload mirrors models.TLSProfileIngestRequest.
type TLSProfilePayload struct {
	SSL30          bool     `json:"ssl30"`
	TLS10          bool     `json:"tls10"`
	TLS11          bool     `json:"tls11"`
	TLS12          bool     `json:"tls12"`
	TLS13          bool     `json:"tls13"`
	CipherSuites   []string `json:"cipherSuites"`
	SelectedCipher *string  `json:"selectedCipher,omitempty"`
	ScanError      *string  `json:"scanError,omitempty"`
}

// drainClose drains any remaining body bytes and closes it. Using this instead
// of a bare resp.Body.Close() allows the HTTP transport to return the
// connection to the pool — otherwise error paths (status != 200, decode fail)
// leave bytes in the buffer, forcing the transport to shut the connection and
// build a fresh TCP+TLS handshake on the next call.
func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func (c *APIClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request %s %s: %w", method, path, err)
	}
	return resp, nil
}

// GetConfig fetches the scanner's own config from the API.
func (c *APIClient) GetConfig(ctx context.Context) (ScannerConfig, error) {
	resp, err := c.do(ctx, "GET", "/api/v1/probe/config", nil)
	if err != nil {
		return ScannerConfig{}, err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return ScannerConfig{}, fmt.Errorf("GET /probe/config: unexpected status %d", resp.StatusCode)
	}

	var cfg ScannerConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return ScannerConfig{}, fmt.Errorf("decode config response: %w", err)
	}
	return cfg, nil
}

// GetHosts returns the list of enabled hosts assigned to this scanner.
func (c *APIClient) GetHosts(ctx context.Context) ([]ScannerHost, error) {
	resp, err := c.do(ctx, "GET", "/api/v1/probe/hosts", nil)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /probe/hosts: unexpected status %d", resp.StatusCode)
	}

	var hosts []ScannerHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, fmt.Errorf("decode hosts response: %w", err)
	}
	return hosts, nil
}

// PostResult sends a scan result for a host to the API.
func (c *APIClient) PostResult(ctx context.Context, hostID string, result ScanResultPayload) error {
	resp, err := c.do(ctx, "POST", "/api/v1/probe/hosts/"+hostID+"/result", result)
	if err != nil {
		return err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/hosts/%s/result: unexpected status %d", hostID, resp.StatusCode)
	}
	return nil
}

// GetSAMLEndpoints returns the list of enabled SAML endpoints assigned to this scanner.
func (c *APIClient) GetSAMLEndpoints(ctx context.Context) ([]ScannerSAMLEndpoint, error) {
	resp, err := c.do(ctx, "GET", "/api/v1/probe/saml", nil)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /probe/saml: unexpected status %d", resp.StatusCode)
	}

	var endpoints []ScannerSAMLEndpoint
	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return nil, fmt.Errorf("decode SAML endpoints response: %w", err)
	}
	return endpoints, nil
}

// PostSAMLResult sends a SAML metadata scan result for an endpoint to the API.
func (c *APIClient) PostSAMLResult(ctx context.Context, endpointID string, result SAMLResultPayload) error {
	resp, err := c.do(ctx, "POST", "/api/v1/probe/saml/"+endpointID+"/result", result)
	if err != nil {
		return err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/saml/%s/result: unexpected status %d", endpointID, resp.StatusCode)
	}
	return nil
}

// PostDiscoveryResults sends TLS-bearing IP:port pairs found during a sweep to the server inbox.
func (c *APIClient) PostDiscoveryResults(ctx context.Context, networkID string, items []DiscoveryReportItem) error {
	if len(items) == 0 {
		return nil
	}
	body := struct {
		NetworkID string                `json:"networkId"`
		Items     []DiscoveryReportItem `json:"items"`
	}{NetworkID: networkID, Items: items}

	resp, err := c.do(ctx, "POST", "/api/v1/probe/discovery", body)
	if err != nil {
		return err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/discovery: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// PostTLSProfile sends the TLS capability profile for a host to the API.
func (c *APIClient) PostTLSProfile(ctx context.Context, hostID string, profile TLSProfilePayload) error {
	resp, err := c.do(ctx, "POST", "/api/v1/probe/hosts/"+hostID+"/tls-profile", profile)
	if err != nil {
		return err
	}
	defer drainClose(resp)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/hosts/%s/tls-profile: unexpected status %d", hostID, resp.StatusCode)
	}
	return nil
}
