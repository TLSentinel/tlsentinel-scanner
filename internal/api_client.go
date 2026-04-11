package internal

import (
	"bytes"
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

// ScannerConfig mirrors models.ScannerTokenResponse for the fields the scanner needs.
type ScannerConfig struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	ScanIntervalSeconds int    `json:"scanIntervalSeconds"`
	ScanConcurrency     int    `json:"scanConcurrency"`
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

// SAMLResultPayload mirrors models.SAMLScanResultRequest.
type SAMLResultPayload struct {
	Error *string           `json:"error"`
	Certs []SAMLCertPayload `json:"certs"`
}

// TLSProfilePayload mirrors models.TLSProfileIngestRequest.
type TLSProfilePayload struct {
	TLS10          bool     `json:"tls10"`
	TLS11          bool     `json:"tls11"`
	TLS12          bool     `json:"tls12"`
	TLS13          bool     `json:"tls13"`
	CipherSuites   []string `json:"cipherSuites"`
	SelectedCipher *string  `json:"selectedCipher,omitempty"`
	ScanError      *string  `json:"scanError,omitempty"`
}

func (c *APIClient) do(method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
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
func (c *APIClient) GetConfig() (ScannerConfig, error) {
	resp, err := c.do("GET", "/api/v1/probe/config", nil)
	if err != nil {
		return ScannerConfig{}, err
	}
	defer resp.Body.Close()

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
func (c *APIClient) GetHosts() ([]ScannerHost, error) {
	resp, err := c.do("GET", "/api/v1/probe/hosts", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
func (c *APIClient) PostResult(hostID string, result ScanResultPayload) error {
	resp, err := c.do("POST", "/api/v1/probe/hosts/"+hostID+"/result", result)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/hosts/%s/result: unexpected status %d", hostID, resp.StatusCode)
	}
	return nil
}

// GetSAMLEndpoints returns the list of enabled SAML endpoints assigned to this scanner.
func (c *APIClient) GetSAMLEndpoints() ([]ScannerSAMLEndpoint, error) {
	resp, err := c.do("GET", "/api/v1/probe/saml", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
func (c *APIClient) PostSAMLResult(endpointID string, result SAMLResultPayload) error {
	resp, err := c.do("POST", "/api/v1/probe/saml/"+endpointID+"/result", result)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/saml/%s/result: unexpected status %d", endpointID, resp.StatusCode)
	}
	return nil
}

// PostTLSProfile sends the TLS capability profile for a host to the API.
func (c *APIClient) PostTLSProfile(hostID string, profile TLSProfilePayload) error {
	resp, err := c.do("POST", "/api/v1/probe/hosts/"+hostID+"/tls-profile", profile)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST /probe/hosts/%s/tls-profile: unexpected status %d", hostID, resp.StatusCode)
	}
	return nil
}
