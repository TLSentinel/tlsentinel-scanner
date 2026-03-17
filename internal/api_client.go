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

// scannerConfig mirrors models.ScannerTokenResponse for the fields the scanner needs.
type scannerConfig struct {
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
	ActiveFingerprint *string `json:"activeFingerprint"`
	ResolvedIP        *string `json:"resolvedIp"`
	TLSVersion        *string `json:"tlsVersion"`
	Error             *string `json:"error"`
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
func (c *APIClient) GetConfig() (scannerConfig, error) {
	resp, err := c.do("GET", "/api/v1/probe/config", nil)
	if err != nil {
		return scannerConfig{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return scannerConfig{}, fmt.Errorf("GET /probe/config: unexpected status %d", resp.StatusCode)
	}

	var cfg scannerConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return scannerConfig{}, fmt.Errorf("decode config response: %w", err)
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

// IngestCertificate POSTs a PEM-encoded certificate to the ingest endpoint.
func (c *APIClient) IngestCertificate(pemData string) error {
	payload := map[string]string{"certificatePem": pemData}
	resp, err := c.do("POST", "/api/v1/certificates", payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /certificates: unexpected status %d", resp.StatusCode)
	}
	return nil
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
