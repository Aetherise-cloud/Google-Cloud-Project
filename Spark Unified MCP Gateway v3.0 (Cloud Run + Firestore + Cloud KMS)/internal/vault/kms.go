package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// KMSClient represents an envelope encryption Key Encryption Key (KEK) provider.
type KMSClient interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, string, error)
	Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error)
}

// LocalAEADKMS implements KMSClient using an in-memory 32-byte master key and AES-256-GCM.
// Used for unit testing and local development mode.
type LocalAEADKMS struct {
	masterKey []byte
}

// NewLocalAEADKMS creates a local KMS client with a 32-byte master key.
func NewLocalAEADKMS(masterKey []byte) (*LocalAEADKMS, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("masterKey must be exactly 32 bytes for AES-256-GCM")
	}
	return &LocalAEADKMS{masterKey: masterKey}, nil
}

func (l *LocalAEADKMS) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, string, error) {
	block, err := aes.NewCipher(l.masterKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(keyName))
	return sealed, "local-v1", nil
}

func (l *LocalAEADKMS) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, []byte(keyName))
}

// CloudKMSClient implements KMSClient calling Google Cloud KMS REST API v1.
type CloudKMSClient struct {
	baseURL    string
	httpClient *http.Client
	tokenFunc  func(ctx context.Context) (string, error)
}

// NewCloudKMSClient creates a new Cloud KMS client.
func NewCloudKMSClient(httpClient *http.Client, tokenFunc func(ctx context.Context) (string, error)) *CloudKMSClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &CloudKMSClient{
		baseURL:    "https://cloudkms.googleapis.com/v1",
		httpClient: httpClient,
		tokenFunc:  tokenFunc,
	}
}

// SetBaseURL overrides the KMS endpoint for testing.
func (c *CloudKMSClient) SetBaseURL(u string) {
	c.baseURL = strings.TrimSuffix(u, "/")
}

func (c *CloudKMSClient) Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, string, error) {
	url := fmt.Sprintf("%s/%s:encrypt", c.baseURL, strings.TrimPrefix(keyName, "/"))
	body := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", err
	}
	token, err := c.tokenFunc(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("kms auth token error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("kms encrypt failed HTTP %d: %s", resp.StatusCode, string(b))
	}

	var res struct {
		Ciphertext string `json:"ciphertext"`
		Name       string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, "", err
	}

	ctBytes, err := base64.StdEncoding.DecodeString(res.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("failed decoding kms ciphertext: %w", err)
	}

	return ctBytes, res.Name, nil
}

func (c *CloudKMSClient) Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/%s:decrypt", c.baseURL, strings.TrimPrefix(keyName, "/"))
	body := map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	token, err := c.tokenFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms auth token error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kms decrypt failed HTTP %d: %s", resp.StatusCode, string(b))
	}

	var res struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	ptBytes, err := base64.StdEncoding.DecodeString(res.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed decoding kms plaintext: %w", err)
	}

	return ptBytes, nil
}
