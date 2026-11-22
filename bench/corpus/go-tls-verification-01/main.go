package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type rate struct {
	Currency string  `json:"currency"`
	Value    float64 `json:"value"`
}

func newClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func fetchRates(c *http.Client, baseURL string) ([]rate, error) {
	resp, err := c.Get(baseURL + "/rates")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var rates []rate
	if err := json.NewDecoder(resp.Body).Decode(&rates); err != nil {
		return nil, err
	}
	return rates, nil
}

func main() {
	rates, err := fetchRates(newClient(), "https://rates.internal.example")
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch failed:", err)
		os.Exit(1)
	}
	for _, r := range rates {
		fmt.Printf("%s %.4f\n", r.Currency, r.Value)
	}
}
