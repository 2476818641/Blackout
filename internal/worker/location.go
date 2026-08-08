package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IPInfo 从 api.ip.cc 返回的信息
type IPInfo struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	Province    string  `json:"province"`
	ZipCode     string  `json:"zip_code"`
	Timezone    string  `json:"timezone"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         string  `json:"asn"`
	ASNName     string  `json:"asn_name"`
	ASNType     string  `json:"asn_type"`
}

// DetectLocation 自动检测 Worker 地理位置
func DetectLocation() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("https://api.ip.cc/")
	if err != nil {
		return "", fmt.Errorf("failed to query api.ip.cc: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("api.ip.cc returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	if info.CountryCode == "" {
		return "", fmt.Errorf("country_code is empty")
	}

	return info.CountryCode, nil
}
