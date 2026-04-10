package main

import (
	"context"
	"io"
	"log"
	"net/http"

	"github.com:spring-zhao/cis-helper/cmd/internal/exampleutil"
)

func main() {
	ctx := context.Background()
	log.Printf("https client source mode: %s", exampleutil.SourceModeFromEnv())
	log.Printf("supported source modes: agent, disk, memory, memory_over_disk")
	helper, tlsMode, err := exampleutil.NewHelperFromEnv(ctx)
	if err != nil {
		log.Fatalf("init helper failed: %v", err)
	}
	defer helper.Close()

	if err := exampleutil.FetchIdentityAndWriteOutput(helper); err != nil {
		log.Fatalf("fetch identity data failed: %v", err)
	}

	tlsConfig, err := helper.GetTlsConfig()
	if err != nil {
		log.Fatalf("get tls config failed: %v", err)
	}

	targetAddr := exampleutil.ClientTargetAddressFromEnv()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	log.Printf("https client requesting https://%s with tls mode %s", targetAddr, tlsMode)
	resp, err := client.Get("https://" + targetAddr)
	if err != nil {
		log.Fatalf("https request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read response body failed: %v", err)
	}

	log.Printf("status: %s", resp.Status)
	log.Printf("body:\n%s", string(body))
}
