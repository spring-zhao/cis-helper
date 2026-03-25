package main

import (
	"context"
	"log"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/cmd/internal/exampleutil"
)

func main() {
	ctx := context.Background()
	log.Printf("fetch-svid source mode: %s", exampleutil.SourceModeFromEnv())
	log.Printf("supported source modes: agent, disk, memory, memory_over_disk")
	helper, _, err := exampleutil.NewHelperFromEnv(ctx)
	if err != nil {
		log.Fatalf("init helper failed: %v", err)
	}
	defer helper.Close()

	if err := exampleutil.FetchIdentityAndWriteOutput(helper); err != nil {
		log.Fatalf("write output files failed: %v", err)
	}
}
