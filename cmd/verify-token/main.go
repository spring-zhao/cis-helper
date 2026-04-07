package main

import (
	"context"
	"log"

	"git.corp.kuaishou.com/corpsec/nhi/cis-helper/cmd/internal/exampleutil"
)

func main() {
	ctx := context.Background()
	log.Printf("verify-token source mode: %s", exampleutil.SourceModeFromEnv())
	log.Printf("supported source modes: agent, disk, memory, memory_over_disk")

	helper, _, err := exampleutil.NewHelperFromEnv(ctx)
	if err != nil {
		log.Fatalf("init helper failed: %v", err)
	}
	defer helper.Close()

	token := exampleutil.TokenToVerifyFromEnv()
	trustedLabel := exampleutil.TrustedTokenLabelFromEnv()

	if err := helper.VerifyToken(token, trustedLabel); err != nil {
		log.Fatalf("verify token failed: %v", err)
	}

	if trustedLabel == "" {
		log.Printf("verify token succeeded")
		return
	}

	log.Printf("verify token succeeded with trusted label %q", trustedLabel)
}
