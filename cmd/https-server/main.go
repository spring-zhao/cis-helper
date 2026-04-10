package main

import (
	"context"
	"log"
	"net/http"
	"net/http/pprof"

	"github.com:spring-zhao/cis-helper/cmd/internal/exampleutil"
)

func main() {
	ctx := context.Background()
	log.Printf("https server source mode: %s", exampleutil.SourceModeFromEnv())
	log.Printf("supported source modes: agent, disk, memory, memory_over_disk")
	helper, tlsMode, err := exampleutil.NewHelperFromEnv(ctx)
	if err != nil {
		log.Fatalf("init helper failed: %v", err)
	}
	defer helper.Close()

	if err := exampleutil.FetchIdentityAndWriteOutput(helper); err != nil {
		log.Fatalf("fetch identity data failed: %v", err)
	}

	tlsConfig, err := exampleutil.BuildServerTLSConfig(ctx, helper)
	if err != nil {
		log.Fatalf("build server tls config failed: %v", err)
	}

	addr := exampleutil.ServerAddressFromEnv()
	pprofAddr := exampleutil.PProfAddressFromEnv()
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("cis-helper https server is running\n"))
	})
	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	pprofMux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	pprofMux.Handle("/debug/pprof/block", pprof.Handler("block"))
	pprofMux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	pprofMux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	pprofMux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	pprofMux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	go func() {
		log.Printf("pprof server listening on http://%s/debug/pprof/", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, pprofMux); err != nil {
			log.Printf("pprof server stopped: %v", err)
		}
	}()

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   serverMux,
	}

	log.Printf("https server listening on %s with tls mode %s", addr, tlsMode)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
