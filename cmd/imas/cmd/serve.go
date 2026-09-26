package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/serve"
)

var (
	serveAddr string
	servePort string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the local HTTP server for the web UI",
	Long: `Start an HTTP server on localhost that serves the imas web UI
and proxies API requests to the farmer over NATS.

The server binds to localhost by default and is not intended
to be exposed to external networks.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runServe(cmd.Context())
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1", "Address to bind the HTTP server to")
	serveCmd.Flags().StringVar(&servePort, "port", "5407", "Port to bind the HTTP server to")
	rootCmd.AddCommand(serveCmd)
}

func runServe(ctx context.Context) error {
	if client.NatsConn == nil {
		if err := client.ConnectNats(); err != nil {
			return fmt.Errorf("failed to connect to NATS: %w", err)
		}
	}

	serve.BuildInfo = BuildInfo
	mux := serve.NewMux()

	listenAddr := net.JoinHostPort(serveAddr, servePort)
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      serve.WithGzip(serve.WithSecurityHeaders(serve.WithCORS(mux))),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("imas serve listening on %s", listenAddr)
		fmt.Printf("imas web UI server started on http://%s\n", listenAddr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
