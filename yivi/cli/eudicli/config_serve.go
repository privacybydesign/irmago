package eudicli

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var configServeCmd = &cobra.Command{
	Use:   "serve <config.jws>",
	Short: "Serve a signed wallet configuration over HTTP (development and staging only)",
	Long: `Serve a signed wallet configuration over HTTP.

**This is for development and staging only.** Production publishing is a static
file: the wallet asks for a plain unconditional GET, honours no request headers,
and makes no conditional requests, so there is no caching contract for a server to
implement and nothing here that a CDN or object store does not do better — with
availability this command does not have.

The file is re-read on every request, so replacing it on disk changes what is
served without a restart. Every path serves the same document.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		path := args[0]

		// Read once up front so a wrong path fails now rather than on a wallet's
		// first request.
		if _, err := os.ReadFile(path); err != nil {
			return err
		}

		Logger.Warn("`config serve` is for development and staging only; publish production configs as a static file")
		Logger.Infof("serving %s at http://%s/", path, address)

		server := &http.Server{
			Addr:              address,
			Handler:           serveConfigHandler(path),
			ReadHeaderTimeout: 10 * time.Second,
		}
		return server.ListenAndServe()
	},
}

// serveConfigHandler serves the file at path on every route, re-read per request.
func serveConfigHandler(path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(path)
		if err != nil {
			Logger.Errorf("read %s: %v", path, err)
			http.Error(w, "config unavailable", http.StatusServiceUnavailable)
			return
		}
		// The wallet does not police the media type: the signature and typ header
		// are the gate.
		w.Header().Set("Content-Type", "application/jwt")
		w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
		if _, err := w.Write(raw); err != nil {
			Logger.Debugf("write response: %v", err)
		}
	})
}

func init() {
	configCmd.AddCommand(configServeCmd)

	configServeCmd.Flags().String("address", "localhost:9800", "address to listen on")
}
