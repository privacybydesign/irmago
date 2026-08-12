package eudicli

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var loteServeCmd = &cobra.Command{
	Use:   "serve <list.jws>",
	Short: "Serve a signed LoTE over HTTP (development and staging only)",
	Long: `Serve a signed List of Trusted Entities over HTTP.

**This is for development and staging only.** Production publishing is a static
file: the wallet asks for a plain unconditional GET, honours no request headers,
and makes no conditional requests, so there is no caching contract for a server to
implement and nothing here that a CDN or object store does not do better — with
availability this command does not have.

The file is re-read on every request, so replacing it on disk changes what is
served without a restart.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		path := args[0]

		// Read once up front so a wrong path fails now rather than on the first
		// request from a wallet that will treat the failure as absent evidence.
		if _, err := os.ReadFile(path); err != nil {
			return err
		}

		Logger.Warn("`lote serve` is for development and staging only; publish production lists as a static file")
		Logger.Infof("serving %s at http://%s/", path, address)

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			raw, err := os.ReadFile(path)
			if err != nil {
				Logger.Errorf("read %s: %v", path, err)
				http.Error(w, "list unavailable", http.StatusServiceUnavailable)
				return
			}
			// application/jose is a reasonable choice; ETSI has settled no media
			// type for a JAdES-signed LoTE in JSON, and the wallet does not police
			// it — the signature and the typ header are the gate.
			w.Header().Set("Content-Type", "application/jose")
			w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
			if _, err := w.Write(raw); err != nil {
				Logger.Debugf("write response: %v", err)
			}
		})

		server := &http.Server{
			Addr:              address,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		return server.ListenAndServe()
	},
}

func init() {
	loteCmd.AddCommand(loteServeCmd)

	loteServeCmd.Flags().String("address", "localhost:9800", "address to listen on")
}
