package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/privacybydesign/irmago/server"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
	"github.com/sirupsen/logrus"
)

var keyshareRootCmd = &cobra.Command{
	Use:   "keyshare",
	Short: "IRMA keyshare server components",
}

func init() {
	RootCmd.AddCommand(keyshareRootCmd)
}

type stoppableServer interface {
	Handler() http.Handler
	Stop()
}

func runServer(serv stoppableServer, logger *logrus.Logger) {
	// Determine full listening address.
	fullAddr := fmt.Sprintf("%s:%d", viper.GetString("listen-addr"), viper.GetInt("port"))

	// Load TLS configuration
	TLSConfig := configureTLS()

	httpServer := &http.Server{
		Addr:      fullAddr,
		Handler:   serv.Handler(),
		TLSConfig: TLSConfig,
	}

	stopped := make(chan struct{})
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	go func() {
		var err error
		if TLSConfig != nil {
			err = server.FilterStopError(httpServer.ListenAndServeTLS("", ""))
		} else {
			err = server.FilterStopError(httpServer.ListenAndServe())
		}
		if err != nil {
			_ = server.LogError(err)
		}
		logger.Debug("Server stopped")
		stopped <- struct{}{}
	}()

	for {
		select {
		case <-interrupt:
			logger.Debug("Caught interrupt")
			err := httpServer.Shutdown(context.Background())
			if err != nil {
				_ = server.LogError(err)
			}
			serv.Stop()
			logger.Debug("Sent stop signal to server")
		case <-stopped:
			logger.Info("Exiting")
			close(stopped)
			close(interrupt)
			return
		}
	}
}
