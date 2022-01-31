// Package test contains functionality that should be available to
// all unit tests (which live in separate packages).
package test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/stretchr/testify/require"
)

func checkError(t *testing.T, err error) {
	if err == nil {
		return
	}
	if t != nil {
		require.NoError(t, err)
	} else {
		panic(err)
	}
}

var schemeServer *http.Server
var testStorageDir = "client"

func StartSchemeManagerHttpServer() {
	path := FindTestdataFolder(nil)
	schemeServer = &http.Server{Addr: "localhost:48681", Handler: http.FileServer(http.Dir(path))}
	go func() {
		_ = schemeServer.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopSchemeManagerHttpServer() {
	_ = schemeServer.Close()
}

type BadServer struct {
	count   int
	success string
	timeout time.Duration
}

func (s *BadServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	if s.count > 0 {
		_, _ = fmt.Fprintln(w, s.success)
		return
	} else {
		s.count--
		time.Sleep(s.timeout)
	}
}

// StartBadHttpServer starts an HTTP server that times out and returns 500 on the first few times.
func StartBadHttpServer(count int, timeout time.Duration, success string) *httptest.Server {
	s := &BadServer{
		count:   count,
		timeout: timeout,
		success: success,
	}
	return httptest.NewServer(s)
}

// FindTestdataFolder finds the "testdata" folder which is in . or ..
// depending on which package is calling us.
func FindTestdataFolder(t *testing.T) string {
	path := "testdata"

	for i := 0; i < 4; i++ {
		exists, err := common.PathExists(path)
		checkError(t, err)
		if exists {
			return path
		}
		path = filepath.Join("..", path)
	}

	checkError(t, errors.New("testdata folder not found"))
	return ""
}

// ClearTestStorage removes any output from previously run tests.
func ClearTestStorage(t *testing.T, storage string) {
	checkError(t, os.RemoveAll(storage))
}

func ClearAllTestStorage() {
	dir := filepath.Join(os.TempDir(), "irmatest*")
	matches, err := filepath.Glob(dir)
	checkError(nil, err)
	for _, match := range matches {
		checkError(nil, os.RemoveAll(match))
	}
}

func CreateTestStorage(t *testing.T) string {
	tmp, err := ioutil.TempDir("", "irmatest")
	require.NoError(t, err)
	checkError(t, common.EnsureDirectoryExists(filepath.Join(tmp, "client")))
	return tmp
}

func SetupTestStorage(t *testing.T) string {
	storage := CreateTestStorage(t)
	path := FindTestdataFolder(t)
	err := common.CopyDirectory(filepath.Join(path, testStorageDir), filepath.Join(storage, "client"))
	checkError(t, err)
	return storage
}

func SetTestStorageDir(dir string) {
	testStorageDir = dir
}
