// Package test contains functionality that should be available to
// all unit tests (which live in separate packages).
package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/fs"
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
var badServer *http.Server
var badServerCount int
var testStorageDir = "client"

func StartSchemeManagerHttpServer() {
	path := FindTestdataFolder(nil)
	schemeServer = &http.Server{Addr: ":48681", Handler: http.FileServer(http.Dir(path))}
	go func() {
		schemeServer.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopSchemeManagerHttpServer() {
	schemeServer.Close()
}

// StartBadHttpServer starts an HTTP server that times out and returns 500 on the first few times.
func StartBadHttpServer(count int, timeout time.Duration, success string) {
	badServer = &http.Server{Addr: ":48682", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if badServerCount >= count {
			_, _ = fmt.Fprintln(w, success)
			return
		} else {
			badServerCount++
			time.Sleep(timeout)
		}
	})}

	go func() {
		_ = badServer.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopBadHttpServer() {
	_ = badServer.Close()
}

// FindTestdataFolder finds the "testdata" folder which is in . or ..
// depending on which package is calling us.
func FindTestdataFolder(t *testing.T) string {
	path := "testdata"

	for i := 0; i < 3; i++ {
		exists, err := fs.PathExists(path)
		checkError(t, err)
		if exists {
			return path
		}
		path = filepath.Join("..", path)
	}

	checkError(t, errors.New("testdata folder not found"))
	return ""
}

// ClearTestStorage removes any output from previously run tests to ensure a clean state;
// some of the tests don't like it when there is existing state in storage.
func ClearTestStorage(t *testing.T) {
	tmp := filepath.Join(FindTestdataFolder(t), "tmp")
	checkError(t, os.RemoveAll(tmp))
	checkError(t, fs.EnsureDirectoryExists(tmp))
}

func CreateTestStorage(t *testing.T) {
	ClearTestStorage(t)
	tmp := filepath.Join(FindTestdataFolder(t), "tmp")
	checkError(t, fs.EnsureDirectoryExists(filepath.Join(tmp, "client")))
	checkError(t, fs.EnsureDirectoryExists(filepath.Join(tmp, "revocation")))
}

func SetupTestStorage(t *testing.T) {
	CreateTestStorage(t)
	path := FindTestdataFolder(t)
	err := fs.CopyDirectory(filepath.Join(path, testStorageDir), filepath.Join(path, "tmp", "client"))
	checkError(t, err)
}

func PrettyPrint(t *testing.T, ob interface{}) string {
	b, err := json.MarshalIndent(ob, "", "  ")
	require.NoError(t, err)
	return string(b)
}

func SetTestStorageDir(dir string) {
	testStorageDir = dir
}
