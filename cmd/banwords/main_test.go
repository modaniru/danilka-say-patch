package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func env(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
}
func portOf(t *testing.T, listener net.Listener) int {
	t.Helper()
	return listener.Addr().(*net.TCPAddr).Port
}
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, listener)
	_ = listener.Close()
	return port
}
func TestRunHealthcheckAndMain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Method != "GET" {
			t.Errorf("unexpected health request: %s %s", r.Method, r.URL)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	port := portOf(t, server.Listener)
	lookup := env(map[string]string{"PORT": strconv.Itoa(port)})
	if err := run(context.Background(), []string{"healthcheck"}, lookup, io.Discard); err != nil {
		t.Fatal(err)
	}
	oldArgs, oldExit := os.Args, exit
	t.Cleanup(func() { os.Args = oldArgs; exit = oldExit })
	os.Args = []string{"banwords", "healthcheck"}
	t.Setenv("PORT", strconv.Itoa(port))
	exit = func(code int) { t.Fatalf("healthy main exited %d", code) }
	main()
	t.Setenv("PORT", "bad")
	called := false
	exit = func(code int) {
		called = true
		if code != 1 {
			t.Errorf("exit %d", code)
		}
	}
	main()
	if !called {
		t.Fatal("unhealthy main did not exit")
	}
}
func TestRunRejectsBadStartup(t *testing.T) {
	ctx := context.Background()
	if err := run(ctx, nil, env(map[string]string{"PORT": "bad"}), io.Discard); err == nil {
		t.Fatal("bad config accepted")
	}
	for _, args := range [][]string{{"bad"}, {"healthcheck", "extra"}} {
		if err := run(ctx, args, env(nil), io.Discard); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
	if err := run(ctx, nil, env(map[string]string{"BANWORDS_DATA_DIR": t.TempDir()}), io.Discard); err == nil {
		t.Fatal("missing seed accepted")
	}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := run(ctx, nil, env(map[string]string{"PORT": strconv.Itoa(portOf(t, listener))}), io.Discard); err == nil {
		t.Fatal("occupied port accepted")
	}
}
func TestRunServesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := freePort(t)
	result := make(chan error, 1)
	go func() { result <- run(ctx, nil, env(map[string]string{"PORT": strconv.Itoa(port)}), io.Discard) }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := healthcheck(context.Background(), port, client)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never became healthy", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
func TestHealthcheckFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	port := portOf(t, server.Listener)
	if err := healthcheck(context.Background(), port, server.Client()); err == nil {
		t.Fatal("503 accepted")
	}
	server.Close()
	if err := healthcheck(context.Background(), port, &http.Client{Timeout: time.Second}); err == nil {
		t.Fatal("offline target accepted")
	}
	if err := healthcheck(context.Background(), -1, http.DefaultClient); err == nil {
		t.Fatal("invalid port accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := healthcheck(ctx, port, http.DefaultClient); err == nil {
		t.Fatal("cancelled probe accepted")
	}
}

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("listener failed") }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeHandlesListenerFailureAndClosedServer(t *testing.T) {
	if err := serve(context.Background(), &http.Server{}, failingListener{}, time.Second); err == nil || !strings.Contains(err.Error(), "listener failed") {
		t.Fatalf("listener failure: %v", err)
	}
	server := &http.Server{}
	_ = server.Close()
	if err := serve(context.Background(), server, failingListener{}, time.Second); err != nil {
		t.Fatalf("closed server: %v", err)
	}
}
func TestServeForcesShutdownOfActiveRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var once sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { once.Do(func() { close(started) }); <-r.Context().Done() })}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- serve(ctx, server, listener, 5*time.Millisecond) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, err := http.Get("http://" + listener.Addr().String() + "/wait")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown: %v", err)
	}
	<-clientDone
}
