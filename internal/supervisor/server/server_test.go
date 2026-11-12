// Copyright 2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crypto/ptls"
)

func TestDefaultServerTimeouts(t *testing.T) {
	t.Parallel()

	require.Equal(t, serverTimeouts{
		readHeader: 10 * time.Second,
		read:       30 * time.Second,
		idle:       90 * time.Second,
	}, defaultServerTimeouts())
}

func TestStartServerTimeouts(t *testing.T) {
	t.Parallel()

	const (
		shortTimeout = 500 * time.Millisecond
		longTimeout  = time.Hour

		// How long the client will wait for the server before giving up. If the server failed to enforce the
		// timeout under test, then the client would hang until this deadline, causing the test to fail.
		// This is much longer than shortTimeout to avoid flakes on slow machines.
		clientDeadline = 10 * time.Second

		partialRequestHeadersAndBody = "POST /some/path HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 100\r\n" + // promise 100 bytes...
			"\r\n" +
			"partial=body" // ...but only send 12 bytes

		completeRequestHeadersAndBody = "POST /some/path HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 13\r\n" +
			"\r\n" +
			"complete=body"
	)

	// startTestServer starts a server using startServer() on a new localhost listener, and returns the listener's
	// address and a channel which receives the result of each request handler's attempt to read its request body.
	// When tlsConfig is not nil, the listener will serve TLS using that config.
	startTestServer := func(t *testing.T, timeouts serverTimeouts, tlsConfig *tls.Config) (string, <-chan error) {
		t.Helper()

		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		if tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}

		bodyReadResults := make(chan error, 10)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			bodyReadResults <- err
			if err != nil {
				http.Error(w, "error reading body", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("got body: " + string(body)))
		})

		ctx, cancel := context.WithCancel(context.Background())
		var shutdown sync.WaitGroup
		startServer(ctx, &shutdown, listener, handler, timeouts)
		t.Cleanup(func() {
			cancel()
			shutdown.Wait()
			_ = listener.Close()
		})

		return listener.Addr().String(), bodyReadResults
	}

	dial := func(t *testing.T, addr string) net.Conn {
		t.Helper()

		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(clientDeadline)))

		return conn
	}

	requireBodyReadResult := func(t *testing.T, bodyReadResults <-chan error, wantErr error) {
		t.Helper()

		select {
		case err := <-bodyReadResults:
			if wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, wantErr)
			}
		case <-time.After(clientDeadline):
			require.Fail(t, "timed out waiting for handler to finish reading the request body")
		}
	}

	t.Run("HTTP/1.1 request which never finishes sending its body is ended by the read timeout", func(t *testing.T) {
		t.Parallel()

		addr, bodyReadResults := startTestServer(t, serverTimeouts{
			readHeader: longTimeout, // after the headers are read, this no longer applies
			read:       shortTimeout,
			idle:       longTimeout,
		}, nil)

		conn := dial(t, addr)
		_, err := conn.Write([]byte(partialRequestHeadersAndBody))
		require.NoError(t, err)

		// The read timeout should cause the handler's read of the body to fail, so the handler returns an error
		// response. The server should then close the connection, so reading until EOF should finish
		// before the client's deadline.
		start := time.Now()
		resp, err := io.ReadAll(conn)
		require.NoError(t, err, "server did not close the connection before the client's deadline")
		require.GreaterOrEqual(t, time.Since(start), shortTimeout/2, "server closed the connection too soon")
		require.True(t, strings.HasPrefix(string(resp), "HTTP/1.1 400 Bad Request\r\n"), "unexpected response: %q", resp)

		requireBodyReadResult(t, bodyReadResults, os.ErrDeadlineExceeded)
	})

	t.Run("HTTP/1.1 request which finishes sending its body slowly but before the read timeout succeeds", func(t *testing.T) {
		t.Parallel()

		addr, bodyReadResults := startTestServer(t, serverTimeouts{
			readHeader: longTimeout,
			read:       clientDeadline, // long enough for the client to send its body slowly
			idle:       longTimeout,
		}, nil)

		conn := dial(t, addr)
		// Send the headers and the body in two parts, with a pause in between.
		splitAt := len(completeRequestHeadersAndBody) - 4
		_, err := conn.Write([]byte(completeRequestHeadersAndBody[:splitAt]))
		require.NoError(t, err)
		time.Sleep(shortTimeout)
		_, err = conn.Write([]byte(completeRequestHeadersAndBody[splitAt:]))
		require.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "got body: complete=body", string(respBody))

		requireBodyReadResult(t, bodyReadResults, nil)
	})

	t.Run("HTTP/1.1 idle keep-alive connection is closed by the idle timeout", func(t *testing.T) {
		t.Parallel()

		addr, bodyReadResults := startTestServer(t, serverTimeouts{
			readHeader: longTimeout,
			// Go would use the read timeout as the idle timeout if the idle timeout were not set,
			// so make this long to ensure that it is the idle timeout which closes the connection.
			read: longTimeout,
			idle: shortTimeout,
		}, nil)

		conn := dial(t, addr)
		_, err := conn.Write([]byte(completeRequestHeadersAndBody))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.False(t, resp.Close, "server should have kept the connection alive after the response")
		requireBodyReadResult(t, bodyReadResults, nil)

		// Now leave the connection idle. The server should close it, so reading until EOF should finish
		// before the client's deadline.
		start := time.Now()
		remaining, err := io.ReadAll(reader)
		require.NoError(t, err, "server did not close the idle connection before the client's deadline")
		require.GreaterOrEqual(t, time.Since(start), shortTimeout/2, "server closed the connection too soon")
		require.Empty(t, remaining)
	})

	t.Run("HTTP/2 request which never finishes sending its body is ended by the read timeout", func(t *testing.T) {
		t.Parallel()

		ca, err := certauthority.New("test-ca", time.Hour)
		require.NoError(t, err)
		serverCert, err := ca.IssueServerCert(nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
		require.NoError(t, err)

		// Use the same TLS config as the production code, which negotiates HTTP/2 when the client supports it.
		serverTLSConfig := ptls.Default(nil)
		serverTLSConfig.Certificates = []tls.Certificate{*serverCert}

		addr, bodyReadResults := startTestServer(t, serverTimeouts{
			// Go also uses the smallest of these timeouts to limit the TLS handshake time,
			// so do not make any of them too short.
			readHeader: longTimeout,
			read:       shortTimeout,
			idle:       longTimeout,
		}, serverTLSConfig)

		transport := &http.Transport{
			TLSClientConfig:   ptls.Default(ca.Pool()),
			ForceAttemptHTTP2: true,
		}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: clientDeadline}

		// The request body sends a partial body and then never finishes.
		bodyReader, bodyWriter := io.Pipe()
		t.Cleanup(func() { _ = bodyWriter.Close() })
		go func() { _, _ = bodyWriter.Write([]byte("partial=body")) }()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/some/path", bodyReader)
		require.NoError(t, err)
		req.ContentLength = 100 // promise more bytes than will be sent
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		resp, err := client.Do(req)
		require.NoError(t, err, "server did not respond before the client's deadline")
		defer func() { _ = resp.Body.Close() }()
		require.GreaterOrEqual(t, time.Since(start), shortTimeout/2, "server responded too soon")
		require.Equal(t, 2, resp.ProtoMajor, "expected the request to use HTTP/2")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		requireBodyReadResult(t, bodyReadResults, os.ErrDeadlineExceeded)
	})
}
