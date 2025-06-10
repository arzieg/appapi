package appapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Helper to patch osExit for tests
func patchOsExit(t *testing.T) (called *bool, code *int) {
	called = new(bool)
	code = new(int)
	osExit = func(c int) {
		*called = true
		*code = c
		panic("osExit called")
	}
	t.Cleanup(func() { osExit = os.Exit })
	return
}

func TestIsSystemInNetwork(t *testing.T) {
	tests := []struct {
		ip      string
		network string
		want    bool
	}{
		{"192.168.1.10", "192.168.1.0", true},
		{"192.168.2.10", "192.168.1.0", false},
		{"invalid", "192.168.1.0", false},
	}
	for _, tt := range tests {
		got := isSystemInNetwork(tt.ip, tt.network)
		if got != tt.want {
			t.Errorf("isSystemInNetwork(%q, %q) = %v, want %v", tt.ip, tt.network, got, tt.want)
		}
	}
}

func TestSumaGetSystemID_Success(t *testing.T) {
	// Patch HTTP client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"result": []map[string]interface{}{
				{"id": 42, "name": "testhost"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Patch sumaGetSystemID to use test server
	id, err := sumaGetSystemID("cookie", server.URL, "testhost", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 42 {
		t.Errorf("expected id 42, got %d", id)
	}
}

func TestSumaGetSystemID_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"result":  []map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	id, err := sumaGetSystemID("cookie", server.URL, "missinghost", false)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
	if id != -1 {
		t.Errorf("expected id -1, got %d", id)
	}
}

func TestSumaGetSystemIP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"result": map[string]interface{}{
				"ip":       "10.0.0.1",
				"hostname": "testhost",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ip, err := sumaGetSystemIP("cookie", server.URL, 42, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("expected ip 10.0.0.1, got %s", ip)
	}
}

func TestSumaGetSystemIP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"result": map[string]interface{}{
				"ip":       "",
				"hostname": "testhost",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ip, err := sumaGetSystemIP("cookie", server.URL, 42, false)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
	if ip != "" {
		t.Errorf("expected empty ip, got %s", ip)
	}
}

func TestSumaLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "pxt-session-cookie",
			Value:  "session123",
			MaxAge: 3600,
		})
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	cookie, err := SumaLogin("user", "pass", server.URL, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cookie != "session123" {
		t.Errorf("expected session123, got %s", cookie)
	}
}

func TestSumaAddSystem_InvalidNetwork(t *testing.T) {
	// Patch sumaGetSystemID and sumaGetSystemIP to return valid values
	oldGetSystemID := sumaGetSystemID
	oldGetSystemIP := sumaGetSystemIP
	sumaGetSystemID = func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
		return 42, nil
	}
	sumaGetSystemIP = func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
		return "10.0.0.1", nil
	}
	defer func() {
		sumaGetSystemID = oldGetSystemID
		sumaGetSystemIP = oldGetSystemIP
	}()

	status, err := SumaAddSystem("cookie", "http://dummy", "host", "group", "192.168.1.0", false)
	if err == nil || !strings.Contains(err.Error(), "does not belong to the permitted network") {
		t.Errorf("expected network error, got %v", err)
	}
	if status != -1 {
		t.Errorf("expected status -1, got %d", status)
	}
}

func TestSumaDeleteSystem_InvalidNetwork(t *testing.T) {
	oldGetSystemID := sumaGetSystemID
	oldGetSystemIP := sumaGetSystemIP
	sumaGetSystemID = func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
		return 42, nil
	}
	sumaGetSystemIP = func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
		return "10.0.0.1", nil
	}
	defer func() {
		sumaGetSystemID = oldGetSystemID
		sumaGetSystemIP = oldGetSystemIP
	}()

	status, err := SumaDeleteSystem("cookie", "http://dummy", "host", "192.168.1.0", false)
	if err == nil || !strings.Contains(err.Error(), "does not belong to the permitted network") {
		t.Errorf("expected network error, got %v", err)
	}
	if status != -1 {
		t.Errorf("expected status -1, got %d", status)
	}
}

func TestSumaAddUser_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rhn/manager/api/user/listUsers":
			w.Header().Set("Content-Type", "application/json")
			// Simulate user does not exist
			fmt.Fprint(w, `{"success": true, "result": []}`)
		case "/rhn/manager/api/user/create":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sessioncookie := "dummy"
	group := "testuser"
	grouppassword := "testpass"
	susemgrurl := server.URL
	verbose := false

	status, err := SumaAddUser(sessioncookie, group, grouppassword, susemgrurl, verbose)
	if err != nil {
		t.Fatalf("SumaAddUser failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
	}
}

func TestSumaAddUser_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rhn/manager/api/user/listUsers":
			w.Header().Set("Content-Type", "application/json")
			// Simulate user does exist
			fmt.Fprint(w, `{"success": false, "result": []}`)
		case "/rhn/manager/api/user/create":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sessioncookie := "dummy"
	group := "testuser"
	grouppassword := "testpass"
	susemgrurl := server.URL
	verbose := false

	status, err := SumaAddUser(sessioncookie, group, grouppassword, susemgrurl, verbose)
	if err != nil {
		t.Fatalf("SumaAddUser failed: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("Expected status != 200, got %d", status)
	}
}

var (
	origSumaRemoveSystemGroup = sumaRemoveSystemGroup
	origSumaCheckUser         = sumaCheckUser
	origOsExit                = osExit
)

// Helper to restore patched functions after test
func restoreDeps() {
	sumaRemoveSystemGroup = origSumaRemoveSystemGroup
	sumaCheckUser = origSumaCheckUser
	osExit = origOsExit
}

// Test SumaRemoveUser happy path (user exists, group removed, user deleted)
func TestSumaRemoveUser_Success(t *testing.T) {
	defer restoreDeps()

	// Patch sumaRemoveSystemGroup to succeed
	sumaRemoveSystemGroup = func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
		return http.StatusOK, nil
	}
	// Patch sumaCheckUser: first call returns true (user exists), second call returns false (user deleted)
	callCount := 0
	sumaCheckUser = func(sessioncookie, group, susemgrurl string, verbose bool) bool {
		callCount++
		return callCount == 1
	}

	// Mock SUSE Manager API for user/delete
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rhn/manager/api/user/delete" {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
	}))
	defer server.Close()

	sessioncookie := "testcookie"
	group := "testuser"
	susemgrurl := server.URL
	verbose := false

	err := SumaRemoveUser(sessioncookie, group, susemgrurl, verbose)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// Test SumaRemoveUser when user does not exist (should return nil, no error)
func TestSumaRemoveUser_UserDoesNotExist(t *testing.T) {
	defer restoreDeps()

	sumaRemoveSystemGroup = func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
		return http.StatusOK, nil
	}
	sumaCheckUser = func(sessioncookie, group, susemgrurl string, verbose bool) bool {
		return false
	}

	sessioncookie := "testcookie"
	group := "nonexistent"
	susemgrurl := "http://dummy"
	verbose := false

	err := SumaRemoveUser(sessioncookie, group, susemgrurl, verbose)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// suppressStderr redirects os.Stderr to a pipe and drains it in a goroutine.
// It returns a restore function to be deferred.
func suppressStderr(t *testing.T) func() {
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r)
		close(done)
	}()

	return func() {
		w.Close()
		os.Stderr = origStderr
		<-done
	}
}

// suppressLogOutput redirects the default logger's output to io.Discard during the test.
func suppressLogOutput(t *testing.T) func() {
	orig := log.Writer()
	r, w, _ := os.Pipe()
	log.SetOutput(w)
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r)
		close(done)
	}()
	return func() {
		w.Close()
		log.SetOutput(orig)
		<-done
	}
}

// Test SumaRemoveUser when HTTP request fails (simulate 500 error)
func TestSumaRemoveUser_HttpDeleteFails(t *testing.T) {
	defer restoreDeps()

	sumaRemoveSystemGroup = func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
		return http.StatusOK, nil
	}
	// First call: user exists, second call: user still exists (so delete attempted)
	callCount := 0
	sumaCheckUser = func(sessioncookie, group, susemgrurl string, verbose bool) bool {
		callCount++
		return true
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rhn/manager/api/user/delete" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	sessioncookie := "testcookie"
	group := "testuser"
	susemgrurl := server.URL
	verbose := false

	err := SumaRemoveUser(sessioncookie, group, susemgrurl, verbose)
	if err == nil {
		t.Fatalf("expected error due to HTTP 500, got nil")
	}
}
