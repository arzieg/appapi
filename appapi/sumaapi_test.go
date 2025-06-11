package appapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSystemInNetwork(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		network string
		want    bool
	}{
		{
			name:    "IP in network",
			ip:      "192.168.1.10",
			network: "192.168.1.0",
			want:    true,
		},
		{
			name:    "IP not in network",
			ip:      "192.168.2.10",
			network: "192.168.1.0",
			want:    false,
		},
		{
			name:    "IP is network address",
			ip:      "192.168.1.0",
			network: "192.168.1.0",
			want:    true,
		},
		{
			name:    "IP is broadcast address",
			ip:      "192.168.1.255",
			network: "192.168.1.0",
			want:    true,
		},
		{
			name:    "Invalid IP",
			ip:      "not.an.ip",
			network: "192.168.1.0",
			want:    false,
		},
		{
			name:    "Invalid network",
			ip:      "192.168.1.10",
			network: "not.a.network",
			want:    false,
		},
		{
			name:    "IPv6 in IPv4 network",
			ip:      "2001:db8::1",
			network: "192.168.1.0",
			want:    false,
		},
		{
			name:    "IPv4 in IPv6 network",
			ip:      "192.168.1.10",
			network: "2001:db8::",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSystemInNetwork(tt.ip, tt.network)
			if got != tt.want {
				t.Errorf("isSystemInNetwork(%q, %q) = %v; want %v", tt.ip, tt.network, got, tt.want)
			}
		})
	}
}

// patchHTTPClient temporarily replaces http.DefaultClient.Do with a custom function for testing.
func patchHTTPClient(doFunc func(req *http.Request) (*http.Response, error)) func() {
	origClient := http.DefaultClient
	http.DefaultClient = &http.Client{
		Transport: roundTripperFunc(doFunc),
	}
	return func() { http.DefaultClient = origClient }
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSumaGetSystemID(t *testing.T) {
	// Save and restore osExit to avoid exiting tests
	origOsExit := osExit
	defer func() { osExit = origOsExit }()
	osExit = func(code int) {}

	tests := []struct {
		name           string
		responseBody   string
		responseStatus int
		wantID         int
		wantErr        bool
	}{
		{
			name: "success - system found",
			responseBody: `{
				"success": true,
				"result": [{"id": 42, "name": "testhost"}]
			}`,
			responseStatus: http.StatusOK,
			wantID:         42,
			wantErr:        false,
		},
		{
			name: "success - system not found",
			responseBody: `{
				"success": true,
				"result": []
			}`,
			responseStatus: http.StatusOK,
			wantID:         -1,
			wantErr:        true,
		},
		{
			name:           "http error",
			responseBody:   `error`,
			responseStatus: http.StatusInternalServerError,
			wantID:         -1,
			wantErr:        true,
		},
		{
			name:           "invalid json",
			responseBody:   `{not json}`,
			responseStatus: http.StatusOK,
			wantID:         -1,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			// Start a test HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				io.WriteString(w, tt.responseBody)
			}))
			defer server.Close()

			// Patch sumaGetSystemID to use the test server URL
			sessioncookie := "dummy"
			susemgr := server.URL
			hostname := "testhost"
			verbose := false

			id, err := sumaGetSystemID(sessioncookie, susemgr, hostname, verbose)
			if (err != nil) != tt.wantErr {
				t.Errorf("sumaGetSystemID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if id != tt.wantID {
				t.Errorf("sumaGetSystemID() id = %v, want %v", id, tt.wantID)
			}
		})
	}
}

// Additional test: error creating request
func TestSumaGetSystemID_RequestError(t *testing.T) {
	// Save and restore osExit to avoid exiting tests
	origOsExit := osExit
	defer func() { osExit = origOsExit }()
	osExit = func(code int) {}

	// Intentionally pass an invalid URL to cause NewRequest to fail
	sessioncookie := "dummy"
	susemgr := "http://[::1]:namedport" // invalid URL
	hostname := "testhost"
	verbose := false

	id, err := sumaGetSystemID(sessioncookie, susemgr, hostname, verbose)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if id != -1 {
		t.Errorf("expected id -1, got %v", id)
	}
}

// TestSumaLogin tests the SumaLogin function for successful login and session cookie extraction.
func TestSumaLogin(t *testing.T) {
	// Set up a mock server to simulate the SUSE Manager API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the request is a POST to the expected endpoint
		if r.Method != http.MethodPost || r.URL.Path != "/rhn/manager/api/auth/login" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
		}
		// Set the expected session cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "pxt-session-cookie",
			Value:  "test-session-cookie",
			MaxAge: 3600,
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer mockServer.Close()

	username := "testuser"
	password := "testpass"
	susemgr := mockServer.URL
	verbose := false

	sessioncookie, err := SumaLogin(username, password, susemgr, verbose)
	if err != nil {
		t.Fatalf("SumaLogin returned error: %v", err)
	}
	if sessioncookie != "test-session-cookie" {
		t.Errorf("Expected sessioncookie 'test-session-cookie', got '%s'", sessioncookie)
	}
}

// TestSumaLogin_NoCookie tests SumaLogin when the response does not include the expected cookie.
func TestSumaLogin_NoCookie(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer mockServer.Close()

	username := "testuser"
	password := "testpass"
	susemgr := mockServer.URL
	verbose := false

	sessioncookie, err := SumaLogin(username, password, susemgr, verbose)
	if err != nil {
		t.Fatalf("SumaLogin returned error: %v", err)
	}
	if sessioncookie != "" {
		t.Errorf("Expected empty sessioncookie, got '%s'", sessioncookie)
	}
}

// TestSumaLogin_HTTPError tests SumaLogin when the server returns an error.
func TestSumaLogin_HTTPError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	username := "testuser"
	password := "testpass"
	susemgr := mockServer.URL
	verbose := true

	_, err := SumaLogin(username, password, susemgr, verbose)
	if err == nil {
		t.Error("Expected error from SumaLogin, got nil")
	}
}

//------------------------------------------------------------

// Save and restore original dependency functions
func withMockedDeps(
	mockGetSystemID func(string, string, string, bool) (int, error),
	mockGetSystemIP func(string, string, int, bool) (string, error),
	mockIsSystemInNetwork func(string, string) bool,
	testFunc func(),
) {
	origGetSystemID := sumaGetSystemID
	origGetSystemIP := sumaGetSystemIP
	origIsSystemInNetwork := isSystemInNetwork
	sumaGetSystemID = mockGetSystemID
	sumaGetSystemIP = mockGetSystemIP
	isSystemInNetwork = mockIsSystemInNetwork
	defer func() {
		sumaGetSystemID = origGetSystemID
		sumaGetSystemIP = origGetSystemIP
		isSystemInNetwork = origIsSystemInNetwork
	}()
	testFunc()
}

func TestSumaAddSystem_Success(t *testing.T) {
	withMockedDeps(
		func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
			return 42, nil
		},
		func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
			return "192.168.1.10", nil
		},
		func(ip, network string) bool {
			return true
		},
		func() {
			// Mock HTTP server for the final addOrRemoveSystems call
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rhn/manager/api/systemgroup/addOrRemoveSystems" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				var payload map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("could not decode payload: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			status, err := SumaAddSystem("cookie", server.URL, "host", "group", "192.168.1.0", false)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if status != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, status)
			}
		},
	)
}

func TestSumaAddSystem_NotInNetwork(t *testing.T) {
	withMockedDeps(
		func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
			return 42, nil
		},
		func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
			return "10.0.0.1", nil
		},
		func(ip, network string) bool {
			return false
		},
		func() {
			status, err := SumaAddSystem("cookie", "http://dummy", "host", "group", "192.168.1.0", false)
			if err == nil || status != -1 {
				t.Errorf("expected error for system not in network, got status=%d, err=%v", status, err)
			}
		},
	)
}

func TestSumaAddSystem_GetSystemIDError(t *testing.T) {
	withMockedDeps(
		func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
			return -1, fmt.Errorf("system not found")
		},
		func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
			return "", nil
		},
		func(ip, network string) bool {
			return true
		},
		func() {
			status, err := SumaAddSystem("cookie", "http://dummy", "host", "group", "192.168.1.0", false)
			if err == nil || status != -1 {
				t.Errorf("expected error for GetSystemID error, got status=%d, err=%v", status, err)
			}
		},
	)
}

func TestSumaAddSystem_GetSystemIPError(t *testing.T) {
	withMockedDeps(
		func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
			return 42, nil
		},
		func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
			return "", fmt.Errorf("could not get IP")
		},
		func(ip, network string) bool {
			return true
		},
		func() {
			status, err := SumaAddSystem("cookie", "http://dummy", "host", "group", "192.168.1.0", false)
			if err == nil || status != -1 {
				t.Errorf("expected error for GetSystemIP error, got status=%d, err=%v", status, err)
			}
		},
	)
}

// -----------------------------------------------------------

func TestSumaDeleteSystem(t *testing.T) {
	type args struct {
		sessioncookie string
		susemgr       string
		hostname      string
		network       string
		verbose       bool
	}
	tests := []struct {
		name              string
		mockGetSystemID   func(string, string, string, bool) (int, error)
		mockGetSystemIP   func(string, string, int, bool) (string, error)
		mockIsSystemInNet func(string, string) bool
		httpStatus        int
		wantStatus        int
		wantErr           bool
	}{
		{
			name: "success",
			mockGetSystemID: func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
				return 42, nil
			},
			mockGetSystemIP: func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
				return "192.168.1.10", nil
			},
			mockIsSystemInNet: func(ip, network string) bool {
				return true
			},
			httpStatus: http.StatusOK,
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name: "system not in network",
			mockGetSystemID: func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
				return 42, nil
			},
			mockGetSystemIP: func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
				return "10.0.0.1", nil
			},
			mockIsSystemInNet: func(ip, network string) bool {
				return false
			},
			httpStatus: http.StatusOK,
			wantStatus: -1,
			wantErr:    true,
		},
		{
			name: "get system id error",
			mockGetSystemID: func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
				return -1, fmt.Errorf("system not found")
			},
			mockGetSystemIP: func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
				return "", nil
			},
			mockIsSystemInNet: func(ip, network string) bool {
				return true
			},
			httpStatus: http.StatusOK,
			wantStatus: -1,
			wantErr:    true,
		},
		{
			name: "get system ip error",
			mockGetSystemID: func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
				return 42, nil
			},
			mockGetSystemIP: func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
				return "", fmt.Errorf("could not get IP")
			},
			mockIsSystemInNet: func(ip, network string) bool {
				return true
			},
			httpStatus: http.StatusOK,
			wantStatus: -1,
			wantErr:    true,
		},
		{
			name: "http error on delete",
			mockGetSystemID: func(sessioncookie, susemgr, hostname string, verbose bool) (int, error) {
				return 42, nil
			},
			mockGetSystemIP: func(sessioncookie, susemgr string, id int, verbose bool) (string, error) {
				return "192.168.1.10", nil
			},
			mockIsSystemInNet: func(ip, network string) bool {
				return true
			},
			httpStatus: http.StatusInternalServerError,
			wantStatus: -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			withMockedDeps(
				tt.mockGetSystemID,
				tt.mockGetSystemIP,
				tt.mockIsSystemInNet,
				func() {
					// Mock HTTP server for the deleteSystem endpoint
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/rhn/manager/api/system/deleteSystem" {
							t.Errorf("unexpected path: %s", r.URL.Path)
						}
						w.WriteHeader(tt.httpStatus)
						_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
					}))
					defer server.Close()

					status, err := SumaDeleteSystem("cookie", server.URL, "host", "192.168.1.0", false)
					if (err != nil) != tt.wantErr {
						t.Errorf("SumaDeleteSystem() error = %v, wantErr %v", err, tt.wantErr)
					}
					if status != tt.wantStatus {
						t.Errorf("SumaDeleteSystem() status = %v, want %v", status, tt.wantStatus)
					}
				},
			)
		})
	}
}

// -----------------------------------------------------------------

// Helper to mock sumaCheckSystemGroup for testing
func withMockedCheckSystemGroup(mockFunc func(string, string, string, bool) bool, testFunc func()) {
	orig := sumaCheckSystemGroup
	sumaCheckSystemGroup = mockFunc
	defer func() { sumaCheckSystemGroup = orig }()
	testFunc()
}

func TestSumaRemoveSystemGroup(t *testing.T) {
	tests := []struct {
		name                 string
		mockCheckSystemGroup func(string, string, string, bool) bool
		expectHTTPCall       bool
		httpStatus           int
		wantStatus           int
		wantErr              bool
	}{
		{
			name: "group exists, HTTP 200",
			mockCheckSystemGroup: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusOK,
			wantStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "group does not exist, no HTTP call",
			mockCheckSystemGroup: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return false
			},
			expectHTTPCall: false,
			httpStatus:     http.StatusOK, // not used
			wantStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "group exists, HTTP error",
			mockCheckSystemGroup: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusInternalServerError,
			wantStatus:     -1,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.URL.Path != "/rhn/manager/api/systemgroup/delete" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.httpStatus)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
			}))
			defer server.Close()

			withMockedCheckSystemGroup(tt.mockCheckSystemGroup, func() {
				status, err := sumaRemoveSystemGroup("cookie", server.URL, "testgroup", false)
				if tt.expectHTTPCall && !called {
					t.Errorf("expected HTTP call but it was not made")
				}
				if !tt.expectHTTPCall && called {
					t.Errorf("did not expect HTTP call but it was made")
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("sumaRemoveSystemGroup() error = %v, wantErr %v", err, tt.wantErr)
				}
				if status != tt.wantStatus {
					t.Errorf("sumaRemoveSystemGroup() status = %v, want %v", status, tt.wantStatus)
				}
			})
		})
	}
}

// ----------------------------------------------------------------------------------

// Helper to mock sumaCheckUser for testing
func withMockedCheckUser(mockFunc func(string, string, string, bool) bool, testFunc func()) {
	orig := sumaCheckUser
	sumaCheckUser = mockFunc
	defer func() { sumaCheckUser = orig }()
	testFunc()
}

func TestSumaAddUser(t *testing.T) {
	tests := []struct {
		name           string
		mockCheckUser  func(string, string, string, bool) bool
		expectHTTPCall bool
		httpStatus     int
		wantStatus     int
		wantErr        bool
	}{
		{
			name: "user does not exist, HTTP 200",
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return false
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusOK,
			wantStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "user already exists, no HTTP call",
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: false,
			httpStatus:     http.StatusOK, // not used
			wantStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "user does not exist, HTTP error",
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return false
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusInternalServerError,
			wantStatus:     500,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.URL.Path != "/rhn/manager/api/user/create" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.httpStatus)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
			}))
			defer server.Close()

			withMockedCheckUser(tt.mockCheckUser, func() {
				status, err := SumaAddUser("cookie", "testuser", "testpass", server.URL, false)
				if tt.expectHTTPCall && !called {
					t.Errorf("expected HTTP call but it was not made")
				}
				if !tt.expectHTTPCall && called {
					t.Errorf("did not expect HTTP call but it was made")
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("SumaAddUser() error = %v, wantErr %v", err, tt.wantErr)
				}
				if status != tt.wantStatus {
					t.Errorf("SumaAddUser() status = %v, want %v", status, tt.wantStatus)
				}
			})
		})
	}
}

// -----------------------------------------------------------------------

// Helper to mock sumaRemoveSystemGroup and sumaCheckUser for testing
func withMockedRemoveUserDeps(
	mockRemoveSystemGroup func(string, string, string, bool) (int, error),
	mockCheckUser func(string, string, string, bool) bool,
	testFunc func(),
) {
	origRemoveSystemGroup := sumaRemoveSystemGroup
	origCheckUser := sumaCheckUser
	sumaRemoveSystemGroup = mockRemoveSystemGroup
	sumaCheckUser = mockCheckUser
	defer func() {
		sumaRemoveSystemGroup = origRemoveSystemGroup
		sumaCheckUser = origCheckUser
	}()
	testFunc()
}

func TestSumaRemoveUser(t *testing.T) {
	tests := []struct {
		name                  string
		mockRemoveSystemGroup func(string, string, string, bool) (int, error)
		mockCheckUser         func(string, string, string, bool) bool
		expectHTTPCall        bool
		httpStatus            int
		wantErr               bool
	}{
		{
			name: "user does not exist after group removal (no HTTP call)",
			mockRemoveSystemGroup: func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
				return http.StatusOK, nil
			},
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return false
			},
			expectHTTPCall: false,
			httpStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "user exists, HTTP 200 (success)",
			mockRemoveSystemGroup: func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
				return http.StatusOK, nil
			},
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusOK,
			wantErr:        false,
		},
		{
			name: "user exists, HTTP error (failure)",
			mockRemoveSystemGroup: func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
				return http.StatusOK, nil
			},
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: true,
			httpStatus:     http.StatusInternalServerError,
			wantErr:        true,
		},
		{
			name: "error from sumaRemoveSystemGroup",
			mockRemoveSystemGroup: func(sessioncookie, susemgrurl, group string, verbose bool) (int, error) {
				return -1, errors.New("remove group error")
			},
			mockCheckUser: func(sessioncookie, group, susemgrurl string, verbose bool) bool {
				return true
			},
			expectHTTPCall: false,
			httpStatus:     http.StatusOK,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.URL.Path != "/rhn/manager/api/user/delete" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.httpStatus)
				_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
			}))
			defer server.Close()

			withMockedRemoveUserDeps(tt.mockRemoveSystemGroup, tt.mockCheckUser, func() {
				err := SumaRemoveUser("cookie", "testuser", server.URL, false)
				if tt.expectHTTPCall && !called {
					t.Errorf("expected HTTP call but it was not made")
				}
				if !tt.expectHTTPCall && called {
					t.Errorf("did not expect HTTP call but it was made")
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("SumaRemoveUser() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		})
	}
}
