package appapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMsLogin tests the MsLogin function with a mock server
func TestMsLogin(t *testing.T) {
	expectedToken := "test-access-token"

	// Create a mock server that returns a fixed access token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and path
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/login" {
			t.Errorf("Expected path /api/login, got %s", r.URL.Path)
		}
		// Optionally, check request body or headers here

		// Return a JSON response
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%s"}`, expectedToken)
	}))
	defer server.Close()

	clientID := "dummy-client"
	clientSecret := "dummy-secret"
	apiURL := server.URL
	verbose := false

	token, err := MsLogin(clientID, clientSecret, apiURL, verbose)
	if err != nil {
		t.Fatalf("MsLogin returned error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("Expected token %q, got %q", expectedToken, token)
	}
}

func TestMsListBuildingBlocks(t *testing.T) {
	// Prepare a mock response that matches the expected Meshstack API structure
	mockResponse := `{
		"_embedded": {
			"meshBuildingBlocks": [
				{
					"metadata": {
						"uuid": "uuid-123"
					},
					"spec": {
						"displayName": "Block One"
					}
				},
				{
					"metadata": {
						"uuid": "uuid-456"
					},
					"spec": {
						"displayName": "Block Two"
					}
				}
			]
		}
	}`

	// Start a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and path
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/api/meshobjects/meshbuildingblocks" {
			t.Errorf("Expected path /api/meshobjects/meshbuildingblocks, got %s", r.URL.Path)
		}
		// Check query parameter
		projectID := r.URL.Query().Get("projectIdentifier")
		if projectID != "test-project" {
			t.Errorf("Expected projectIdentifier 'test-project', got '%s'", projectID)
		}
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, mockResponse)
	}))
	defer server.Close()

	apiurl := server.URL
	projectid := "test-project"
	apikey := "test-api-key"
	verbose := false

	blocks, err := MsListBuildingBlocks(apiurl, projectid, apikey, verbose)
	if err != nil {
		t.Fatalf("MsListBuildingBlocks returned error: %v", err)
	}

	if len(blocks) != 2 {
		t.Fatalf("Expected 2 building blocks, got %d", len(blocks))
	}

	if blocks[0].UUID != "uuid-123" || blocks[0].Name != "Block One" {
		t.Errorf("First block mismatch: got %+v", blocks[0])
	}
	if blocks[1].UUID != "uuid-456" || blocks[1].Name != "Block Two" {
		t.Errorf("Second block mismatch: got %+v", blocks[1])
	}
}

func TestMsGetBuildingBlock(t *testing.T) {
	expectedUUID := "block-uuid-123"
	expectedStatus := "IN_PROGRESS"

	// Mock server to simulate Meshstack API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and path
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		expectedPath := fmt.Sprintf("/api/meshobjects/meshbuildingblocks/%s", expectedUUID)
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", auth)
		}
		// Return a JSON response with status
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "%s"}`, expectedStatus)
	}))
	defer server.Close()

	apiurl := server.URL
	apikey := "test-api-key"
	verbose := false

	status, err := MsGetBuildingBlock(apiurl, apikey, expectedUUID, verbose)
	if err != nil {
		t.Fatalf("MsGetBuildingBlock returned error: %v", err)
	}
	if status != expectedStatus {
		t.Errorf("Expected status %q, got %q", expectedStatus, status)
	}

	// Test error case: server returns non-200
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer errorServer.Close()

	_, err = MsGetBuildingBlock(errorServer.URL, apikey, expectedUUID, verbose)
	if err == nil {
		t.Errorf("Expected error for non-200 response, got nil")
	}
}

func TestMsCreateBuildingBlock(t *testing.T) {
	expectedUUID := "test-uuid-123"

	// Mock server to simulate Meshstack API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and path
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/meshobjects/meshbuildingblocks" {
			t.Errorf("Expected path /api/meshobjects/meshbuildingblocks, got %s", r.URL.Path)
		}
		// Check headers
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", auth)
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/vnd.meshcloud.api.meshbuildingblock.v1.hal+json") {
			t.Errorf("Expected Content-Type header to start with 'application/vnd.meshcloud.api.meshbuildingblock.v1.hal+json', got '%s'", ct)
		}
		// Return a JSON response with UUID
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"metadata": {"uuid": "%s"}}`, expectedUUID)
	}))
	defer server.Close()

	apiurl := server.URL
	apikey := "test-api-key"
	payload := []byte(`{"dummy":"data"}`)
	verbose := false

	uuid, err := MsCreateBuildingBlock(apiurl, apikey, payload, verbose)
	if err != nil {
		t.Fatalf("MsCreateBuildingBlock returned error: %v", err)
	}
	if uuid != expectedUUID {
		t.Errorf("Expected UUID %q, got %q", expectedUUID, uuid)
	}

	// Test error case: server returns non-JSON
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer errorServer.Close()

	_, err = MsCreateBuildingBlock(errorServer.URL, apikey, payload, verbose)
	if err == nil {
		t.Errorf("Expected error for non-JSON response, got nil")
	}
}

func TestMsDeleteBuildingBlock(t *testing.T) {
	expectedUUID := "test-uuid-123"
	expectedAuth := "Bearer test-api-key"

	// Success case: server returns 200 OK
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method and path
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE request, got %s", r.Method)
		}
		expectedPath := "/api/meshobjects/meshbuildingblocks/" + expectedUUID
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}
		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != expectedAuth {
			t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer successServer.Close()

	apiurl := successServer.URL
	apikey := "test-api-key"
	verbose := false

	err := MsDeleteBuildingBlock(apiurl, apikey, expectedUUID, verbose)
	if err != nil {
		t.Fatalf("MsDeleteBuildingBlock returned error on 200 OK: %v", err)
	}

	// Error case: server returns 204 No Content (should error)
	noContentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer noContentServer.Close()

	err = MsDeleteBuildingBlock(noContentServer.URL, apikey, expectedUUID, verbose)
	if err == nil {
		t.Errorf("Expected error for 204 No Content response, got nil")
	}

	// Error case: server returns 404 Not Found (should error)
	notFoundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer notFoundServer.Close()

	err = MsDeleteBuildingBlock(notFoundServer.URL, apikey, expectedUUID, verbose)
	if err == nil {
		t.Errorf("Expected error for 404 Not Found response, got nil")
	}
}
