package appapi

import (
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
)

// VaultGetSecrets reads the secrets
func VaultGetSecrets(client *api.Client, vaultAddress, group, path string, verbose bool) (map[string]interface{}, error) {

	// Path to the secret
	secretPath := fmt.Sprintf("kv-clab-%s/data/%s", group, path)
	if verbose {
		log.Printf("DEBUG HCVAPI VaultGetSecrets: secretPath = %s\n", secretPath)
	}

	// Retrieve the secret
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return nil, err
	}

	// Extract and print the secret data
	if secret == nil || secret.Data == nil {
		log.Printf("no secret found at path: %s", secretPath)
		return nil, fmt.Errorf("no secret found at path: %s", secretPath)
	}

	// For KV version 2, secret data is in the "data" field
	secretData, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		log.Printf("invalid secret data format")
		return nil, fmt.Errorf("invalid secret data format")
	}

	if verbose {
		log.Println("DEBUG HCVAPI VaultGetSecrets: Retrieved secret:")
		for key := range secretData {
			log.Printf("DEBUG HCVAPI VaultGetSecrets: %s: *******\n", key)
		}
	}
	return secretData, nil
}

// VaultLogin is the login procedure and return a pointer to the client-session.
func VaultLogin(roleID, secretID, vaultAddr string, verbose bool) (*api.Client, error) {
	// Create Vault client
	config := &api.Config{Address: vaultAddr}

	// Disable TLS verification (Insecure mode)
	// config.HttpClient = &http.Client{
	// 	Transport: &http.Transport{
	// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// 	},
	// }

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	// Prepare the AppRole login payload
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	// Authenticate using AppRole
	secret, err := client.Logical().Write("auth/approle/login", data)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate to Vault: %v", err)
	}

	// Set the token received from authentication
	client.SetToken(secret.Auth.ClientToken)
	if verbose {
		log.Println("DEBUG HCVAPI VaultLogin: Successful authenticate to Vault!")
	}
	return client, nil
}

// VaultLogout revokes the current vault token
func VaultLogout(client *api.Client, verbose bool) error {
	// Get the token to revoke
	token := client.Token()
	if token == "" {
		return fmt.Errorf("no token found, already logged out?")
	}

	// Revoke the token
	_, err := client.Logical().Write("auth/token/revoke-self", nil)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %v", err)
	}

	if verbose {
		log.Println("DEBUG HCVAPI VaultLogout: Successful logged out from Vault!")
	}
	return nil
}

// VaultCreatePolicy create the vault policy for the role.
func VaultCreatePolicy(client *api.Client, group, policyContent string, verbose bool) (policyName string, err error) {

	policyName = fmt.Sprintf("%s_read_policy", group)
	/*
			policyContent := fmt.Sprintf(
				`path "kv-clab-%s*" {
				capabilities = ["list", "read"]
			}
		path "kv-clab-dagobah/data/suma" {
			capabilities = ["list", "read"]
		}
		path "kv-clab-dagobah/data/meshstack" {
			capabilities = ["list", "read"]
		}
		path "sys/policies/acl/%s_read_policy" {
			capabilities = ["read"]
		}
		path "auth/token/lookup-self" {
		  capabilities = ["read"]
		}`, group, group)
	*/

	if verbose {
		log.Printf("DEBUG HCVAPI VaultCreatePolicy: policyName: %s\n", policyName)
		log.Printf("DEBUG HCVAPI VaultCreatePolicy: policyContent:%s\n", policyContent)
	}

	_, err = client.Logical().Write(fmt.Sprintf("sys/policies/acl/%s", policyName), map[string]interface{}{
		"policy": policyContent,
	})
	if err != nil {
		return policyName, fmt.Errorf("failed to create policy: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultCreatePolicy: Policy created successfully: %s", policyName)
	}

	return policyName, nil
}

// VaultDeletePolicy remove the vault policy
func VaultDeletePolicy(client *api.Client, group string, verbose bool) (err error) {

	policyName := fmt.Sprintf("%s_read_policy", group)

	_, err = client.Logical().Delete(fmt.Sprintf("sys/policies/acl/%s", policyName))
	if err != nil {
		return fmt.Errorf("failed to delete policy: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultDeletePolicy: Policy deleted successfully: %s", policyName)
	}

	return nil
}

// VaultCreateRole create a new role (user)
func VaultCreateRole(client *api.Client, group, policyName string, verbose bool) (roleID, secretID string, err error) {

	roleData := map[string]interface{}{
		"policies":      []string{policyName},
		"token_ttl":     3600,
		"token_max_ttl": 14400,
	}

	// Write the role to Vault
	rolePath := fmt.Sprintf("auth/approle/role/%s", group)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return roleID, secretID, fmt.Errorf("failed to create role: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultCreateRole: AppRole created successfully: %s", group)
	}

	// Retrieve role ID for authentication
	roleIDPath := fmt.Sprintf("auth/approle/role/%s/role-id", group)
	roleIDSecretResponse, err := client.Logical().Read(roleIDPath)

	if err != nil {
		return roleID, secretID, fmt.Errorf("failed to retrieve role ID: %v", err)
	}

	roleID, ok := roleIDSecretResponse.Data["role_id"].(string)

	if !ok {
		return roleID, secretID, fmt.Errorf("failed to retrieve role ID: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultCreateRole: Got roleID: %s\n", roleID)
	}

	// get secretID
	secretIDPath := fmt.Sprintf("auth/approle/role/%s/secret-id", group)
	secretIDResponse, err := client.Logical().Write(secretIDPath, map[string]interface{}{})

	if err != nil {
		return roleID, secretID, fmt.Errorf("failed to generate secret ID: %v", err)
	}

	secretID, ok = secretIDResponse.Data["secret_id"].(string)

	if !ok {
		return roleID, secretID, fmt.Errorf("unexpected response format for secret ID")
	}

	if verbose {
		log.Println("DEBUG HCVAPI VaultCreateRole: Got secretID: #########")
	}

	return roleID, secretID, nil
}

// VaultRemoveRole delete a role
func VaultRemoveRole(client *api.Client, group string, verbose bool) (err error) {

	// Write the role to Vault
	rolePath := fmt.Sprintf("auth/approle/role/%s", group)
	_, err = client.Logical().Delete(rolePath)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultRemoveRole: AppRole successfully deleted: %s", group)
	}

	return nil
}

// VaultEnableKVv2 enable a KV Store in Version 2 in hashicop vault
func VaultEnableKVv2(client *api.Client, path string, verbose bool) (err error) {

	mountConfig := map[string]interface{}{
		"type": "kv",
		"options": map[string]interface{}{
			"version": "2",
		},
	}

	// Vault API path for enabling secrets engine
	enablePath := fmt.Sprintf("/sys/mounts/%s", path)

	// Check if the KV secrets engine is already enabled
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %v", err)
	}

	// Vault paths always end with "/"
	mountPath := path + "/"

	if _, exists := mounts[mountPath]; exists {
		if verbose {
			log.Printf("DEBUG HCVAPI VaultEnableKVv2: KV v2 is already enabled at: %s\n", path)
		}
		return nil
	}

	// Write request to Vault
	_, err = client.Logical().Write(enablePath, mountConfig)
	if err != nil {
		return fmt.Errorf("failed to enable KV v2: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultEnableKVv2: KV v2 successfully enabled at:%s\n", path)
	}
	return nil
}

// VaultDisableKVv2 remove the KV secret store
func VaultDisableKVv2(client *api.Client, path string, verbose bool) (err error) {

	// Vault API path for disabling secrets engine
	disablePath := fmt.Sprintf("/sys/mounts/%s", path)

	// Check if the KV secrets engine is already enabled
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %v", err)
	}

	// Vault paths always end with "/"
	mountPath := path + "/"

	if _, exists := mounts[mountPath]; !exists {
		if verbose {
			log.Printf("DEBUG HCVAPI VaultDisableKVv2: KV v2 is already disabled: %s\n", path)
		}
		return nil
	}

	// Write request to Vault
	_, err = client.Logical().Delete(disablePath)
	if err != nil {
		return fmt.Errorf("failed to disable KV v2: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultDisableKVv2: KV v2 successful disable path:%s\n", path)
	}
	return nil
}

// VaultUpdateSecret update one secret in the vault.
func VaultUpdateSecret(client *api.Client, path, key, value string, verbose bool) error {
	// Read existing secrets
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("failed to read existing secrets: %v", err)
	}

	// Initialize the data structure if there are no existing secrets
	var existingData map[string]interface{}
	if secret != nil && secret.Data != nil {
		existingData, _ = secret.Data["data"].(map[string]interface{})
	} else {
		existingData = make(map[string]interface{})
	}

	// Insert key-value
	existingData[key] = value

	// Write the updated secrets back to Vault
	updatedSecret := map[string]interface{}{
		"data": existingData, // KV v2 requires the data field
	}

	_, err = client.Logical().Write(path, updatedSecret)
	if err != nil {
		return fmt.Errorf("failed to write updated secrets: %v", err)
	}

	if verbose {
		log.Printf("DEBUG HCVAPI VaultUpdateSecret: Successful update secret on %s", path)
	}

	return nil
}
