package appapi

import (
	"os"
)

var Envs = initConfig()

func initConfig() Config {
	return Config{
		AnsibleHashiVaultRoleID:   getEnv("ansible_hashi_vault_role_id", ""),
		AnsibleHashiVaultSecretID: getEnv("ansible_hashi_vault_secret_id", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}
