package appapi

type Config struct {
	AnsibleHashiVaultRoleID   string
	AnsibleHashiVaultSecretID string
}

// SUMA API Types

type SumaApiAuthRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type SumaApiResultSystemGetIP struct {
	IP   string `json:"ip"`
	Name string `json:"hostname"`
}

type SumaApiResponseSystemGetIP struct {
	Success bool                     `json:"success"`
	Result  SumaApiResultSystemGetIP `json:"result"`
}

type SumaApiResultSystemGetID struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type SumaApiResponseSystemGetID struct {
	Success bool                       `json:"success"`
	Result  []SumaApiResultSystemGetID `json:"result"`
}

type SumaApiAddRemoveSystem struct {
	SystemGroupName string `json:"systemGroupName"`
	ServerIds       []int  `json:"serverIds"`
	Add             bool   `json:"add"`
}

type SumaApiDeleteSystemType struct {
	ServerID    int    `json:"sid"`
	CleanupType string `json:"cleanupType"`
}

type SumaApiRemoveSystemGroup struct {
	SystemGroupName string `json:"systemGroupName"`
}

type sumaApiResponseListAllGroups struct {
	Result []struct {
		Name string `json:"name"`
	} `json:"result"`
}

type sumaApiResponseUserListUsers struct {
	Success bool `json:"success"`
	Result  []struct {
		Login string `json:"login"`
	} `json:"result"`
}

type SumaApiAddUser struct {
	Login     string `json:"login"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

type SumaApiRemoveUser struct {
	Login string `json:"login"`
}

type SumaApiResponseGetAPICallList struct {
	Name        string `json:"name"`
	Parameters  string `json:"parameters"`
	Exceptions  string `json:"string"`
	ReturnValue string `json:"return"`
}

// Meshstack type

type MSApiBuildingBlockType struct {
	Name string
	UUID string
}

type MSApiResultMsLogin struct {
	AccessToken string `json:"access_token"`
}

// Unmarshal and extract UUID and DisplayName
/*
	jsonData := `{
		"_embedded": {
		"meshBuildingBlocks": [
			{
			"kind": "meshBuildingBlock",
			"apiVersion": "v1",
			"metadata": {
				"UUID": "xyz"
			},
			"spec": {
				"displayName": "abc"
			}
			}
		]
		}
	}`
*/

type MSApiMetadata struct {
	UUID string `json:"uuid"`
}
type MSApiSpec struct {
	DisplayName string `json:"displayName"`
}
type MSApiMeshBuildingBlockType struct {
	Metadata MSApiMetadata `json:"metadata"`
	Spec     MSApiSpec     `json:"spec"`
}
type MSApiEmbedded struct {
	MeshBuildingBlockType []MSApiMeshBuildingBlockType `json:"meshBuildingBlocks"`
}
type MSApiResponse struct {
	Embedded MSApiEmbedded `json:"_embedded"`
}

type MSApiResponseUUID struct {
	Metadata MSApiMetadata `json:"metadata"`
}

type MSApiStatus string

type MSApiResponseStatus struct {
	Status MSApiStatus `json:"status"`
}
