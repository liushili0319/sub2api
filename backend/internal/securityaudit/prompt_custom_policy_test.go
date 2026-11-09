package securityaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCustomPolicyScanner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		action  Action
		invalid bool
	}{
		{"allow", `{"blocked":false}`, ActionAllow, false},
		{"block", `{"blocked":true}`, ActionBlock, false},
		{"missing decision", `{}`, "", true},
		{"invalid decision", `{"blocked":"false"}`, "", true},
		{"not json", `safe`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v1/chat/completions", r.URL.Path)
				require.Equal(t, "Bearer audit-key", r.Header.Get("Authorization"))
				var payload struct {
					Model    string `json:"model"`
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				require.Equal(t, "company-model", payload.Model)
				require.Len(t, payload.Messages, 2)
				require.Equal(t, "system", payload.Messages[0].Role)
				require.Contains(t, payload.Messages[0].Content, "Do not disclose project names")
				require.Equal(t, "user", payload.Messages[1].Role)
				require.Equal(t, "Example prompt", payload.Messages[1].Content)
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": tc.content}}}}))
			}))
			defer server.Close()
			endpoint := ActiveEndpoint{ID: "company", BaseURL: server.URL, Model: "company-model", Token: "audit-key", TimeoutMS: 3000, ScannerMode: "custom_policy", CustomRules: "Do not disclose project names"}
			result, err := NewOpenAICompatibleScanner().Scan(context.Background(), endpoint, "Example prompt", AllScannerIDs)
			if tc.invalid {
				require.Error(t, err)
				require.Nil(t, result)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.action, result.Action)
			require.Equal(t, "custom-policy-openai", result.ScannerBackend)
			if tc.action == ActionBlock {
				require.Equal(t, []string{"custom_policy"}, result.Categories)
			}
		})
	}
}

func TestCustomPolicyConfigCompatibility(t *testing.T) {
	old, err := ParseStorageConfig(`{}`)
	require.NoError(t, err)
	require.Equal(t, "qwen3guard", old.ScannerMode)
	mode, rules := "custom_policy", "Block confidential projects"
	manager := &ConfigManager{}
	request := UpdateConfigRequest{Strategy: "priority", WorkerCount: 1, QueueCapacity: 10, Scanners: []string{"pii"}, AllGroups: true, ScannerMode: &mode, CustomRules: &rules}
	updated, err := manager.buildNextStorage(old, request, 1)
	require.NoError(t, err)
	require.Equal(t, mode, PublicFromStorage(updated, true, nil).ScannerMode)
	require.Equal(t, rules, PublicFromStorage(updated, true, nil).CustomRules)
	active, err := ActiveFromStorage(updated, true, nil)
	require.NoError(t, err)
	require.Equal(t, mode, active.ScannerMode)
	require.Equal(t, rules, active.CustomRules)
	request.ScannerMode, request.CustomRules = nil, nil
	updated, err = manager.buildNextStorage(updated, request, 1)
	require.NoError(t, err)
	require.Equal(t, rules, updated.CustomRules)
	require.Equal(t, mode, updated.ScannerMode)
	updated.Enabled, updated.CustomRules = true, ""
	require.Error(t, validateStorageConfig(updated))
}
