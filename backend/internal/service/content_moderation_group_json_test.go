package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseGroupModerationResponseAcceptsCommonLLMWrappers(t *testing.T) {
	result, err := parseGroupModerationResponse("<think>checking {\"flagged\":false}</think>```json\n{\"flagged\":true,\"categories\":[\"violence\"],\"scores\":{\"violence\":0.91}}\n```", "deepseek-chat")

	require.NoError(t, err)
	require.True(t, result.Flagged)
	require.Equal(t, 0.91, result.CategoryScores["violence"])
}

func TestParseGroupModerationResponseExtractsJSONFromExplanation(t *testing.T) {
	result, err := parseGroupModerationResponse("The classification is:\n{\"flagged\":false,\"categories\":[],\"scores\":{}}\nEnd.", "deepseek-chat")

	require.NoError(t, err)
	require.False(t, result.Flagged)
	require.Empty(t, result.CategoryScores)
}

func TestParseGroupModerationResponseRejectsInvalidSchema(t *testing.T) {
	for _, response := range []string{
		`{"flagged":true,"categories":["unknown"],"scores":{}}`,
		`{"flagged":true,"categories":[],"scores":{"violence":1.1}}`,
		`{"flagged":null,"categories":[],"scores":{}}`,
		`{"flagged":true,"categories":[],"scores":{"violence":null}}`,
		`{"flagged":true,"categories":null,"scores":{}}`,
		`{"flagged":true,"categories":[],"scores":null}`,
		`{"categories":[],"scores":{}}`,
	} {
		_, err := parseGroupModerationResponse(response, "deepseek-chat")
		require.Error(t, err, response)
	}
}

func TestExtractGroupModerationJSONObjectIgnoresBracesInsideStrings(t *testing.T) {
	jsonObject, err := extractGroupModerationJSONObject(`prefix {"flagged":false,"categories":[],"scores":{},"note":"brace } in text"} suffix`)

	require.NoError(t, err)
	require.Equal(t, `{"flagged":false,"categories":[],"scores":{},"note":"brace } in text"}`, jsonObject)
}

func TestExtractGroupModerationJSONObjectRejectsMultipleObjects(t *testing.T) {
	_, err := extractGroupModerationJSONObject(`{"flagged":false,"categories":[],"scores":{}} then {"flagged":true}`)

	require.Error(t, err)
}
