package service

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type contentModerationGroupCallerStub struct {
	responses []string
	count     int
}

func (s *contentModerationGroupCallerStub) AuditChat(context.Context, int64, string, string) (string, error) {
	response := s.responses[min(s.count, len(s.responses)-1)]
	s.count++
	return response, nil
}

func TestContentModerationGroupEngineUsesInjectedGroupCaller(t *testing.T) {
	groupID := int64(12)
	caller := &contentModerationGroupCallerStub{responses: []string{`{"flagged":true,"categories":["violence"],"scores":{"violence":0.99}}`}}
	service := &ContentModerationService{groupCaller: caller}

	result, err := service.callModeration(context.Background(), &ContentModerationConfig{
		Engine:    ContentModerationEngineGroup,
		GroupID:   &groupID,
		Model:     "deepseek-chat",
		TimeoutMS: 3000,
	}, "test prompt")

	require.NoError(t, err)
	require.Equal(t, 1, caller.count)
	require.Equal(t, 0.99, result.CategoryScores["violence"])
}

func TestContentModerationGroupSystemPromptRequiresClassificationOnly(t *testing.T) {
	prompt := contentModerationGroupSystemPrompt(false)
	require.Contains(t, prompt, "Do not refuse classification")
	require.Contains(t, prompt, "specific threat")
	require.Contains(t, prompt, "Return exactly one JSON object")
	require.Contains(t, contentModerationGroupSystemPrompt(true), "previous output violated this contract")
}

func TestContentModerationGroupEngineKeepsBlockedRetryBlocked(t *testing.T) {
	groupID := int64(12)
	var calls atomic.Int32
	caller := contentModerationGroupCallerFunc(func(context.Context, int64, string, string) (string, error) {
		if calls.Add(1) == 1 {
			return `{"flagged":true,"categories":["violence"],"scores":{"violence":0.99}}`, nil
		}
		return `{"flagged":false,"categories":[],"scores":{}}`, nil
	})
	hashCache := &contentModerationTestHashCache{}
	settings := &contentModerationTestSettingRepo{values: map[string]string{
		SettingKeyRiskControlEnabled: "true",
	}}
	cfg := &ContentModerationConfig{
		Engine:      ContentModerationEngineGroup,
		GroupID:     &groupID,
		Model:       "deepseek-chat",
		Enabled:     true,
		Mode:        ContentModerationModePreBlock,
		BlockStatus: 403,
		SampleRate:  100,
		RetryCount:  0,
		AllGroups:   true,
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	settings.values[SettingKeyContentModerationConfig] = string(raw)

	service := &ContentModerationService{
		settingRepo: settings,
		repo:        &contentModerationTestRepo{},
		hashCache:   hashCache,
		groupCaller: caller,
		asyncQueue:  make(chan contentModerationTask, 4),
	}
	body := []byte(`{"messages":[{"role":"user","content":"repeat blocked prompt"}]}`)
	input := ContentModerationCheckInput{Protocol: ContentModerationProtocolOpenAIChat, Body: body}

	first, err := service.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, first.Blocked)
	require.Equal(t, ContentModerationActionBlock, first.Action)
	require.Equal(t, int32(1), calls.Load())
	require.Len(t, service.asyncQueue, 1, "the first blocked request must create one audit record")

	second, err := service.Check(context.Background(), input)
	require.NoError(t, err)
	require.True(t, second.Blocked)
	require.Equal(t, ContentModerationActionHashBlock, second.Action)
	require.Equal(t, int32(1), calls.Load(), "an agent retry must not ask the model to reclassify an already blocked input")
	require.Len(t, service.asyncQueue, 1, "an agent retry must not enqueue another audit record")
}

func TestContentModerationGroupEngineHonorsTimeout(t *testing.T) {
	groupID := int64(12)
	service := &ContentModerationService{groupCaller: contentModerationGroupCallerFunc(func(ctx context.Context, _ int64, _, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})}

	_, err := service.callModeration(context.Background(), &ContentModerationConfig{
		Engine:     ContentModerationEngineGroup,
		GroupID:    &groupID,
		Model:      "deepseek-chat",
		TimeoutMS:  1,
		RetryCount: 0,
	}, "test prompt")

	require.ErrorIs(t, err, context.DeadlineExceeded)
}

type contentModerationGroupJSONRepairCallerStub struct {
	responses []string
	repairs   []bool
}

func (s *contentModerationGroupJSONRepairCallerStub) AuditChat(context.Context, int64, string, string) (string, error) {
	return s.responses[0], nil
}

func (s *contentModerationGroupJSONRepairCallerStub) AuditChatWithJSONRepair(_ context.Context, _ int64, _, _ string, repair bool) (string, error) {
	s.repairs = append(s.repairs, repair)
	response := s.responses[0]
	if repair && len(s.responses) > 1 {
		response = s.responses[1]
	}
	return response, nil
}

func TestContentModerationGroupEngineUsesJSONRepairPromptOnRetry(t *testing.T) {
	groupID := int64(12)
	caller := &contentModerationGroupJSONRepairCallerStub{responses: []string{
		`not json`,
		`{"flagged":false,"categories":[],"scores":{}}`,
	}}

	result, err := (&ContentModerationService{groupCaller: caller}).callModeration(context.Background(), &ContentModerationConfig{
		Engine:     ContentModerationEngineGroup,
		GroupID:    &groupID,
		Model:      "deepseek-chat",
		TimeoutMS:  3000,
		RetryCount: 1,
	}, "test prompt")

	require.NoError(t, err)
	require.False(t, result.Flagged)
	require.Equal(t, []bool{false, true}, caller.repairs)
}

type contentModerationGroupCallerFunc func(context.Context, int64, string, string) (string, error)

func (f contentModerationGroupCallerFunc) AuditChat(ctx context.Context, groupID int64, model, text string) (string, error) {
	return f(ctx, groupID, model, text)
}

type contentModerationGroupRepositoryStub struct {
	GroupRepository
}

func (contentModerationGroupRepositoryStub) GetByIDLite(context.Context, int64) (*Group, error) {
	return &Group{Status: StatusActive, Platform: PlatformDeepseek}, nil
}

func TestContentModerationGroupEngineConfigRoundTrip(t *testing.T) {
	repo := &contentModerationTestSettingRepo{values: map[string]string{}}
	service := NewContentModerationService(repo, nil, nil, contentModerationGroupRepositoryStub{}, nil, nil, nil, nil)
	engine := ContentModerationEngineGroup
	groupID := int64(12)
	model := "deepseek-chat"

	view, err := service.UpdateConfig(context.Background(), UpdateContentModerationConfigInput{
		Engine:  &engine,
		GroupID: &groupID,
		Model:   &model,
	})

	require.NoError(t, err)
	require.Equal(t, ContentModerationEngineGroup, view.Engine)
	require.Equal(t, &groupID, view.GroupID)
	require.Equal(t, model, view.Model)
	require.Equal(t, &groupID, view.EngineConfigs[ContentModerationEngineGroup].GroupID)
}
