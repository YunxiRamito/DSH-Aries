package client

import (
	"context"
	"encoding/json"
	"net/url"
)

type CommandField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

type CommandDefinition struct {
	Path       string         `json:"path"`
	Summary    string         `json:"summary"`
	Usage      string         `json:"usage"`
	Arguments  []CommandField `json:"arguments,omitempty"`
	Flags      []CommandField `json:"flags,omitempty"`
	Permission string         `json:"permission"`
	Examples   []string       `json:"examples,omitempty"`
	LocalOnly  bool           `json:"local_only,omitempty"`
}

type Registry struct {
	APIVersion string              `json:"api_version"`
	Items      []CommandDefinition `json:"items"`
}

type CommandRequest struct {
	Argv  []string                   `json:"argv"`
	Flags map[string]json.RawMessage `json:"flags,omitempty"`
}

type Candidate struct {
	Value       string `json:"value"`
	Display     string `json:"display"`
	Description string `json:"description"`
}

func (c *Client) Commands(ctx context.Context) (Registry, error) {
	var registry Registry
	b, err := c.Get(ctx, "/api/v1/admin/commands")
	if err != nil {
		return registry, err
	}
	err = json.Unmarshal(b, &registry)
	return registry, err
}

func (c *Client) CommandHelp(ctx context.Context, path string) (CommandDefinition, error) {
	var result struct {
		Command CommandDefinition `json:"command"`
	}
	b, err := c.Get(ctx, "/api/v1/admin/commands/help?path="+url.QueryEscape(path))
	if err != nil {
		return result.Command, err
	}
	err = json.Unmarshal(b, &result)
	return result.Command, err
}

func (c *Client) Complete(ctx context.Context, words []string, cursor int) ([]Candidate, error) {
	var result struct {
		Candidates []Candidate `json:"candidates"`
	}
	body, err := json.Marshal(struct {
		Words  []string `json:"words"`
		Cursor int      `json:"cursor_position"`
	}{words, cursor})
	if err != nil {
		return nil, err
	}
	b, err := c.Post(ctx, "/api/v1/admin/commands/complete", body, "")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &result)
	return result.Candidates, err
}

func (c *Client) Execute(ctx context.Context, request CommandRequest, idempotencyKey string) (json.RawMessage, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return c.Post(ctx, "/api/v1/admin/commands/execute", body, idempotencyKey)
}
