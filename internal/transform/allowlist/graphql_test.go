package allowlist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestSelectedGraphQLOperation(t *testing.T) {
	tests := []struct {
		name          string
		document      string
		operationName string
		want          graphqlOperation
		wantOK        bool
	}{
		{
			name:     "anonymous query",
			document: `{ viewer { id } }`,
			want:     graphqlQuery,
			wantOK:   true,
		},
		{
			name:          "named query selected from multiple operations",
			document:      `query Read { viewer { id } } mutation Write { updateViewer { id } }`,
			operationName: "Read",
			want:          graphqlQuery,
			wantOK:        true,
		},
		{
			name:          "named mutation selected from multiple operations",
			document:      `query Read { viewer { id } } mutation Write { updateViewer { id } }`,
			operationName: "Write",
			want:          graphqlMutation,
			wantOK:        true,
		},
		{
			name:     "subscription",
			document: `subscription Events { eventAdded { id } }`,
			want:     graphqlSubscription,
			wantOK:   true,
		},
		{
			name:     "fragment does not affect operation type",
			document: `query Read { viewer { ...ViewerFields } } fragment ViewerFields on Viewer { id }`,
			want:     graphqlQuery,
			wantOK:   true,
		},
		{
			name:     "multiple operations need a selection",
			document: `query Read { viewer { id } } mutation Write { updateViewer { id } }`,
		},
		{
			name:          "unknown operation name",
			document:      `query Read { viewer { id } }`,
			operationName: "Missing",
		},
		{
			name:          "duplicate operation name is ambiguous",
			document:      `query Same { viewer { id } } mutation Same { updateViewer { id } }`,
			operationName: "Same",
		},
		{
			name:     "malformed document",
			document: `query Read {`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selectedGraphQLOperation(tc.document, tc.operationName)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAllowlist_GraphQLOperations(t *testing.T) {
	queryOnly, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			Methods:           []string{http.MethodPost},
			Paths:             []string{"/graphql"},
			GraphQLOperations: []string{"query"},
		}},
	})
	require.NoError(t, err)

	documentWithMultipleOperations := `query Read { viewer { id } } mutation Write { updateViewer { id } }`
	tests := []struct {
		name        string
		body        string
		contentType string
		want        transform.TransformAction
	}{
		{
			name:        "anonymous query allowed",
			body:        `{"query":"{ viewer { id } }"}`,
			contentType: "application/json",
			want:        transform.ActionContinue,
		},
		{
			name:        "query content type parameters allowed",
			body:        `{"query":"query Read { viewer { id } }"}`,
			contentType: "application/json; charset=utf-8",
			want:        transform.ActionContinue,
		},
		{
			name:        "mutation rejected",
			body:        `{"query":"mutation Write { updateViewer { id } }"}`,
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "subscription rejected",
			body:        `{"query":"subscription Events { eventAdded { id } }"}`,
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "selected query allowed",
			body:        fmt.Sprintf(`{"query":%q,"operationName":"Read"}`, documentWithMultipleOperations),
			contentType: "application/json",
			want:        transform.ActionContinue,
		},
		{
			name:        "selected mutation rejected",
			body:        fmt.Sprintf(`{"query":%q,"operationName":"Write"}`, documentWithMultipleOperations),
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "ambiguous document rejected",
			body:        fmt.Sprintf(`{"query":%q}`, documentWithMultipleOperations),
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "malformed JSON rejected",
			body:        `{"query":`,
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "duplicate JSON field rejected",
			body:        `{"query":"mutation Write { updateViewer { id } }","query":"{ viewer { id } }"}`,
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name:        "persisted operation without document rejected",
			body:        `{"extensions":{"persistedQuery":{"sha256Hash":"abc"}}}`,
			contentType: "application/json",
			want:        transform.ActionReject,
		},
		{
			name: "missing content type rejected",
			body: `{"query":"{ viewer { id } }"}`,
			want: transform.ActionReject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(tc.body))
			req.Host = "api.example.com"
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			result, err := queryOnly.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
		})
	}
}

func TestAllowlist_GraphQLOperationsRequireCompleteBufferedBody(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			GraphQLOperations: []string{"query"},
		}},
	})
	require.NoError(t, err)

	body := `{"query":"query Read { viewer { id } }"}`
	tests := []struct {
		name     string
		maxBytes int64
		want     transform.TransformAction
	}{
		{
			name:     "complete document allowed",
			maxBytes: int64(len(body)),
			want:     transform.ActionContinue,
		},
		{
			name:     "truncated document rejected",
			maxBytes: int64(len(body) - 1),
			want:     transform.ActionReject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(body))
			req.Host = "api.example.com"
			req.Header.Set("Content-Type", "application/json")
			req.Body = transform.NewBufferedBody(req.Body, tc.maxBytes)

			result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
		})
	}
}

func TestAllowlist_GraphQLOperationsGET(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			Methods:           []string{http.MethodGet},
			Paths:             []string{"/graphql"},
			GraphQLOperations: []string{"query"},
		}},
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		url  string
		want transform.TransformAction
	}{
		{
			name: "query allowed",
			url:  "https://api.example.com/graphql?query=" + url.QueryEscape(`query Read { viewer { id } }`),
			want: transform.ActionContinue,
		},
		{
			name: "mutation rejected",
			url:  "https://api.example.com/graphql?query=" + url.QueryEscape(`mutation Write { updateViewer { id } }`),
			want: transform.ActionReject,
		},
		{
			name: "duplicate query parameter rejected",
			url:  "https://api.example.com/graphql?query=%7Bviewer%7D&query=%7Bother%7D",
			want: transform.ActionReject,
		},
		{
			name: "malformed query string rejected",
			url: "https://api.example.com/graphql?query=" +
				url.QueryEscape(`query Read { viewer { id } }`) +
				"&ignored=x;query=" +
				url.QueryEscape(`mutation Write { updateViewer { id } }`),
			want: transform.ActionReject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Host = "api.example.com"

			result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
		})
	}
}

func TestAllowlist_GraphQLOperationsTunnelHandshake(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			Methods:           []string{http.MethodGet, http.MethodPost},
			Paths:             []string{"/graphql"},
			GraphQLOperations: []string{"query"},
		}},
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		host      string
		mode      transform.Mode
		handshake bool
		want      transform.TransformAction
	}{
		{
			name:      "matching MITM tunnel admitted by host",
			host:      "api.example.com:443",
			mode:      transform.ModeMITM,
			handshake: true,
			want:      transform.ActionContinue,
		},
		{
			name:      "SNI-only tunnel cannot enforce GraphQL restriction",
			host:      "api.example.com:443",
			mode:      transform.ModeSNIOnly,
			handshake: true,
			want:      transform.ActionReject,
		},
		{
			name:      "unmatched MITM tunnel rejected",
			host:      "other.example.com:443",
			mode:      transform.ModeMITM,
			handshake: true,
			want:      transform.ActionReject,
		},
		{
			name: "ordinary CONNECT request is not a tunnel handshake",
			host: "api.example.com:443",
			mode: transform.ModeMITM,
			want: transform.ActionReject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "https://"+tc.host, nil)
			req.Host = tc.host
			result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{
				Mode:            tc.mode,
				TunnelHandshake: tc.handshake,
			}, req)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Action)
		})
	}
}

func TestAllowlist_AllGraphQLOperationTypesCanBeAllowed(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			GraphQLOperations: []string{"Query", "Mutation", "Subscription"},
		}},
	})
	require.NoError(t, err)

	documents := []string{
		`query Read { viewer { id } }`,
		`mutation Write { updateViewer { id } }`,
		`subscription Events { eventAdded { id } }`,
	}
	for _, document := range documents {
		body := fmt.Sprintf(`{"query":%q}`, document)
		req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(body))
		req.Host = "api.example.com"
		req.Header.Set("Content-Type", "application/json")

		result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{}, req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, result.Action)
	}
}

func TestAllowlist_GraphQLOperationsDecodeFromYAML(t *testing.T) {
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`
rules:
  - host: api.example.com
    methods: [POST]
    paths: [/graphql]
    graphql_operations: [query]
`), &node))

	transformer, err := factory(node, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(`{"query":"mutation Write { updateViewer { id } }"}`))
	req.Host = "api.example.com"
	req.Header.Set("Content-Type", "application/json")
	result, err := transformer.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
}

func TestAllowlist_EmptyGraphQLOperationsDeniesAll(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			GraphQLOperations: []string{},
		}},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(`{"query":"{ viewer { id } }"}`))
	req.Host = "api.example.com"
	req.Header.Set("Content-Type", "application/json")
	result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
}

func TestAllowlist_UnrestrictedRuleDoesNotParseGraphQL(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{
			{Host: "api.example.com", GraphQLOperations: []string{"query"}},
			{Host: "api.example.com"},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", io.NopCloser(errorReader{}))
	req.Host = "api.example.com"
	req.Header.Set("Content-Type", "application/json")
	result, err := allowlist.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
}

func TestAllowlist_InvalidGraphQLOperation(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			GraphQLOperations: []string{"execute"},
		}},
	})
	require.ErrorContains(t, err, `invalid GraphQL operation "execute"`)
}

func TestAllowlist_GraphQLBodyRemainsAvailableToNextTransform(t *testing.T) {
	allowlist, err := newFromConfig(allowlistConfig{
		Rules: []allowlistRuleConfig{{
			Host:              "api.example.com",
			GraphQLOperations: []string{"query"},
		}},
	})
	require.NoError(t, err)

	body := `{"query":"{ viewer { id } }"}`
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/graphql", strings.NewReader(body))
	req.Host = "api.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Body = transform.NewBufferedBody(req.Body, 1<<20)
	pipeline := transform.NewPipeline([]transform.Transformer{allowlist}, transform.BodyLimits{}, nil)

	var traces []transform.TransformTrace
	response, err := pipeline.ProcessRequest(context.Background(), &transform.TransformContext{}, req, &traces)
	require.NoError(t, err)
	require.Nil(t, response)
	restored, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(restored))
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, fmt.Errorf("unexpected read") }
