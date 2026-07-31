package allowlist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

type graphqlOperation string

const (
	graphqlQuery        graphqlOperation = "query"
	graphqlMutation     graphqlOperation = "mutation"
	graphqlSubscription graphqlOperation = "subscription"
)

func compileGraphQLOperations(configured []string, ruleIndex int) (map[graphqlOperation]bool, error) {
	if configured == nil {
		return nil, nil
	}

	operations := make(map[graphqlOperation]bool, len(configured))
	for _, configuredOperation := range configured {
		operation := graphqlOperation(strings.ToLower(configuredOperation))
		switch operation {
		case graphqlQuery, graphqlMutation, graphqlSubscription:
			operations[operation] = true
		default:
			return nil, fmt.Errorf(
				"allowlist: rules[%d]: invalid GraphQL operation %q (must be query, mutation, or subscription)",
				ruleIndex,
				configuredOperation,
			)
		}
	}
	return operations, nil
}

func (r *rule) allowsGraphQLOperation(requested graphqlOperation) bool {
	return r.graphqlOperations[requested]
}

// requestGraphQLOperation returns the operation selected by a standard
// GraphQL-over-HTTP GET or JSON POST request. classified is false when the
// request is malformed, uses an unsupported encoding, or does not identify a
// single operation; a restricted allowlist rule must fail closed in those cases.
func requestGraphQLOperation(req *http.Request) (graphqlOperation, bool, error) {
	var document, operationName string

	switch req.Method {
	case http.MethodGet:
		queryValues, ok := req.URL.Query()["query"]
		if !ok || len(queryValues) != 1 {
			return "", false, nil
		}
		document = queryValues[0]

		operationNames := req.URL.Query()["operationName"]
		if len(operationNames) > 1 {
			return "", false, nil
		}
		if len(operationNames) == 1 {
			operationName = operationNames[0]
		}

	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			return "", false, nil
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			return "", false, fmt.Errorf("reading GraphQL request body: %w", err)
		}
		var ok bool
		document, operationName, ok = decodeGraphQLJSONRequest(body)
		if !ok {
			return "", false, nil
		}

	default:
		return "", false, nil
	}

	operation, ok := selectedGraphQLOperation(document, operationName)
	if !ok {
		return "", false, nil
	}
	return operation, true, nil
}

func decodeGraphQLJSONRequest(body []byte) (document, operationName string, ok bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return "", "", false
	}

	seen := make(map[string]bool)
	hasDocument := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return "", "", false
		}
		name, isString := key.(string)
		if !isString || seen[name] {
			return "", "", false
		}
		seen[name] = true

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", "", false
		}
		switch name {
		case "query":
			if err := json.Unmarshal(value, &document); err != nil {
				return "", "", false
			}
			hasDocument = true
		case "operationName":
			if string(value) != "null" {
				if err := json.Unmarshal(value, &operationName); err != nil {
					return "", "", false
				}
			}
		}
	}

	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || !hasDocument {
		return "", "", false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return "", "", false
	}
	return document, operationName, true
}

func selectedGraphQLOperation(document, operationName string) (graphqlOperation, bool) {
	doc, err := parser.ParseQuery(&ast.Source{Input: document})
	if err != nil {
		return "", false
	}

	var selected *ast.OperationDefinition
	if operationName == "" {
		if len(doc.Operations) != 1 {
			return "", false
		}
		selected = doc.Operations[0]
	} else {
		for _, operation := range doc.Operations {
			if operation.Name != operationName {
				continue
			}
			if selected != nil {
				return "", false
			}
			selected = operation
		}
		if selected == nil {
			return "", false
		}
	}

	switch selected.Operation {
	case ast.Query:
		return graphqlQuery, true
	case ast.Mutation:
		return graphqlMutation, true
	case ast.Subscription:
		return graphqlSubscription, true
	default:
		return "", false
	}
}
