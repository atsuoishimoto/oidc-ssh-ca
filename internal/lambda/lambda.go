// Package lambda exposes the signing pipeline as an AWS Lambda Function
// URL handler. No HTTP server is started: the Function URL event is
// translated directly into a server.Sign call, so the wire format
// (Authorization: Bearer + JSON public_key, certificate as text/plain)
// is identical to the standalone server.
package lambda

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/server"
)

// Handler adapts a Server to Lambda Function URL events.
func Handler(srv *server.Server) func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	return func(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
		// A decode failure leaves body nil, which Sign denies as a bad
		// request (it is not valid JSON).
		var body []byte
		if req.IsBase64Encoded {
			body, _ = base64.StdEncoding.DecodeString(req.Body)
		} else {
			body = []byte(req.Body)
		}

		// Function URL events lowercase all header names.
		auth := req.Headers["authorization"]
		if auth == "" {
			auth = req.Headers["Authorization"]
		}

		resp := srv.Sign(ctx, req.RequestContext.HTTP.Method, auth, body)
		return events.LambdaFunctionURLResponse{
			StatusCode: resp.Status,
			Headers: map[string]string{
				"Content-Type": resp.ContentType,
				"X-Request-Id": resp.RequestID,
			},
			Body: string(resp.Body),
		}, nil
	}
}

// Start runs the Lambda runtime loop with the Function URL handler.
// It never returns.
func Start(srv *server.Server) {
	awslambda.Start(Handler(srv))
}
