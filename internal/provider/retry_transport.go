// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"google.golang.org/api/googleapi"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

const defaultRetryTransportTimeoutSec = 90

type retryTransport struct {
	retryPredicates []RetryErrorPredicateFunc
	internal        http.RoundTripper
}

// NewTransportWithDefaultRetries constructs a default retryTransport that will retry common temporary errors
func NewTransportWithDefaultRetries(t http.RoundTripper) *retryTransport {
	return &retryTransport{
		retryPredicates: defaultErrorRetryPredicates,
		internal:        t,
	}
}

// RoundTrip implements the RoundTripper interface method.
// It retries the given HTTP request based on the retry predicates
// registered under the retryTransport.
func (t *retryTransport) RoundTrip(req *http.Request) (resp *http.Response, respErr error) {
	// Set timeout to default value.
	ctx := req.Context()
	var ccancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, ccancel = context.WithTimeout(ctx, defaultRetryTransportTimeoutSec*time.Second)
		defer func() {
			if ctx.Err() == nil {
				// Cleanup child context created for retry loop if ctx not done.
				ccancel()
			}
		}()
	}

	attempts := 0
	backoff := time.Millisecond * 500
	nextBackoff := time.Millisecond * 500

	// VCR depends on the original request body being consumed, so
	// consume here. Since this won't affect the request itself,
	// we do this before the actual Retry loop so we can consume the request Body as needed
	// e.g. if the request couldn't be retried, we use the original request
	if _, err := httputil.DumpRequestOut(req, true); err != nil {
		log.Printf("[WARN] Retry Transport: Consuming original request body failed: %v", err)
	}

	log.Printf("[DEBUG] Retry Transport: starting RoundTrip retry loop")
Retry:
	for {
		// RoundTrip contract says request body can/will be consumed, so we need to
		// copy the request body for each attempt.
		// If we can't copy the request, we run as a single request.
		newRequest, copyErr := copyHttpRequest(req)
		if copyErr != nil {
			log.Printf("[WARN] Retry Transport: Unable to copy request body: %v.", copyErr)
			log.Printf("[WARN] Retry Transport: Running request as non-retryable")
			resp, respErr = t.internal.RoundTrip(req)
			break Retry
		}

		log.Printf("[DEBUG] Retry Transport: request attempt %d", attempts)
		// Do the wrapped Roundtrip. This is one request in the retry loop.
		resp, respErr = t.internal.RoundTrip(newRequest)
		attempts++

		retryErr := t.checkForRetryableError(resp, respErr)
		if retryErr == nil {
			log.Printf("[DEBUG] Retry Transport: Stopping retries, last request was successful")
			break Retry
		}
		if !retryErr.Retryable {
			log.Printf("[DEBUG] Retry Transport: Stopping retries, last request failed with non-retryable error: %s", retryErr.Err)
			break Retry
		}

		log.Printf("[DEBUG] Retry Transport: Waiting %s before trying request again", backoff)
		select {
		case <-ctx.Done():
			log.Printf("[DEBUG] Retry Transport: Stopping retries, context done: %v", ctx.Err())
			break Retry
		case <-time.After(backoff):
			log.Printf("[DEBUG] Retry Transport: Finished waiting %s before next retry", backoff)

			// Fibonnaci backoff - 0.5, 1, 1.5, 2.5, 4, 6.5, 10.5, ...
			lastBackoff := backoff
			backoff = backoff + nextBackoff
			nextBackoff = lastBackoff
			continue
		}
	}
	log.Printf("[DEBUG] Retry Transport: Returning after %d attempts", attempts)
	return resp, respErr
}

// checkForRetryableError uses the googleapi.CheckResponse util to check for
// errors in the response, and determines whether there is a retryable error.
// in response/response error.
func (t *retryTransport) checkForRetryableError(resp *http.Response, respErr error) *resource.RetryError {
	var errToCheck error

	if respErr != nil {
		errToCheck = respErr
	} else {
		respToCheck := *resp
		// The RoundTrip contract states that the HTTP response/response error
		// returned cannot be edited. We need to consume the Body to check for
		// errors, so we need to create a copy if the Response has a body.
		if resp.Body != nil && resp.Body != http.NoBody {
			// Use httputil.DumpResponse since the only important info is
			// error code and messages in the response body.
			dumpBytes, err := httputil.DumpResponse(resp, true)
			if err != nil {
				return resource.NonRetryableError(fmt.Errorf("unable to check response for error: %v", err))
			}
			respToCheck.Body = ioutil.NopCloser(bytes.NewReader(dumpBytes))
		}
		errToCheck = googleapi.CheckResponse(&respToCheck)
	}

	if errToCheck == nil {
		return nil
	}
	if isRetryableError(errToCheck, t.retryPredicates...) {
		return resource.RetryableError(errToCheck)
	}
	return resource.NonRetryableError(errToCheck)
}

// copyHttpRequest provides an copy of the given HTTP request for one RoundTrip.
// If the request has a non-empty body (io.ReadCloser), the body is deep copied
// so it can be consumed.
func copyHttpRequest(req *http.Request) (*http.Request, error) {
	newRequest := *req
	if req.Body == nil || req.Body == http.NoBody {
		return &newRequest, nil
	}
	// Helpers like http.NewRequest add a GetBody for copying.
	// If not given, we should reject the request.
	if req.GetBody == nil {
		return nil, errors.New("request.GetBody is not defined for non-empty Body")
	}

	bd, err := req.GetBody()
	if err != nil {
		return nil, err
	}

	newRequest.Body = bd
	return &newRequest, nil
}
