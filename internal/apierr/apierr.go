// Package apierr is the one place an error becomes part of the contract.
//
// Codes are stable strings and are what clients branch on; messages are for humans and may change
// freely; the gRPC code and the HTTP status are both advisory mappings of the code, never the
// source of truth (see common.proto).
//
// The type carries a commonv1.Error as gRPC status details, so an error crossing a service boundary
// arrives with its code intact rather than flattened into a string a caller has to parse.
package apierr

import (
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "dariyanws/gen/dariya/common/v1"
)

// Stable codes. Adding one is a contract change; changing the spelling of one is a breaking change.
const (
	CodeValidation     = "ValidationException"
	CodeNotFound       = "ResourceNotFound"
	CodeAlreadyExists  = "ResourceAlreadyExists"
	CodeAccessDenied   = "AccessDenied"
	CodeThrottling     = "ThrottlingException"
	CodeInternal       = "InternalFailure"
	CodeInvalidSig     = "InvalidSignature"
	CodeSigExpired     = "SignatureExpired"
	CodeIdempotencyMis = "IdempotentParameterMismatch"
)

type Error struct {
	Code    string
	Message string

	// RequestID is stamped by the front door and filled in as the error passes outward. Empty here
	// is normal — the constructor rarely knows it.
	RequestID string

	// Details are only rendered to a caller under DARIYA_DEV=1. In production, explaining precisely
	// which check rejected a request describes the system to someone who failed it.
	Details map[string]string

	// Cause stays server-side. It is logged, never serialised.
	Cause error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// Proto renders the wire form. Details are included only when dev is true.
func (e *Error) Proto(dev bool) *commonv1.Error {
	pe := &commonv1.Error{Code: e.Code, Message: e.Message, RequestId: e.RequestID}
	if dev {
		pe.Details = e.Details
	}
	return pe
}

// GRPCStatus lets this type travel over gRPC with its code attached as details, rather than being
// reduced to a codes.Code that has far fewer values than the contract has error codes.
func (e *Error) GRPCStatus() *status.Status {
	st := status.New(e.grpcCode(), e.Message)
	if withDetails, err := st.WithDetails(e.Proto(false)); err == nil {
		return withDetails
	}
	return st
}

func (e *Error) grpcCode() codes.Code {
	switch e.Code {
	case CodeValidation, CodeIdempotencyMis:
		return codes.InvalidArgument
	case CodeNotFound:
		return codes.NotFound
	case CodeAlreadyExists:
		return codes.AlreadyExists
	case CodeAccessDenied:
		return codes.PermissionDenied
	case CodeThrottling:
		return codes.ResourceExhausted
	case CodeInvalidSig, CodeSigExpired:
		return codes.Unauthenticated
	default:
		return codes.Internal
	}
}

// HTTPStatus is the edge mapping. Advisory: clients branch on Code.
func (e *Error) HTTPStatus() int {
	switch e.Code {
	case CodeValidation, CodeIdempotencyMis:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeAlreadyExists:
		return http.StatusConflict
	case CodeAccessDenied:
		return http.StatusForbidden
	case CodeThrottling:
		return http.StatusTooManyRequests
	case CodeInvalidSig, CodeSigExpired:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func Validation(format string, args ...any) *Error {
	return &Error{Code: CodeValidation, Message: fmt.Sprintf(format, args...)}
}

func NotFound(format string, args ...any) *Error {
	return &Error{Code: CodeNotFound, Message: fmt.Sprintf(format, args...)}
}

func AlreadyExists(format string, args ...any) *Error {
	return &Error{Code: CodeAlreadyExists, Message: fmt.Sprintf(format, args...)}
}

// Internal wraps an unexpected failure. The cause is kept for logs and deliberately never reaches
// the caller — an internal error message is where table names and DSNs leak out.
func Internal(cause error, format string, args ...any) *Error {
	return &Error{Code: CodeInternal, Message: fmt.Sprintf(format, args...), Cause: cause}
}

// From extracts an *Error from any error, inventing an InternalFailure if there is none. Used at
// the boundary where an error becomes a response.
func From(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err, "internal failure")
}
