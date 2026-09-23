// Package iam evaluates policy: given a verified caller, an action and a resource, may it proceed?
//
// The evaluation engine is pure — no database, no network, no clock. Everything that decides an
// authorisation outcome is an argument to Evaluate, which is what makes the rules testable as
// rules rather than as integration behaviour. Storage is a separate concern (M3.2) and so is the
// RPC (M3.3).
//
// # The rules, and why they are these rules
//
// Three, in order, copied from IAM because they are the part of IAM that is actually load-bearing:
//
//  1. An explicit Deny always wins, whatever else matched.
//  2. Otherwise an Allow that matched wins.
//  3. Otherwise the answer is no.
//
// Rule 3 is the one that matters most and is the easiest to get backwards. The default is deny, so
// a new account can do nothing at all until something says otherwise, and a policy that fails to
// load denies rather than opens. Rule 1 exists so that a broad Allow can be carved into without
// rewriting it — and so that a deny can be relied upon, which an "allow wins" system cannot offer.
package iam

import (
	"strconv"
	"strings"

	iamv1 "dariyanws/gen/dariya/iam/v1"
)

// Request is what is being attempted. Concrete: no wildcards.
//
// Wildcards are something policies contain, never something requests contain. If a request could
// carry one, "may I do anything to everything?" becomes a question the engine has to answer, and
// the answer would be yes for any principal holding a broad allow.
type Request struct {
	// Service-qualified, exactly as written in policy: "func:Invoke", "kyu:SendMessage".
	Action string

	// The specific resource, fully qualified.
	ResourceARN string
}

// Decision is the outcome plus enough to explain it.
type Decision struct {
	Effect iamv1.Decision

	// Which statement decided. Empty on an implicit deny, because nothing did — and that
	// emptiness is itself the diagnosis: "no policy mentions this" rather than "a policy said no".
	PolicyARN string
	SID       string
}

// Allowed is the only question most callers have.
func (d Decision) Allowed() bool { return d.Effect == iamv1.Decision_DECISION_ALLOW }

// AttachedPolicy is a policy bound to the principal being evaluated.
type AttachedPolicy struct {
	PolicyARN string
	Document  *iamv1.PolicyDocument
}

// Evaluate applies the three rules.
//
// Deny is searched for across every policy before any allow is honoured, rather than short-
// circuiting on the first allow found. That costs a full pass and is not an optimisation worth
// making: stopping early at an allow would make the outcome depend on the order policies happened
// to come back from the database, which is the kind of bug that appears once in production and
// never in a test.
func Evaluate(policies []AttachedPolicy, req Request) Decision {
	var allow *Decision

	for _, policy := range policies {
		for _, statement := range policy.Document.GetStatements() {
			if !matches(statement, req) {
				continue
			}

			switch statement.GetEffect() {
			case iamv1.Effect_EFFECT_DENY:
				// Wins immediately. Nothing later can overturn it, so there is nothing to gain
				// by continuing.
				return Decision{
					Effect:    iamv1.Decision_DECISION_EXPLICIT_DENY,
					PolicyARN: policy.PolicyARN,
					SID:       statement.GetSid(),
				}

			case iamv1.Effect_EFFECT_ALLOW:
				if allow == nil {
					allow = &Decision{
						Effect:    iamv1.Decision_DECISION_ALLOW,
						PolicyARN: policy.PolicyARN,
						SID:       statement.GetSid(),
					}
				}

			default:
				// EFFECT_UNSPECIFIED. A statement with no effect is not an allow — a proto3 zero
				// value must never be the permissive answer, or a field a client forgot to set
				// grants access.
			}
		}
	}

	if allow != nil {
		return *allow
	}
	return Decision{Effect: iamv1.Decision_DECISION_IMPLICIT_DENY}
}

func matches(statement *iamv1.Statement, req Request) bool {
	return matchesAny(statement.GetActions(), req.Action) &&
		matchesAny(statement.GetResources(), req.ResourceARN)
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if Match(pattern, value) {
			return true
		}
	}
	return false
}

// Match applies the pattern language: an exact string, or a prefix ending in "*".
//
// Deliberately smaller than IAM's, which allows "*" and "?" anywhere. The interesting part of
// authorisation is the evaluation order, not the glob syntax, and a richer matcher is mostly a
// source of policies that are hard to read and accidentally broad. "kyu:*" and
// "arn:dariya:func:hind-1:000000000001:function/*" cover what this cloud can express.
//
// A "*" appearing anywhere other than the end is treated as a literal rather than silently
// ignored. Matching it loosely would make a policy author's typo quietly permissive; matching it
// literally makes it quietly restrictive, and between two failure modes the safe one is preferred.
func Match(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

// ValidateDocument rejects a policy that cannot mean anything, at write time rather than at
// evaluation time.
//
// A statement with no actions or no resources can never match, so it is dead weight that reads
// like a grant — the kind of thing found during an incident, believed to be doing something. An
// unspecified effect is worse: it looks like a rule and denies nothing and allows nothing.
func ValidateDocument(doc *iamv1.PolicyDocument) error {
	if doc == nil {
		return &ValidationError{Reason: "a policy document is required"}
	}
	if len(doc.GetStatements()) == 0 {
		return &ValidationError{Reason: "a policy must have at least one statement"}
	}

	for i, s := range doc.GetStatements() {
		switch {
		case s.GetEffect() == iamv1.Effect_EFFECT_UNSPECIFIED:
			return &ValidationError{Index: i, Reason: "effect must be ALLOW or DENY"}
		case len(s.GetActions()) == 0:
			return &ValidationError{Index: i, Reason: "at least one action is required"}
		case len(s.GetResources()) == 0:
			return &ValidationError{Index: i, Reason: "at least one resource is required"}
		}
		for _, a := range s.GetActions() {
			if a == "" {
				return &ValidationError{Index: i, Reason: "an action must not be empty"}
			}
		}
		for _, r := range s.GetResources() {
			if r == "" {
				return &ValidationError{Index: i, Reason: "a resource must not be empty"}
			}
		}
	}
	return nil
}

// ValidationError names which statement was wrong, since a policy with eight of them is otherwise
// a guessing game.
type ValidationError struct {
	Index  int
	Reason string
}

func (e *ValidationError) Error() string {
	return "policy statement " + strconv.Itoa(e.Index) + ": " + e.Reason
}
