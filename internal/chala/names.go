package chala

import (
	"fmt"
	"regexp"
	"strings"

	"dariyanws/internal/apierr"
)

// Everything chala writes into Docker is derived here, from an account and an instance name, and
// nowhere else. A container's name, its labels, its network and its DNS alias all come from the
// same two values, so they cannot disagree about whose instance it is.

const (
	labelKind     = "dariya.chala"
	labelAccount  = "dariya.account"
	labelInstance = "dariya.instance"
	labelImage    = "dariya.image"
	labelTag      = "dariya.tag."

	kindInstance = "instance"
	kindNetwork  = "network"

	// DNSSuffix is the private zone every instance name lives under (DESIGN.md decision 13h).
	DNSSuffix = "chala.dariya.internal"

	maxTags        = 16
	maxTagValueLen = 255
)

var (
	// A DNS label, because the name becomes one.
	instanceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagKey       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
)

func validateName(name string) error {
	if !instanceName.MatchString(name) {
		return apierr.Validation(
			"an instance name is 1-63 of [a-z0-9-], not starting or ending with '-': %q", name)
	}
	return nil
}

func validateTags(tags map[string]string) error {
	if len(tags) > maxTags {
		return apierr.Validation("at most %d tags, got %d", maxTags, len(tags))
	}
	for k, v := range tags {
		if !tagKey.MatchString(k) {
			return apierr.Validation("a tag key is 1-63 of [A-Za-z0-9._-]: %q", k)
		}
		if len(v) > maxTagValueLen {
			return apierr.Validation("tag %q: a value is at most %d bytes", k, maxTagValueLen)
		}
	}
	return nil
}

// containerName is global on the daemon, so it carries the account. Two accounts may both have an
// instance called "web"; their containers cannot collide, and a lookup by name for one account
// cannot land on the other's.
func containerName(account, name string) string {
	return fmt.Sprintf("chala-%s-%s", account, name)
}

// NetworkName is the account's mini-VPC (DESIGN.md decision 13d).
func NetworkName(account string) string { return "dariya-acct-" + account }

// DNSName is the instance's stable name on its account network.
func DNSName(account, name string) string {
	return fmt.Sprintf("%s.%s.%s", name, account, DNSSuffix)
}

func ARN(region, account, name string) string {
	return fmt.Sprintf("arn:dariya:chala:%s:%s:instance/%s", region, account, name)
}

func instanceLabels(account, name, imageID string, tags map[string]string) map[string]string {
	labels := map[string]string{
		labelKind:     kindInstance,
		labelAccount:  account,
		labelInstance: name,
		labelImage:    imageID,
	}
	for k, v := range tags {
		labels[labelTag+k] = v
	}
	return labels
}

func tagsFrom(labels map[string]string) map[string]string {
	tags := map[string]string{}
	for k, v := range labels {
		if key, ok := strings.CutPrefix(k, labelTag); ok {
			tags[key] = v
		}
	}
	return tags
}

// accountFilter is the label filter every listing starts from. The account comes from a verified
// capability; there is no listing that is not scoped by it.
func accountFilter(account string) []string {
	return []string{labelKind + "=" + kindInstance, labelAccount + "=" + account}
}
