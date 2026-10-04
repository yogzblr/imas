package pki

// The sealed wire of internal.* (docs/design/imas-payload-encryption-design.md,
// Decision B, J.4): for each SaaS API <-> farmer subject, the purpose and
// method its payloadbox Call or Reply is bound to. Both ends derive them
// from here, from the subject a message arrived on (farmer) or is sent on
// (the SaaS API), so the two can't drift apart. FLAG FOR SECURITY REVIEW.
//
// Every a2f/f2a message is sealed between the SaaS API's box key and the
// platform key (platformbox.go, saasapibox.go), with Message.TenantID
// payloadbox.PlatformTenantID and Message.SproutID
// payloadbox.PrincipalSaaSAPI. The tenant a message concerns travels
// inside the box, in its params or result, so it is authenticated with
// everything else; each end checks it against its own record (farmer at
// the point of effect, the SaaS API against the job or batch it sent).

import (
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// SaaSAPISubjectPrefix is the prefix of every SaaS API <-> farmer subject.
// A message's method is its subject without it.
const SaaSAPISubjectPrefix = "internal."

// SaaSAPIWire is what one internal.* message is sealed to: its purpose,
// its method and its full subject.
type SaaSAPIWire struct {
	Purpose string
	Method  string
	Subject string
}

// saasapiRequestPurposes maps each SaaS API request subject to its
// purpose. Nothing else is a SaaS API request.
var saasapiRequestPurposes = map[string]string{
	controlplane.SubjectTenantProvision:   payloadbox.PurposeSaaSTenantProvision,
	controlplane.SubjectTenantDeprovision: payloadbox.PurposeSaaSTenantDeprovision,
	controlplane.SubjectSproutAction:      payloadbox.PurposeSaaSSproutAction,
}

// SaaSAPIRequestWire is the wire of a SaaS API request on subject; false
// for a subject that isn't one.
func SaaSAPIRequestWire(subject string) (SaaSAPIWire, bool) {
	purpose, ok := saasapiRequestPurposes[subject]
	if !ok {
		return SaaSAPIWire{}, false
	}
	return SaaSAPIWire{Purpose: purpose, Method: strings.TrimPrefix(subject, SaaSAPISubjectPrefix), Subject: subject}, true
}

// SproutActionReplyWire is the wire of farmer's reply to
// internal.sprout.action: f2a.sprout.action, bound by ReplyTo to the
// request's ID, with the request's method and subject.
func SproutActionReplyWire() SaaSAPIWire {
	return SaaSAPIWire{
		Purpose: payloadbox.PurposeSaaSSproutActionReply,
		Method:  strings.TrimPrefix(controlplane.SubjectSproutAction, SaaSAPISubjectPrefix),
		Subject: controlplane.SubjectSproutAction,
	}
}

// TenantResultWire is the wire of farmer's asynchronous provisioning
// result for jobID: f2a.tenant.provisioned on
// internal.tenant.provisioned.<job_id>, or the deprovisioned pair. The
// subject names the job, so a result sealed for one job doesn't open on
// another's subject. jobID must be a valid job ID
// (controlplane.ValidJobID): it becomes a subject token.
func TenantResultWire(deprovision bool, jobID string) (SaaSAPIWire, error) {
	if !controlplane.ValidJobID(jobID) {
		return SaaSAPIWire{}, fmt.Errorf("pki: invalid job id %q", jobID)
	}
	purpose, prefix := payloadbox.PurposeSaaSTenantProvisioned, controlplane.SubjectTenantProvisionedPrefix
	if deprovision {
		purpose, prefix = payloadbox.PurposeSaaSTenantDeprovisioned, controlplane.SubjectTenantDeprovisionedPrefix
	}
	return SaaSAPIWire{
		Purpose: purpose,
		Method:  strings.TrimSuffix(strings.TrimPrefix(prefix, SaaSAPISubjectPrefix), "."),
		Subject: prefix + jobID,
	}, nil
}
