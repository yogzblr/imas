package jobs

import "time"

// testTenant is the tenant most tests record and read jobs in: the tenant
// of the connection RegisterNatsConn is called with in these tests.
const testTenant = "t_test"

// mustKey is jobKey for a key a test knows is valid.
func mustKey(tenantID, sproutID, jid, object string) string {
	key, err := jobKey(tenantID, sproutID, jid, object)
	if err != nil {
		panic(err)
	}
	return key
}

// tenantJobPrefix is jobs/<tenantID>/<sproutID>/<jid>/.
func tenantJobPrefix(tenantID, sproutID, jid string) string {
	return mustKey(tenantID, sproutID, jid, "")
}

// jobPrefix, createdKey, metaKey and eventKey name testTenant's keys for a
// job, as the listener writes them.
func jobPrefix(sproutID, jid string) string { return tenantJobPrefix(testTenant, sproutID, jid) }

func createdKey(sproutID, jid string) string {
	return mustKey(testTenant, sproutID, jid, createdObject)
}

func metaKey(sproutID, jid string) string { return mustKey(testTenant, sproutID, jid, metaObject) }

func eventKey(sproutID, jid string, at time.Time) string {
	return tenantEventKey(testTenant, sproutID, jid, at)
}

// tenantEventKey is eventKey in tenantID.
func tenantEventKey(tenantID, sproutID, jid string, at time.Time) string {
	key, err := jobRef{tenantID: tenantID, sproutID: sproutID, jid: jid}.eventKey(at)
	if err != nil {
		panic(err)
	}
	return key
}
