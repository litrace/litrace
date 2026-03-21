// SPDX-License-Identifier: GPL-2.0-or-later

package tests

import "testing"

func TestReadWrite(t *testing.T) {
	runSimpleFixtureMatch(t, "read-write", "trace=read,write", "-P", "/tmp/litrace-read-write.sample")
}
