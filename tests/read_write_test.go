package tests

import "testing"

func TestReadWrite(t *testing.T) {
	runSimpleFixtureMatch(t, "read-write", "trace=read,write", "-P", "/tmp/litrace-read-write.sample")
}
