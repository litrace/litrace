// SPDX-License-Identifier: GPL-2.0-only

package trace

func eventTracePathAt(ev Event, argIndex int) (string, bool) {
	desc, ok := findVarArgDesc(ev, argIndex)
	if !ok {
		return "", false
	}
	if desc.Flags != varFlagNone {
		return "", false
	}

	payload, ok := varPayloadSlice(ev, desc)
	if !ok {
		return "", false
	}

	return string(payload), true
}
