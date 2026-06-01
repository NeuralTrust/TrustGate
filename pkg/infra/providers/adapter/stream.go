package adapter

// SSEEvent builds the standard SSE lines for one event:
//
//	event: <eventType>
//	data: <dataJSON>
//	<empty line>
//
// The caller writes each element followed by "\n".
func SSEEvent(eventType string, dataJSON []byte) [][]byte {
	return [][]byte{
		[]byte("event: " + eventType),
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}

// SSEData builds a single "data: …" line followed by an empty separator.
// This is the format used by providers that do not emit "event:" lines
// (e.g. OpenAI, Azure).
func SSEData(dataJSON []byte) [][]byte {
	return [][]byte{
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}
