# problem

The canonical [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) ("Problem
Details for HTTP APIs") error body.

```go
type Details struct {
	Type     string `json:"type,omitempty"`     // URI reference identifying the problem type
	Title    string `json:"title,omitempty"`    // short, human-readable summary
	Status   int    `json:"status,omitempty"`   // HTTP status code
	Detail   string `json:"detail,omitempty"`   // human-readable explanation for this occurrence
	Instance string `json:"instance,omitempty"` // URI reference identifying this occurrence
}
```

`Details` implements `error` (via `Error() string`, preferring `Detail`, then
`Title`), so it can be returned/wrapped as a normal Go error, e.g. from a PEP
middleware's 403 response body.

## Usage

```go
return problem.Details{
	Title:  "Forbidden",
	Status: http.StatusForbidden,
	Detail: "principal is not permitted to perform this action",
}
```
