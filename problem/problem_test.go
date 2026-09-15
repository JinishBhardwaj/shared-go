package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetails_Error(t *testing.T) {
	tests := []struct {
		name string
		d    Details
		want string
	}{
		{
			name: "detail present",
			d:    Details{Title: "Not Found", Detail: "domain xyz not found"},
			want: "domain xyz not found",
		},
		{
			name: "title only",
			d:    Details{Title: "Not Found"},
			want: "Not Found",
		},
		{
			name: "empty",
			d:    Details{},
			want: "problem details error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetails_ImplementsError(t *testing.T) {
	var _ error = Details{}
}

func TestDetails_MarshalJSON_Extensions(t *testing.T) {
	d := Details{
		Type:   "https://example.com/probs/forbidden",
		Title:  "Forbidden",
		Status: http.StatusForbidden,
		Extensions: map[string]any{
			"policy":         "deny-by-default",
			"missing_scopes": []any{"read:domain"},
		},
	}

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got["type"] != d.Type || got["title"] != d.Title || got["policy"] != "deny-by-default" {
		t.Fatalf("Marshal() = %s, missing registered or extension members", b)
	}
	if _, ok := got["detail"]; ok {
		t.Fatalf("Marshal() = %s, want empty detail omitted", b)
	}
}

func TestDetails_UnmarshalJSON_RoundTrip(t *testing.T) {
	in := `{"type":"about:blank","title":"Forbidden","status":403,"policy":"deny-by-default"}`

	var d Details
	if err := json.Unmarshal([]byte(in), &d); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if d.Type != "about:blank" || d.Title != "Forbidden" || d.Status != http.StatusForbidden {
		t.Fatalf("Unmarshal() registered fields = %+v", d)
	}
	if d.Extensions["policy"] != "deny-by-default" {
		t.Fatalf("Unmarshal() Extensions = %+v, want policy preserved", d.Extensions)
	}

	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("re-Marshal() error = %v", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if roundTripped["policy"] != "deny-by-default" {
		t.Fatalf("round trip lost extension member: %s", out)
	}
}

func TestDetails_WriteTo(t *testing.T) {
	d := Details{Status: http.StatusForbidden, Title: "Forbidden", Detail: "no policy match"}

	rec := httptest.NewRecorder()
	if err := d.WriteTo(rec); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	if got := rec.Header().Get("Content-Type"); got != MediaType {
		t.Errorf("Content-Type = %q, want %q", got, MediaType)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal error = %v", err)
	}
	if body["detail"] != "no policy match" {
		t.Errorf("body = %s, missing detail", rec.Body.String())
	}
}

func TestDetails_WriteTo_DefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := (Details{}).WriteTo(rec); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
