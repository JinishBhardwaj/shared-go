package problem

import "testing"

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
