package core

import "testing"

func TestResourceRealm(t *testing.T) {
	tests := []struct {
		name      string
		resource  Resource
		wantRealm string
		wantOK    bool
		wantBody  string
	}{
		{
			name:      "github enterprise resource",
			resource:  "ghes-corp:acme/service-a",
			wantRealm: "ghes-corp",
			wantOK:    true,
			wantBody:  "acme/service-a",
		},
		{
			name:      "talmi session",
			resource:  "talmi:session",
			wantRealm: "talmi",
			wantOK:    true,
			wantBody:  "session",
		},
		{
			name:      "colons in body split only on first",
			resource:  "github-com:a:b:c",
			wantRealm: "github-com",
			wantOK:    true,
			wantBody:  "a:b:c",
		},
		{
			name:      "no colon is malformed",
			resource:  "no-colon",
			wantRealm: "",
			wantOK:    false,
			wantBody:  "no-colon",
		},
		{
			name:      "empty is malformed",
			resource:  "",
			wantRealm: "",
			wantOK:    false,
			wantBody:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRealm, gotOK := tt.resource.Realm()
			if gotRealm != tt.wantRealm || gotOK != tt.wantOK {
				t.Errorf("Resource.Realm() = (%v, %v), want (%v, %v)", gotRealm, gotOK, tt.wantRealm, tt.wantOK)
			}
			gotBody := tt.resource.Body()
			if gotBody != tt.wantBody {
				t.Errorf("Resource.Body() = %v, want %v", gotBody, tt.wantBody)
			}
		})
	}
}
