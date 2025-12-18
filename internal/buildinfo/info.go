package buildinfo

var (
	Version    = "v1.0.0"
	CommitHash = "unknown"
)

type Info struct {
	About      string `json:"about,omitempty"`
	Service    string `json:"service,omitempty"`
	Version    string `json:"version,omitempty"`
	CommitHash string `json:"commit_hash,omitempty"`
}

func GetBuildInfo() Info {
	return Info{
		About:      "https://github.com/darmiel/talmi",
		Service:    "Talmi",
		Version:    Version,
		CommitHash: CommitHash,
	}
}
