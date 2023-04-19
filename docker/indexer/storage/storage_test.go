package storage

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
)

func getRepoInfo(t *testing.T) *preparation.Result {
	return &preparation.Result{
		Name:   "abc",
		Commit: [20]byte{0x41, 0x41, 0x41, 0x41},
	}
}

func getDoc(t *testing.T, pages int) *document {
	return &document{
		Name:         "abc",
		Commit:       []byte{0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		FileHashType: "MD5",
	}
}

func TestNewDoc(t *testing.T) {
	for _, tc := range []struct {
		repoInfo *preparation.Result
		wantDoc  *document
	}{
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 1),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 2),
		},
		{
			repoInfo: getRepoInfo(t),
			wantDoc:  getDoc(t, 3),
		},
	} {
		doc := newDoc(tc.repoInfo, "MD5")
		if diff := cmp.Diff(tc.wantDoc, doc); diff != "" {
			t.Errorf("newDoc() returned an unexpected document diff (-want, +got):\n%s", diff)
		}
	}
}
