/*
Copyright 2022 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/
// Package processing implements the hashing step for each provide input.
package processing

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv.dev/docker/indexer/shared"
	"github.com/google/osv.dev/docker/indexer/stages/preparation"
	"golang.org/x/sync/semaphore"

	log "github.com/golang/glog"
)

const workers = 25

// Storer is used to permanently store the results.
type Storer interface {
	Store(ctx context.Context, repoInfo *preparation.Result, fileResults []FileResult) error
}

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path     string
	HashType string
	Hash     []byte
}

// Stage holds the data structures necessary to perform the processing.
type Stage struct {
	Storer  Storer
	RepoHdl *storage.BucketHandle
}

// Run runs the stages and hashes all files for each incoming request.
func (s *Stage) Run(ctx context.Context, input chan *preparation.Result) error {
	wErr := make(chan error, workers)
	sem := semaphore.NewWeighted(workers)
	for {
		if err := sem.Acquire(ctx, 1); err != nil {
			return fmt.Errorf("failed to acquire semaphore: %v", err)
		}

		var (
			repoInfo *preparation.Result
			ok       bool
		)
		select {
		case repoInfo, ok = <-input:
		case err := <-wErr:
			log.Errorf("worker returned an error: %v", err)
		case <-ctx.Done():
			return context.Canceled
		}
		if !ok {
			break
		}

		go func() {
			defer sem.Release(1)

			var err error
			switch repoInfo.Type {
			case shared.Git:
				err = s.processGit(ctx, repoInfo)
			default:
				err = errors.New("unknown repository type")
			}
			if err != nil {
				wErr <- err
			}
		}()
	}
	return sem.Acquire(ctx, workers)
}

func (s *Stage) processGit(ctx context.Context, repoInfo *preparation.Result) error {
	repoDir, err := shared.CopyFromBucket(ctx, s.RepoHdl, repoInfo.Name)
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(repoDir); err != nil {
			log.Errorf("failed to remove repo folder: %v", err)
		}
	}()
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return fmt.Errorf("failed to open repo: %v", err)
	}
	tree, err := repo.Worktree()
	if err != nil {
		return err
	}
	repoInfo.CheckoutOptions.Force = true
	if err := tree.Checkout(repoInfo.CheckoutOptions); err != nil {
		return err
	}

	var fileResults []FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		for _, ext := range repoInfo.FileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf)
				fileResults = append(fileResults, FileResult{
					Path:     p,
					HashType: "MD5",
					Hash:     hash[:],
				})
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.Storer.Store(ctx, repoInfo, fileResults)
}
