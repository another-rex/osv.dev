package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	repoDir  = flag.String("repo", "", "repo directory")
	repo2Dir = flag.String("repo2", "", "repo 2 directory")
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type Hash = [16]byte

// FileResult holds the per file hash and path information.
type FileResult struct {
	Path string `datastore:"path,noindex"`
	Hash Hash   `datastore:"hash"`
}

func main() {
	flag.Parse()
	buildGit(*repoDir)

	log.Println(compareTwoResults(buildFileHashes(*repoDir), buildFileHashes(*repo2Dir)))
}

func compareTwoResults(a []*FileResult, b []*FileResult) int {
	mapA := fileHashesToDict(a)
	mapB := fileHashesToDict(b)

	diffCount := 0
	for k, fr := range mapA {
		if _, ok := mapB[k]; !ok {
			log.Printf("%v", fr.Path)
			diffCount += 1
		}
	}

	return diffCount + max(len(mapB)-len(mapA), 0)
}

func fileHashesToDict(res []*FileResult) map[Hash]*FileResult {
	output := make(map[Hash]*FileResult)
	for _, fr := range res {
		output[fr.Hash] = fr
	}
	return output
}

func buildFileHashes(repoDir string) []*FileResult {
	fileExts := []string{
		".hpp",
		".h",
		".hh",
		".cc",
		".c",
		".cpp",
	}

	var fileResults []*FileResult
	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		for _, ext := range fileExts {
			if filepath.Ext(p) == ext {
				buf, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				hash := md5.Sum(buf)
				fileResults = append(fileResults, &FileResult{
					Path: strings.ReplaceAll(p, repoDir, ""),
					Hash: hash,
				})
			}
		}
		return nil
	}); err != nil {
		log.Panicf("failed during file walk: %v", err)
	}

	log.Printf("%v", len(fileResults))

	return fileResults
}

func buildGit(repoDir string) error {
	fileResults := buildFileHashes(repoDir)

	b := strings.Builder{}
	b.WriteString(`{"name":"protobuf", "file_hashes": [`)

	for i, fr := range fileResults {
		if i == len(fileResults)-1 {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"}", base64.StdEncoding.EncodeToString(fr.Hash[:]))
		} else {
			fmt.Fprintf(&b, "{\"hash\": \"%s\"},", base64.StdEncoding.EncodeToString(fr.Hash[:]))
		}
	}
	b.WriteString("]}")

	// os.WriteFile("test", []byte(b.String()), 0666)
	// TODO: Use proper grpc library calls here
	cmd := exec.Command("curl")
	cmd.Args = append(cmd.Args, "-d", b.String(), "https://api.osv.dev/v1/", "https://api.osv.dev/v1experimental/determineversion")

	buffer := bytes.Buffer{}
	_, err := buffer.Write([]byte(b.String()))
	if err != nil {
		log.Panicln(err)
	}

	cmd.Stdin = &buffer
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Panicf("%s: %s", err.Error(), string(output))
	}

	log.Println(string(output))
	return nil
}
