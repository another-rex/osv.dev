package main

import (
	"bufio"
	"os"
	"testing"
)

func Test_valid_version_InvalidVersions(t *testing.T) {
	file, err := os.Open("fixtures/invalid_versions.txt")
	if err != nil {
		t.Error("Failed to open invalid_version.txt")
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ver := scanner.Text()
		if valid_version(ver) {
			t.Errorf("Invalid version is valid: %s", ver)
		}
	}
}

func Test_valid_version_ValidVersions(t *testing.T) {
	file, err := os.Open("fixtures/valid_versions.txt")
	if err != nil {
		t.Error("Failed to open valid_version.txt")
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ver := scanner.Text()
		if len(ver) == 0 {
			continue
		}
		if !valid_version(ver) {
			t.Errorf("valid version is invalid: %s", ver)
		}
	}
}
