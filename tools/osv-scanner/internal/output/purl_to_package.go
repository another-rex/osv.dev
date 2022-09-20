package output

import (
	"github.com/package-url/packageurl-go"
)

func PURLToPackage(purl string) (Package, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		return Package{}, err
	}
	return Package{
		Name:      parsedPURL.Name,
		Ecosystem: parsedPURL.Type, // TODO: Might want some mapping here to properly cased ecosystems
		Version:   parsedPURL.Version,
	}, nil
}
