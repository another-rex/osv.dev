# OSV - Open Source Vulnerabilities

[osv.dev] is a [vulnerability database] and triage infrastructure for
open source projects aimed at helping both open source maintainers and
consumers of open source.

This repository contains the infrastructure code that serves [osv.dev]
(and other user tooling). This infrastructure serves as an aggregator of
vulnerability databases that have adopted the
[OpenSSF Vulnerability format](https://github.com/ossf/osv-schema).

[osv.dev] additionally provides infrastructure to ensure affected
versions are accurately represented in each vulnerability entry, through
bisection and version analysis.

[osv.dev]: https://osv.dev
[vulnerability database]: https://osv.dev/list

<p align="center">
  <img src="docs/images/diagram.png" width="600">
</p>

## Current data sources
**This is an ongoing project.** We encourage open source ecosystems to adopt
the [OpenSSF Vulnerability format](https://github.com/ossf/osv-schema) to enable
open source users to easily aggregate and consume vulnerabilities across all ecosystesm.
See our [blog post](https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html)
for more details.

The following ecosystems have vulnerabilities encoded in this format:
- [GitHub Advisory Database](https://github.com/github/advisory-database) ([CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md))
- [PyPI Advisory Database](https://github.com/pypa/advisory-database) ([CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE))
- [Go Vulnerability Database](https://github.com/golang/vulndb) ([CC-BY 4.0](https://github.com/golang/vulndb#license))
- [Rust Advisory Database](https://github.com/RustSec/advisory-db) ([CC0 1.0](https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt))
- [Global Security Database](https://github.com/cloudsecurityalliance/gsd-database) ([CC0 1.0](https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE))
- [OSS-Fuzz](https://github.com/google/oss-fuzz-vulns) ([CC-BY 4.0](https://github.com/google/oss-fuzz-vulns/blob/main/LICENSE))

Together, these include vulnerabilities from:
- npm
- Maven
- Go
- NuGet
- PyPI
- RubyGems
- crates.io
- Packagist
- Linux
- OSS-Fuzz

### Data dumps

For convenience, these sources are aggregated and continuously exported to a GCS bucket
maintained by OSV: [gs://osv-vulnerabilities](https://osv-vulnerabilities.storage.googleapis.com).

This bucket contains individual entries of the format `gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json`
as well as a zip containing all vulnerabilities for each ecosystem at
`gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

E.g. for PyPI vulnerabilities:

```bash
# Or download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

## Viewing the web UI

An instance of OSV's web UI is deployed at <https://osv.dev>.

## Using the API

```bash
  curl -X POST -d \
      '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
      "https://api.osv.dev/v1/query"

  curl -X POST -d \
      '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
      "https://api.osv.dev/v1/query"
```

Detailed documentation for using the API can be found at
<https://osv.dev/docs/>.

## Architecture

You can find an overview of OSV's architecture [here](docs/architecture.md).

## This repository

This repository contains all the code for running https://osv.dev on GCP. This
consists of:

- API server (`gcp/api`)
- Web interface (`gcp/appengine`)
- Workers for bisection and impact analysis (`docker/worker`)
- Sample tools (`tools`)

You'll need to check out submodules as well for many local building steps to
work:

```bash
git submodule update --init --recursive
```

## Development
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Third party tools

There are also community tools that use OSV. Note that these are community built tools and
unsupported by the core OSV maintainers.

- [G-Rath/osv-detector](https://github.com/G-Rath/osv-detector): A scanner that uses the OSV database.

## Contributing
Contributions are welcome! We also have a
[mailing list](https://groups.google.com/g/osv-discuss) and a
[FAQ](https://osv.dev/docs/#tag/faq).
