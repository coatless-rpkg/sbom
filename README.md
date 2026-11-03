# sbom

sbom writes Software Bills of Materials (SBOMs) for R packages and R library
installations, in CycloneDX, SPDX, SWID and a CSV inventory (see below).
`sbom_package()` describes one package and the dependencies installed for it,
and `sbom_installed()` describes the packages in a library. Both read only the
`DESCRIPTION` files on disk. They run no package code and make no network
requests, and given the same inputs and `timestamp` they produce the same
document.

Each component records its package URL (purl), its distributor as supplier, its
maintainer, its licence and the dependencies it declares. Licences are mapped to
SPDX expressions through R's own licence database. When a licence has no SPDX
equivalent, SPDX output declares `NOASSERTION` with a comment quoting the
`DESCRIPTION`, and CycloneDX output gives the licence by name. Anything sbom
could not determine, such as a dependency that is not installed or a version
that fails its constraint, is listed by `sbom_issues()` and written into the
document as a plain sentence, so the file states its own gaps.

## Installation

sbom is not yet on CRAN. Install the development version from a local checkout
of its source, running this from the package directory:

``` r
# install.packages("remotes")
remotes::install_local()
```

## Example

``` r
library(sbom)

x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
x
sbom_issues(x)

out <- file.path(tempdir(), "sbom")
write_sbom(x, out, format = "all")
list.files(out)
```

`format = "all"` writes one file per standard format into `out`, named after
the root component:

| Format | Extension | Versions |
|:--|:--|:--|
| CycloneDX JSON | `.cdx.json` | 1.4, 1.5, 1.6 (default), 1.7 |
| CycloneDX XML | `.cdx.xml` | 1.4, 1.5, 1.6 (default), 1.7 |
| SPDX JSON | `.spdx.json` | 2.2, 2.3 (default) |
| SPDX YAML | `.spdx.yaml` | 2.2, 2.3 (default) |
| SPDX XML | `.spdx.xml` | 2.2, 2.3 (default) |
| SPDX tag-value | `.spdx` | 2.2, 2.3 (default) |
| SPDX 3 JSON-LD | `.spdx3.jsonld` | 3.0.1 |
| SWID tag | `.swidtag` | 2015 |

`format = "csv"` writes a component inventory for spreadsheet review. It is not
an SBOM standard and is not part of `"all"`. `sbom_formats()` lists the formats
and their versions.
