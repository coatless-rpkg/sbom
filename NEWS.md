# sbom 0.1.0

* Initial CRAN submission.

* `sbom()` builds a software bill of materials for an R package, library,
  project or Shiny app, offline by default.

* `write_sbom()`, `read_sbom()` and `validate_sbom()` handle CycloneDX, SPDX
  and SWID.

* `overrides` fills in values that `{sbom}` cannot find, such as the license
  of an in-house package, and records who supplied each one and why.

* `advisories = TRUE` adds the security advisories that OSV lists for the
  exact versions in an SBOM. It downloads OSV's advisory data, so it needs
  web access; pass the path of a downloaded copy instead to work offline.

* `sbom_example()` returns example projects to try.
