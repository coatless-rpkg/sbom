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

* `sbom()` also reads a single file, such as a `DESCRIPTION` or an `renv.lock`, and given several paths and a `name`, builds one SBOM that covers them all. `combine_sbom()` does the same for SBOMs you already have.
* `sbom_example()` returns example projects to try.
