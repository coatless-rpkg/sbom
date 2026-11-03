# sbom (development version)

* First version. `sbom_package()` and `sbom_installed()` build an SBOM from the
  `DESCRIPTION` files of a package and its installed dependencies, or of an R
  library, without network access. `write_sbom()` writes it as CycloneDX
  1.4-1.7 (JSON or XML) or SPDX 2.3 JSON, following R Observatory's output
  conventions. Values sbom could not determine are recorded by `sbom_issues()`
  and written into the document as notes.
