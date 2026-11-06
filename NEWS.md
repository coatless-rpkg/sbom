# sbom 0.1.0

First release.

## Building

* `sbom_package()` and `sbom_installed()` build an SBOM from the `DESCRIPTION`
  files of a package and its installed dependencies, or of an R library,
  without network access. `sbom()` builds one for a project folder from its
  `renv.lock`, Posit Connect `manifest.json`, `default.nix`, `DESCRIPTION` or
  code, and reports as issues the packages that one of those sources lists and
  another does not, or lists at a different version. `sbom_renv()`,
  `sbom_rsconnect()`, `sbom_shiny()` and `sbom_nix()` read a lockfile, a
  manifest, a Shiny app folder or a `default.nix` written by rix.

* An SBOM records what is inside packages: code compiled in through
  `LinkingTo`, vendored C and C++ sources, bundled JavaScript and CSS, declared
  `SystemRequirements` and the shared libraries a package links, each with its
  evidence level. `embedded = FALSE` and `system = FALSE` skip the detection.
  When R's version is exact, the base packages are listed at that version.

* What sbom could not determine is recorded as issues (`sbom_issues()`) and
  written into the document as notes. A remote URL is written without any user
  name, password or token it holds, and the path of a local git repository is
  never written as a vcs URL.

* `overrides` asserts values where sbom found none, or found something else,
  with who asserted each and why. An asserted version is exact, and the
  component's package URL, package file name and, when it is the package URL,
  its `ref` follow it; the checksums of the version found are dropped. An
  asserted version of R is also the version of the base packages. Each
  asserted field removes the issues it answers, and an issue that also states
  a fact that stays true, such as that a dependency is not installed or that a
  package is not in a CRAN snapshot, becomes a note that says the value is
  asserted.

* `advisories = TRUE`, off by default, lists the security advisories that OSV
  publishes from the R Consortium advisory database for the exact versions of
  the SBOM's CRAN packages. sbom downloads OSV's CRAN export and matches it
  locally, so that no package name leaves the machine; the path of a copy of
  that `all.zip` works offline. `sbom_advisories()` lists them.

## Writing and reading

* `write_sbom()` writes CycloneDX 1.4 to 1.7 (JSON or XML), SPDX 2.2 or 2.3
  (JSON, YAML, XML or tag-value), SPDX 3.0.1 JSON-LD, a SWID tag, or a CSV
  inventory, following R Observatory's conventions, advisories included. A
  document's serial number or namespace derives from its content. Characters
  that XML forbids are written in CycloneDX XML as the replacement character.

* `read_sbom()` reads an SBOM in any of these formats, made by sbom or by any
  other tool, detecting the format from the content, and records as issues
  what it could not read. It reads back the advisories sbom wrote, and counts
  other tools' vulnerability data in an issue instead of reading it as OSV's.

* `print()`, `summary()`, `sbom_tree()` and `sbom_diff()` inspect an SBOM, and
  show control characters as spaces, so that a hostile file cannot rewrite the
  terminal.

## Validating

* `validate_sbom()` checks CycloneDX documents and SPDX 2 documents in JSON or
  YAML against the bundled schema of their format, and converts SPDX 2
  documents in XML or tag-value form to the SPDX JSON model and checks them
  against its schema. SPDX 3 documents are checked against their JSON schema,
  without its Shapes Constraint Language rules, and SWID tags against
  structural rules or, when the user supplies it with the option
  `sbom.swid_xsd`, the standard's official schema. Every document, and an
  `<sbom>`, is also checked against integrity rules and the NTIA 2021 minimum
  elements. `error_on` turns a failure into an error, for scripts.
