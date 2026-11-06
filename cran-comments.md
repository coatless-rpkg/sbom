## R CMD check results

0 errors | 0 warnings | 0 notes

`R CMD check --as-cran` on macOS 27.2 (aarch64-apple-darwin23) with R 4.6.2,
without the remote incoming checks.

* This is a new submission. CRAN's incoming checks will note that, and may
  list "lockfiles" and "NTIA" as possibly misspelled words in DESCRIPTION.
  Both are correct: a lockfile is the file in which 'renv' records package
  versions, and NTIA is the acronym of the National Telecommunications and
  Information Administration, spelled out where it appears.

## Network use and system commands

* sbom uses the network only when the user asks it to: with
  `advisories = TRUE`, which downloads the Open Source Vulnerabilities (OSV)
  export of CRAN advisories and looks up the ratings of the public advisory
  ids it names, and with `snapshot` in `sbom_nix()`, which looks package
  versions up in a CRAN snapshot. The tests and examples never use the
  network: the two examples that would are in `\dontrun{}`, and the tests mock
  every function that could reach it.
* System commands (`otool`, `ldd`, `dpkg`, `rpm`, `nix-instantiate`,
  `nix-store`, and a child R process for `sbom_shiny(evaluate_ui = TRUE)`) run
  only through wrapper functions, which the tests mock in
  `tests/testthat/setup-sysreqs.R`. The few tests that call a real one are
  skipped on CRAN. The examples set `system = FALSE` or `nix = FALSE`, so they
  run none.

## Bundled files

The package bundles the CycloneDX, SPDX 2 and SPDX 3 schemas, the two W3C
schemas that the SWID schema imports, and the identifiers of the SPDX License
List. `inst/COPYRIGHTS` lists every bundled file with its source, copyright,
license and changes.

## Method references

There are no published references describing the methods in this package. It
implements the CycloneDX, SPDX and SWID specifications.
