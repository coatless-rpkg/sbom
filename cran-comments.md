## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Test environments

* Local: macOS 27.2 (aarch64), R 4.6.2, `R CMD check --as-cran`.
* GitHub Actions: macOS (R release), Windows (R release), and Ubuntu (R devel,
  release and oldrel-1).

## Network use and system commands

* The package uses the network only when asked to: `advisories = TRUE`
  downloads the Open Source Vulnerabilities (OSV) export of CRAN advisories
  and looks up the ratings of the advisory ids it names, and a `snapshot`
  given as a URL looks package versions up in a CRAN snapshot. The two
  examples that would use the network are in `\dontrun{}`, and the tests mock
  every call that could reach it.
* System commands (`otool`, `ldd`, `dpkg`, `rpm`, `nix-instantiate`,
  `nix-store`, and a child R process for `sbom_shiny(evaluate_ui = TRUE)`) run
  only through wrapper functions, which the tests mock. The few tests that call
  a real one are skipped on CRAN, and the examples run none.

## Bundled files

The package bundles the CycloneDX, SPDX 2 and SPDX 3 schemas, the two W3C
schemas that the SWID schema imports, and the identifiers of the SPDX License
List. `inst/COPYRIGHTS` lists each file with its source, copyright, license
and changes.

## Method references

There are no published references describing the methods in this package. It
implements the CycloneDX, SPDX and SWID specifications.
