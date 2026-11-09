## Submission

This is an update to sbom 0.1.0. It adds two features, both listed in
NEWS.md: `checksums = TRUE` records the SHA-256 and MD5 of each CRAN or
Bioconductor package's source tarball, and each R package's DESCRIPTION Title
is now written as its description.

## R CMD check results

0 errors | 0 warnings | 0 notes

## Test environments

* Local: macOS 27.2 (aarch64), R 4.6.2, `R CMD check --as-cran`.
* GitHub Actions: macOS (R release), Windows (R release), and Ubuntu (R devel,
  release and oldrel-1).

## Network use and system commands

* The package uses the network only when asked to: `advisories = TRUE`
  downloads the Open Source Vulnerabilities (OSV) export of CRAN advisories
  and looks up the ratings of the advisory ids it names, a `snapshot` given as
  a URL looks package versions up in a CRAN snapshot, and `checksums = TRUE`
  reads repository metadata with 'pak', which downloads it when its copy is
  out of date. The two examples that would use the network are in
  `\dontrun{}`, and the tests mock every call that could reach it.
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
