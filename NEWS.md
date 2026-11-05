# sbom (development version)

* First version. `sbom_package()` and `sbom_installed()` build an SBOM from the
  `DESCRIPTION` files of a package and its installed dependencies, or of an R
  library, without network access. `write_sbom()` writes it as CycloneDX
  1.4-1.7 (JSON or XML), SPDX 2.2 or 2.3 (JSON, YAML, XML or tag-value), SPDX
  3.0.1 JSON-LD or a SWID tag, or as a CSV inventory, following R
  Observatory's output conventions. Values sbom could not determine are
  recorded by `sbom_issues()` and written into the document as notes.

* `sbom()` builds an SBOM for a project folder from its `renv.lock`, Posit
  Connect `manifest.json`, `default.nix`, `DESCRIPTION` or code, and reports
  as issues the packages that one of those sources lists and another does
  not, and those they list at different versions. `sbom_renv()` and
  `sbom_rsconnect()` read a lockfile or manifest directly, and `summary()`,
  `sbom_tree()` and `sbom_diff()` inspect an SBOM.

* `sbom_shiny()` describes a Shiny app folder (rhino, golem, `app.R`, or `ui.R`
  with `server.R`): the app is the root, the R packages come from the strongest
  source in the folder, and the JavaScript and CSS it ships are recorded, with
  an opt-in `evaluate_ui = TRUE` that runs the UI in a separate process.
  `sbom()` calls it for an app folder.

* `sbom_nix()` describes a `default.nix` written by rix, from its text or, with
  Nix installed, from the Nix store (experimental), with an opt-in `snapshot`
  that looks package versions up in a CRAN snapshot. `sbom()` reads
  `default.nix` as a project source, between `manifest.json` and
  `DESCRIPTION`.

* SBOMs now record what is inside packages: code compiled in through
  `LinkingTo`, vendored C and C++ sources, bundled JavaScript, declared
  `SystemRequirements` and the shared libraries a package links, each with its
  evidence level, in every output format. `embedded = FALSE` and
  `system = FALSE` skip the detection.

* `read_sbom()` reads an SBOM in any of the eight formats, made by sbom or by
  any other tool, into an `<sbom>`. It detects the format from the file's
  content, not its name, and records as issues what it could not read.

* `validate_sbom()` checks an SBOM file against the bundled schema of its
  format, and checks the content of a file or an `<sbom>` against integrity
  rules (ids, relationships, licence expressions against the bundled SPDX
  License List, purls) and the NTIA 2021 minimum elements. It returns an
  `<sbom_validation>`, which prints a report with a hint for each check, and
  whose findings `as.data.frame()` returns. `error_on` turns a failure into an
  error, for scripts.

* `purl()` requires each of `name`, `version`, `namespace` and
  `repository_url` to have length 1 or the length of the longest, and errors
  otherwise rather than recycling silently. A version of `""` is left out, as
  `NA` is.

* SPDX 2 output defines each `LicenseRef-` it uses, such as one asserted with
  an override, in `hasExtractedLicensingInfos`, as the SPDX specification
  requires.

* A package installed from a local git repository no longer has its
  `RemoteUrl`, a path on the machine that built the SBOM, written as its vcs
  URL, and a remote URL loses any user name, password or token it holds before
  it is written. SBOMs made by earlier versions may hold both; check them
  before sharing them.

* R's `FreeBSD` licence now maps to the SPDX id `BSD-2-Clause-Views`.

* A supplier asserted with an override for R or a base package is now written
  in SPDX 2.

* SPDX 3 output spells SHA3 checksum algorithms as SPDX 3 does (`sha3_256`
  and so on), and SPDX 2.2 output leaves out SHA3 checksums, which SPDX 2.2
  does not list.

* A dependency that is `optional` is written in SPDX 2 and SPDX 3 as an
  optional dependency, as a `Suggests` dependency already was.

* `print()`, `summary()`, `sbom_tree()` and `sbom_diff()` show the control
  characters of a value as spaces, so that an SBOM read from a hostile file,
  or built from a hostile `DESCRIPTION`, cannot rewrite the terminal.
