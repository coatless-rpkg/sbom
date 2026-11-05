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
