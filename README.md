# sbom

sbom writes Software Bills of Materials (SBOMs) for R packages and R library
installations, in CycloneDX, SPDX, SWID and a CSV inventory (see below).
`sbom_package()` describes one package and the dependencies installed for it,
and `sbom_installed()` describes the packages in a library. They read the
`DESCRIPTION` files on disk, and also what a package carries inside it: the
copies of `LinkingTo` packages that it compiles in, vendored C and C++ code,
bundled JavaScript and CSS, the system requirements it declares and, for
installed packages with compiled code, the shared libraries it links. They run
no package code and make no network requests unless you ask for security
advisories (see below); the system steps run `otool` or `ldd`, `dpkg` or
`rpm`, and read pak's rules on disk. Given the same inputs and `timestamp`
they produce the same document.

Each component records its package URL (purl), its distributor as supplier, its
maintainer, its licence and the dependencies it declares. Licences are mapped to
SPDX expressions through R's own licence database. When a licence has no SPDX
equivalent, SPDX output declares `NOASSERTION` with a comment quoting the
`DESCRIPTION`, and CycloneDX output gives the licence by name. Anything sbom
could not determine, such as a dependency that is not installed or a version
that fails its constraint, is listed by `sbom_issues()` and written into the
document as a plain sentence, so the file states its own gaps.

## Inputs

| Function | Describes |
|:--|:--|
| `sbom()` | A project folder: it picks the strongest source the folder holds and cross-checks it against the others. |
| `sbom_package()` | One package, from its `DESCRIPTION`, with the dependencies installed for it. |
| `sbom_installed()` | The packages in an R library. |
| `sbom_renv()` | The packages an `renv.lock` pins. |
| `sbom_rsconnect()` | A content item described by a Posit Connect `manifest.json`. |
| `sbom_shiny()` | A Shiny app folder: the app is the root, with the JavaScript and CSS it ships. |
| `sbom_nix()` | A `default.nix` written by rix, read as text or from the Nix store. |

`sbom()` prefers `renv.lock`, then `manifest.json`, then `default.nix`, then a
package's `DESCRIPTION`, and falls back to scanning the R code in the folder. Every
source it reads is listed in the SBOM's inputs. Where sources disagree, the
SBOM keeps the stronger source's answer, and `sbom_issues()` reports each
package that one source lists and the other does not, and each package they
list at different versions: for example a locked package that is installed at
another version, a package that the code uses but `DESCRIPTION` does not
declare, or a lockfile and a manifest that pin different versions. A
project's version is its git commit, read from the files in the nearest
`.git`.

``` r
x <- sbom("path/to/project")
sbom_issues(x)
```

## Shiny apps

`sbom()` recognises a Shiny app folder and describes it with `sbom_shiny()`,
which you can also call directly. The app is the root component, an
application, and one SBOM covers it whatever sources the folder holds. Four
layouts are recognised: `rhino` (a `rhino.yml`, static files in `app/static`),
`golem` (a package `DESCRIPTION` with golem's structure, static files in
`inst/app/www`), `app.R` and `ui.R` with `server.R` (static files in `www`).

The R packages come from the strongest source in the folder: `renv.lock`, then
a Posit Connect `manifest.json`, then `default.nix`, then `DESCRIPTION`, then a
scan of the code. Every other source present cross-checks it, and each
disagreement is an issue.

The JavaScript and CSS libraries in the static folder are found by the header
comments of their files, with the same bounds as for a package: no symlinks
followed, a fixed depth and a fixed number of files. They are inferred
components under the root, and nothing is invented for a file that is not a
library.

By default no code from the app runs. `evaluate_ui = TRUE` runs the app's code
(the whole of `app.R`, or `ui.R`) in a separate R process, with a time limit,
to find the HTML dependencies its UI holds, and records them as observed. The
process inherits your environment variables and sees your user and site
libraries as well as `lib`; `global.R` and the app's `R/` folder are not
sourced. It needs htmltools, works for `app.R` and `ui.R` apps, and misses
anything that `renderUI()` or other server code inserts later. If the UI cannot
be evaluated, an issue says so and the static result stays. A rhino app's npm
dependencies are not read, and an issue says so when the app has a
`package.json` or `package-lock.json`, at its top or in `.rhino/`
(`.rhino/package.json` and `.rhino/package-lock.json`).

``` r
x <- sbom_shiny("path/to/app")
sbom_components(x)
```

## Nix

`sbom_nix()` describes a `default.nix` written by the rix package, and `sbom()`
reads one as a project source. It has two modes.

Without Nix, or with `nix = FALSE`, it reads the file as text and runs
nothing. It lists R at the version of rix's `r_ver`, each R package the file
names, packages from git or from the CRAN archive, Nix system packages and TeX
Live. The file does not say which version a nixpkgs snapshot holds, so CRAN
packages have no version and an issue says so. A hand-written Nix file cannot
be read this way: `sbom_nix()` stops, and `sbom()` records a warning and builds
the SBOM from the next source.

`snapshot = "ppm"`, or the path or URL of a CRAN `PACKAGES` file, looks the
versions up in a CRAN snapshot, as inferred. A lookup uses the network only
when `snapshot` is given.

With Nix installed, `sbom_nix()` reads the environment from the Nix store: the
runtime closure of the shell's inputs, with each version, the references
between R packages and Nix libraries, and the system packages. Nix mode is
experimental. It is built on the output formats documented for Nix 2.18 and
later, and its tests use recorded examples of that output rather than a Nix
installation. Nix mode runs nix-instantiate, which may download nixpkgs. Build
the environment with `nix-shell` or `nix-build` first, or sbom reads the file
instead and adds an issue.

``` r
x <- sbom_nix("path/to/default.nix", nix = FALSE)
y <- sbom_nix("path/to/default.nix", nix = FALSE, snapshot = "ppm")
```

## Inspect

`summary()` counts an SBOM's components by ecosystem, type and evidence, tallies
their licences and lists the drift issues. `sbom_tree()` prints the dependency
tree of the root component. `sbom_diff()` compares two SBOMs and lists the
components that were added or removed and those whose version, licence or
source changed.

``` r
summary(x)
sbom_tree(x, max_depth = 2)
sbom_diff(old, new)
```

## Security advisories (opt-in)

With `advisories = TRUE`, every builder lists the security advisories that OSV
publishes from the R Consortium advisory database for the exact versions of
the SBOM's CRAN packages. Matching happens on your machine, so no package name
is sent anywhere. sbom downloads OSV's CRAN export,
`https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip`, and looks
up the CVSS rating of each upstream record it names at `https://api.osv.dev`,
sending only those public ids. On a server without network access, download
that `all.zip` elsewhere and pass its path as `advisories`: it is read where
it is, without the network and without ratings.

Only exact versions are compared, of the packages whose package URL is a CRAN
one (`pkg:cran`), packages from CRAN-like repositories among them. A CRAN
package with a minimum version, or no version, is named in an issue instead
of being matched, and so is an R package that sbom does not know to come from
CRAN: one that is not installed, or was installed from a local source or from
GitHub, GitLab, Bitbucket or git. OSV does not cover Bioconductor packages
yet, and the SBOM says so when it holds one.
The SBOM lists what OSV says about these exact versions and nothing more: a
package without an advisory is not shown to be free of flaws, and an upstream
CVSS rating describes the upstream flaw, not how exposed the R package is.

When the advisory data cannot be downloaded or read, the call fails with an
error that names the problem; `advisories_on_error = "continue"` builds the
SBOM anyway, with a warning, an issue and a note that no advisory data was on
hand. Every SBOM built without advisories carries that note.

The advisories are written as R Observatory writes them: CycloneDX
`vulnerabilities`, SPDX 2 advisory references (category `SECURITY` in 2.3,
`OTHER` in 2.2) and SPDX 3 `security_Vulnerability` elements. A SWID tag has
no place for them, and says so. `sbom_advisories()` lists them, one row per
advisory and affected package, and `read_sbom()` reads them back.

``` r
# Online: downloads OSV's CRAN export, and looks up ratings by public id.
x <- sbom("path/to/project", advisories = TRUE)
# Offline: the path of an all.zip downloaded beforehand.
x <- sbom("path/to/project", advisories = "path/to/all.zip")
sbom_advisories(x)
```

This example runs offline. It zips a made-up OSV record for `ppmpkg`, a
made-up package in the example manifest that ships with sbom, as OSV zips its
export, and needs a `zip` program:

``` r
dir <- file.path(tempdir(), "osv")
dir.create(dir, showWarnings = FALSE)
record <- file.path(dir, "EXAMPLE-2026-1.json")
writeLines(c(
  '{"id": "EXAMPLE-2026-1", "summary": "A made-up advisory for this example",',
  ' "published": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",',
  ' "affected": [{"package": {"ecosystem": "CRAN", "name": "ppmpkg"},',
  '   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}]}]}'
), record)
zip <- file.path(tempdir(), "all.zip")

if (nzchar(Sys.which("zip"))) {
  utils::zip(zip, record, flags = "-j -q")
  manifest <- system.file("extdata", "manifest.json", package = "sbom")
  x <- sbom_rsconnect(manifest, system = FALSE, advisories = zip)
  sbom_advisories(x)[, c("id", "name", "version", "fixed")]
}
```

## Read and validate any SBOM

`read_sbom()` reads an SBOM in any of the eight formats, made by sbom or by
any other tool, into an `<sbom>` that you can inspect, compare or write again.
`validate_sbom()` checks a file against the bundled schema of its format, and
checks the content of a file or an `<sbom>` against integrity rules and the
NTIA 2021 minimum elements, without network access. It prints a report with a
hint for each problem, and `as.data.frame()` gives the findings for review.

``` r
y <- read_sbom("path/to/sbom.spdx.json")
validate_sbom("path/to/sbom.spdx.json")
```

The status is `fail` when any layer fails, `skipped` when every layer that ran
was skipped (as with `checks = "schema"` on a version sbom has no schema for),
`partial` when a layer was skipped or could check only part of the rules (SPDX
XML and tag-value have no official schema, SPDX's SHACL rules for SPDX 3 are
not checked, and without jsonvalidate the JSON schemas are not checked), and
`pass` otherwise.

## Inside packages

A package can carry code that is not an R package. With `embedded = TRUE` (the
default), sbom records it as components contained in the package:

- A package named in `LinkingTo` is compiled into the package, so its headers
  are an embedded component, separate from the same package as a dependency.
- C and C++ libraries copied into a package's `src/` folder, or named in its
  `COPYRIGHTS` file or `cph` entries, are vendored components. The version is
  read from a header when there is one, and is otherwise unknown.
- Bundled JavaScript and CSS libraries are read from `htmlwidgets` YAML and
  from the header comments of files under `www/`, `htmlwidgets/lib/` and
  `lib/`. Their licences are not read.

With `system = TRUE` (the default), sbom also records what a package needs from
the operating system:

- `SystemRequirements` is mapped to system libraries and programs through pak's
  rules, as pak has them on disk: sbom turns off pak's update of its rules, so
  it makes no network request. The text itself is written as it stands too: a
  property in CycloneDX, the package comment in SPDX, a column in the CSV and,
  for the root, the SWID tag. So text that pak cannot map, such as "C++17", is
  kept, and no component is invented for it.
- For installed packages with compiled code, the shared libraries the binary
  links (read with `otool` or `ldd`) become components, with the version of the
  Debian or RPM package that owns the file when the operating system says so.
  A library's own "current version" is never written as a version. R's own
  libraries, the C, C++, Fortran and OpenMP runtimes, and the copies that
  packages ship in a library folder are not system libraries. What Windows
  DLLs link is not read.
- When a package declares a library it does not link dynamically, sbom adds an
  informational issue: it may include its own copy, whose version is unknown.

Each component states how sbom knows it. `declared` means a package says so,
as in `SystemRequirements` (even when pak's rules give the library its name)
or a `htmlwidgets` file. `observed` means sbom read it from a binary or the
operating system. `inferred` means a rule matched: a `LinkingTo` entry, a
header comment or a name in `COPYRIGHTS`. Machines without `otool`, `ldd`,
`dpkg`, `rpm` or pak still get an SBOM, with an issue naming what was not
checked or is unknown. Set `embedded = FALSE` or `system = FALSE` to skip
either step.

In SPDX and CycloneDX a system requirement is a dependency (in SPDX 3, scoped
to the build for build tools such as make and cmake, and to run time
otherwise), and a dynamic link is a link relationship (`DYNAMIC_LINK` in SPDX
2, `hasDynamicLink` in SPDX 3, a dependency in CycloneDX). A SWID tag lists
system components among the root's `requires` links, like any other
component, without saying which relationship it is.

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

# system = TRUE (the default) also runs otool or ldd and reads pak's rules.
x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
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
