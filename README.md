# sbom

sbom writes Software Bills of Materials (SBOMs) for R packages and R library
installations, in CycloneDX, SPDX, SWID and a CSV inventory (see below).
`sbom_package()` describes one package and the dependencies installed for it,
and `sbom_installed()` describes the packages in a library. Both read only the
`DESCRIPTION` files on disk. They run no package code and make no network
requests, and given the same inputs and `timestamp` they produce the same
document.

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

`sbom()` prefers `renv.lock`, then `manifest.json`, then a package's
`DESCRIPTION`, and falls back to scanning the R code in the folder. Every
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

x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
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
