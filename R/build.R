#' Build an SBOM for a package or an R library
#'
#' `sbom_package()` describes one package and everything it depends on.
#' `sbom_installed()` describes the packages in an R library. Both read the
#' `DESCRIPTION` files that are on disk and nothing else: they run no package
#' code and make no network requests, except that `advisories = TRUE`
#' downloads OSV's advisory data.
#'
#' The root of `sbom_package()` is the package at `path`, recorded as
#' declared. Every dependency is looked up in `lib` and recorded as observed,
#' at the version installed there. A dependency that is not installed becomes
#' an `unknown` component with an issue, and an installed version that fails
#' the declared constraint is listed as installed, with an issue. Packages
#' reached only through `Suggests` have scope `"optional"`.
#'
#' R is always a component. When `lib` is the current library search path and
#' `r_version` is `NULL`, it is listed at the running version. With any other
#' library, the lowest version that the dependency tree states, the highest
#' `R (>= x)` found, is used as a minimum. The base packages used come with
#' R: when R's version is exact, they are listed at that version, with R's
#' evidence, and otherwise without a version.
#'
#' @param path A package directory, a `DESCRIPTION` file or a source tarball
#'   (`.tar.gz`). A tarball is also hashed, and its file name recorded.
#' @param dependencies The `DESCRIPTION` fields to follow, from `"Depends"`,
#'   `"Imports"`, `"LinkingTo"` and `"Suggests"`. Only the root's own
#'   `Suggests` are listed, and the packages they name are not followed.
#' @param lib Library paths to read installed packages from. Each must exist.
#'   When a package is in more than one, the first path wins, as it does when
#'   R loads it.
#' @param r_version The R version, as a string, to record exactly. `NULL`
#'   picks it as described in Details.
#' @param author,organization Who made the SBOM, recorded in its metadata.
#'   `author` may name several people; `NA` and empty names are dropped.
#'   Without either, an issue is recorded.
#' @param regid The registration id of `organization`: the domain name, or URL,
#'   of the organization, under which it registers SWID tags (ISO/IEC
#'   19770-2). A SWID tag names the organization as its creator with this
#'   regid. It must be a single string, from which leading and trailing
#'   white space is dropped. `NULL`, `NA` and an empty or blank
#'   string mean none; then the tag uses the placeholder
#'   `http://invalid.unavailable`, and when an `organization` was given, an
#'   issue is recorded. The default is the `sbom.regid` option, as
#'   `author` and `organization` read `sbom.author` and `sbom.organization`.
#' @param timestamp The creation time, as a date-time or as seconds since
#'   1970-01-01 UTC. An explicit `timestamp` wins. Without one, the
#'   `SOURCE_DATE_EPOCH` environment variable is used when it is set, so that
#'   builds are reproducible, and a note records that the timestamp came from
#'   it; otherwise it is the current time. Nix sets
#'   `SOURCE_DATE_EPOCH` to 1980-01-01 in every `nix-shell`, and when the
#'   timestamp is that value a note says it is a placeholder.
#' @param overrides Values to assert where `sbom` found none, or found
#'   something different. `NULL`, a data frame or the path to a CSV file, with
#'   the character columns `component` (the `name` or `ref` of one
#'   component, as sbom built it, before any row moves it; embedded and
#'   system components only by `ref`), `field`, `value`, `asserted_by` and
#'   `reason`. `field` is one
#'   of `"version"`, `"license_spdx"`, `"supplier_name"`, `"supplier_url"`,
#'   `"maintainer"`, `"purl"` and `"download_location"`. Rows are applied in
#'   order, and each is recorded with who asserted it and why. An override
#'   that contradicts a found value wins and adds an `override-conflict` issue.
#'   Asserting `"version"` makes it the exact version, and moves the
#'   component's package URL to it unless a row asserts the `"purl"`: a
#'   package URL at the old version takes the new one, and one without a
#'   version gains it when its type is `cran`, `github`, `gitlab` or
#'   `bitbucket`. A package file named for the old version is renamed for
#'   the new one, and any other is dropped, as are the checksums of the
#'   version found. An asserted version of R is also the version of the base
#'   packages, each with a record of the assertion. Asserting a CRAN `"purl"`
#'   (`pkg:cran`) makes the component a CRAN package, or a Bioconductor
#'   package when its `repository_url` names bioconductor.org. When a
#'   component's `ref` is its package URL, the `ref` follows the package URL
#'   that the overrides leave, and every reference to it moves too; a `ref`
#'   that another component already has is an error. Any other `ref`, such
#'   as `unknown/<name>`, stays as it is.
#'   An asserted field removes the component's issues that it answers, such
#'   as `version-missing` or `purl-inferred`. An issue that also states a
#'   fact that stays true is reworded instead, as info: that a package came
#'   from a git repository, once its package URL is asserted; that a
#'   dependency is missing, once its version and package URL are both
#'   asserted; and that a `LinkingTo` package is not installed, once its
#'   version is. The issues that name the components without a version, such
#'   as `system-version-unknown`, name only those still without one, and go
#'   when none is left.
#'   A blank value, an unknown component or field, or a missing column, is an
#'   error.
#' @param embedded Whether to record the code that packages carry inside them.
#'   A package named in `LinkingTo` is recorded as an embedded component of
#'   the package that compiles it in, nested under that package, as
#'   inferred, at the version and with the license that the library,
#'   lockfile or manifest records for it now. A C or C++ library that a package
#'   copies into its `src/` folder (source packages), or names in its
#'   `COPYRIGHTS` file or `cph` entries (source and installed packages), is
#'   recorded as a vendored component of that package, from the rules in
#'   `inst/extdata/vendored.csv`. The version is read from the library's
#'   header when there is one, and is otherwise unknown. A JavaScript or CSS
#'   library declared in htmlwidgets YAML, or found by the header comment of a
#'   file under `www/`, `htmlwidgets/lib/` or `lib/` (under `inst/` in source
#'   packages), is recorded as an npm component of that package, from the
#'   rules in `inst/extdata/javascript.csv`. Its license is not read.
#' @param system Whether to detect system libraries. A package's
#'   `SystemRequirements` text is mapped to system libraries and programs
#'   with the rules of the pak package, when it is installed. sbom turns off
#'   pak's update of those rules, so pak uses the rules it has cached or
#'   ships and makes no network request. The shared libraries that installed
#'   compiled code links are read with `otool` (macOS) or `ldd` (Linux).
#' @param advisories Whether to list the OSV security advisories for the
#'   SBOM's packages, from the R Consortium advisory database that OSV
#'   publishes; see [sbom_advisories()]. Only exact versions are compared,
#'   of the packages whose package URL is a CRAN one (`pkg:cran`), packages
#'   from CRAN-like repositories among them, matched by name. A package with
#'   a CRAN package URL and a minimum version, or none, is named in an
#'   `advisories-no-exact-version` issue. An R package that is not known to
#'   come from CRAN, because sbom could not tell where it came from (as for a
#'   package that is not installed), or because it was installed from a
#'   local source or from GitHub, GitLab, Bitbucket or git, is named in an
#'   `advisories-not-cran` issue. Bioconductor packages are not compared:
#'   OSV does not cover them yet, and when the SBOM holds one a note states
#'   that the advisory database leaves them out.
#'   Matching is local, with the versions and package URLs after
#'   `overrides`, so no package name leaves the machine.
#'
#'   `FALSE`, the default, lists none, makes no network request and adds a
#'   note that no advisory data was on hand. `TRUE` downloads OSV's CRAN
#'   export,
#'   `https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip`, and
#'   looks up the CVSS ratings of the upstream records it names at
#'   `https://api.osv.dev`, sending only their public ids. On a machine
#'   without network access, download that `all.zip` elsewhere and pass its
#'   path: it is read where it is, without the network and without ratings.
#'
#'   The SBOM lists what OSV says about these exact versions: a package
#'   without an advisory is not shown to be free of flaws, and an upstream
#'   CVSS rating describes the upstream flaw, not how exposed the R package
#'   is.
#' @param advisories_on_error What happens when the advisory data cannot be
#'   downloaded or read, as when the download fails or the zip is damaged:
#'   `"error"`, the default, is an error of class `sbom_advisories_error`
#'   that names the problem; `"continue"` builds the SBOM without
#'   advisories, with an R warning of class `sbom_advisories_unavailable`, a
#'   warning issue and a note that no advisory data was on hand. A download
#'   larger than 50 MB is refused as an error too. A CVSS rating that cannot
#'   be looked up never fails the call: it is left out, with an issue. The
#'   lookups stop at the first that times out or fails at the connection,
#'   and take at most two minutes in all.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
#' x
#' @export
sbom_package <- function(path = ".",
                         dependencies = c("Depends", "Imports", "LinkingTo", "Suggests"),
                         lib = .libPaths(), r_version = NULL,
                         author = getOption("sbom.author"),
                         organization = getOption("sbom.organization"),
                         regid = getOption("sbom.regid"),
                         timestamp = NULL, overrides = NULL,
                         embedded = TRUE, system = TRUE, advisories = FALSE,
                         advisories_on_error = c("error", "continue")) {
  dependencies <- match.arg(dependencies, several.ok = TRUE)
  on_error <- check_advisories_args(advisories, advisories_on_error)
  check_lib(lib)
  regid <- check_regid(regid)
  root_desc <- read_package_description(path)
  root <- package_component(root_desc, "declared", "package", is_root = TRUE)
  is_tarball <- file.exists(path) && !dir.exists(path) &&
    grepl("\\.(tar\\.gz|tgz|tar)$", path)
  if (is_tarball) {
    root$component$hashes <- list(data.frame(
      alg = "SHA-256", content = cli::hash_file_sha256(path), of = "source tarball",
      stringsAsFactors = FALSE
    ))
    root$component$package_file_name <- basename(path)
  }
  inputs <- library_inputs("DESCRIPTION", path, lib)
  x <- build_sbom(
    root = root, lookup = library_lookup(lib), root_desc = root_desc,
    fields = intersect(c("Depends", "Imports", "LinkingTo"), dependencies),
    root_suggests = "Suggests" %in% dependencies, lib = lib,
    r_version = r_version, author = author, organization = organization,
    regid = regid, timestamp = timestamp, inputs = inputs,
    embedded = embedded, system = system, source_dir = package_source_dir(path)
  )
  if (is_tarball && embedded) {
    x$issues <- add_issue(
      x$issues, x$metadata$root, "embedded", "tarball-not-unpacked",
      paste0(
        "The source tarball ", basename(path), " was not unpacked, so the code ",
        "bundled in it is not listed."
      ),
      severity = "info"
    )
  }
  apply_advisories(apply_overrides(x, overrides), advisories, on_error)
}

# The DESCRIPTION at `path` (a folder, a DESCRIPTION file or a tarball),
# which must name its package: as sbom_package() reads it, and as a
# cross-check of DESCRIPTION reads it.
read_package_description <- function(path, call = parent.frame()) {
  desc <- read_description(path)
  if (!"Package" %in% names(desc) || !nzchar(trimws(desc[["Package"]]))) {
    cli::cli_abort(
      "The {.file DESCRIPTION} at {.file {path}} has no {.field Package} field.",
      call = call
    )
  }
  desc
}

# The inputs of a reader that read `path`, of kind `kind`, and the library
# paths `lib`: as sbom_package() and the code scan record them, and as their
# cross-checks do.
library_inputs <- function(kind, path, lib) {
  data.frame(
    kind = c(kind, rep("library", length(lib))),
    path = c(as.character(path), as.character(lib)),
    stringsAsFactors = FALSE
  )
}

# The folder that holds a package's files, from a folder or a DESCRIPTION
# path, or NULL for an archive, which is not unpacked.
package_source_dir <- function(path) {
  if (dir.exists(path)) {
    path
  } else if (identical(basename(path), "DESCRIPTION")) {
    dirname(path)
  }
}

#' @rdname sbom_package
#' @param pkgs Names of the installed packages to list. `NULL` lists every
#'   package in `lib`, and an issue is recorded when there are none. The
#'   dependencies of the listed packages are listed too. A name that is not
#'   installed in `lib`, other than a base package, is an error.
#' @param name The name of the library, used for its root component.
#' @examples
#' sbom_installed("sbom", system = FALSE)
#' @export
sbom_installed <- function(pkgs = NULL, lib = .libPaths(), name = "R library",
                           r_version = NULL, author = getOption("sbom.author"),
                           organization = getOption("sbom.organization"),
                           regid = getOption("sbom.regid"),
                           timestamp = NULL, overrides = NULL,
                           embedded = TRUE, system = TRUE, advisories = FALSE,
                           advisories_on_error = c("error", "continue")) {
  on_error <- check_advisories_args(advisories, advisories_on_error)
  check_lib(lib)
  regid <- check_regid(regid)
  lookup <- library_lookup(lib)
  base <- base_packages()
  if (is.null(pkgs)) {
    db <- lookup$all()
    n_installed <- nrow(db)
    pkgs <- db$package[!db$package %in% base]
    listed_base <- db$package[db$package %in% base]
  } else {
    n_installed <- nrow(library_index(lib))
    pkgs <- unique(as.character(pkgs))
    absent <- setdiff(pkgs[!vapply(pkgs, function(p) !is.null(lookup$get(p)), NA)], base)
    if (length(absent) > 0L) {
      cli::cli_abort("{.val {absent}} {?is/are} not installed in {.file {lib}}.")
    }
    listed_base <- intersect(pkgs, base)
  }
  pkgs <- sort(pkgs, method = "radix")
  # The listed packages are resolved as the Imports of a stand-in root, whose
  # edges are replaced by `contains` below.
  root_desc <- c(Package = installed_root_name(), Imports = paste(pkgs[!pkgs %in% base], collapse = ", "))
  root <- list(
    component = component_row(
      ref = "r-library", name = enc2utf8_bytes(as.character(name)),
      type = "platform", ecosystem = "library",
      is_root = TRUE, scope = "required", evidence = "observed", source_input = "library"
    ),
    issues = empty_issues()
  )
  if (n_installed == 0L) {
    root$issues <- add_issue(
      root$issues, root$component$ref, "library", "library-empty",
      "The library sbom read holds no installed packages."
    )
  }
  inputs <- data.frame(
    kind = rep("library", length(lib)), path = as.character(lib),
    stringsAsFactors = FALSE
  )
  x <- build_sbom(
    root = root, lookup = lookup, root_desc = root_desc,
    fields = c("Depends", "Imports", "LinkingTo"), root_suggests = FALSE,
    lib = lib, r_version = r_version, author = author,
    organization = organization, regid = regid, timestamp = timestamp,
    inputs = inputs, extra_base = listed_base, embedded = embedded,
    system = system
  )
  apply_advisories(apply_overrides(x, overrides), advisories, on_error)
}

# The placeholder package name of the root of a library build.
installed_root_name <- function() ".sbom-library-root"

# Every library path must exist. read_library() skips missing ones, which
# would otherwise give a confident but empty SBOM.
check_lib <- function(lib, call = parent.frame()) {
  lib <- as.character(lib)
  missing <- lib[is.na(lib) | !dir.exists(lib)]
  if (length(missing) > 0L) {
    cli::cli_abort(
      "{cli::qty(length(missing))}The librar{?y/ies} {.file {missing}} do{?es/} not exist.",
      call = call
    )
  }
}

# One string, without leading or trailing white space, or NA for none: NULL,
# NA and blank strings mean no regid.
check_regid <- function(regid, call = parent.frame()) {
  if (is.null(regid)) {
    return(NA_character_)
  }
  if (length(regid) != 1L || !(is.character(regid) || is.na(regid))) {
    cli::cli_abort(
      "{.arg regid} must be a single string, not {.obj_type_friendly {regid}}.",
      call = call
    )
  }
  regid <- trimws(enc2utf8_bytes(as.character(regid)))
  if (is.na(regid) || !nzchar(regid)) NA_character_ else regid
}

# Shared by every builder. `root` is list(component, issues). For a library
# root, `root_desc` is a stand-in whose Imports are the listed packages; an
# issue that would name a stand-in names the root component instead.
#
# sbom_renv() already knows its packages, so it passes `resolved`, a list like
# resolve_dependencies() returns whose edges may also have an `evidence`
# column (default "declared"). Its records come from a lock file rather than
# a library: `package_evidence` and `package_source` give their evidence and
# source, `where` says where a missing dependency is not and `missing_code`
# is its issue code, `r_evidence` overrides the evidence for an exact R
# version, and `all_required` makes every package required, since a lock
# file lists what the project needs. `not_installed`
# names the records that lacked a field and that no installed copy of the
# same version could fill.
build_sbom <- function(...) {
  # What the operating system and the library folders say is asked once in
  # this build, and forgotten after it.
  with_sys_cache(build_sbom_cached(...))
}

# The body of build_sbom(), run inside its per-build system cache. Takes the
# same arguments.
build_sbom_cached <- function(root, lookup, root_desc, fields, root_suggests, lib,
                       r_version, author, organization, regid, timestamp,
                       inputs, extra_base = character(), resolved = NULL,
                       package_evidence = "observed", package_source = "library",
                       where = "installed in the library sbom read",
                       missing_code = "dependency-not-installed", r_evidence = NULL,
                       all_required = FALSE, not_installed = character(),
                       embedded = TRUE, system = TRUE, source_dir = NULL, detect_lib = lib) {
  root_row <- root$component
  root_is_library <- identical(root_row$ecosystem, "library")
  root_name <- root_desc[["Package"]]
  res <- if (is.null(resolved)) {
    resolve_dependencies(root_desc, lookup, fields, root_suggests)
  } else {
    resolved
  }
  edges <- res$edges
  base <- base_packages()

  # Scope: optional when no non-Suggests edge reaches the target.
  required_to <- unique(edges$to[edges$field != "Suggests"])
  scope_of <- function(name) {
    if (all_required || name %in% required_to) "required" else "optional"
  }

  # Library packages and their issues.
  issues <- root$issues
  comps <- list(root_row)
  ref_of <- character()
  for (pkg in res$packages) {
    out <- package_component(
      lookup$get(pkg), package_evidence, package_source,
      scope = scope_of(pkg), library_checked = pkg %in% not_installed
    )
    comps[[length(comps) + 1L]] <- out$component
    issues <- rbind(issues, out$issues)
    ref_of[[pkg]] <- out$component$ref
  }

  # Missing packages.
  for (pkg in res$missing) {
    row <- unknown_component(pkg)
    row$scope <- scope_of(pkg)
    comps[[length(comps) + 1L]] <- row
    ref_of[[pkg]] <- row$ref
  }
  issues <- dependency_issues(
    issues, edges, res, ref_of, lookup, root_name, root_row$name, where, missing_code
  )

  # R and base packages.
  base_edge <- unique(edges$to[edges$to %in% base])
  base_used <- sort(unique(c(base_edge, extra_base)), method = "radix")
  r <- resolve_r_version(lib, r_version, root_desc, lapply(res$packages, lookup$get))
  r_rows <- r_components(r$version, r$version_is, r$stated_spec, base_used, r_evidence)
  base_scope <- vapply(base_used, function(p) {
    if (p %in% edges$to && !p %in% required_to) "optional" else "required"
  }, "")
  if (length(base_used) > 0L) {
    r_rows$scope[match(paste0("R/", base_used), r_rows$ref)] <- unname(base_scope)
  }
  all_comps <- do.call(rbind, c(comps, list(r_rows)))
  all_comps <- all_comps[order(all_comps$ref, method = "radix"), , drop = FALSE]
  rownames(all_comps) <- NULL

  rels <- package_relationships(edges, base_used, ref_of, root_row$ref, root_name, root_is_library)
  if (embedded) {
    inside <- linkingto_components(all_comps, rels, lookup, where)
    vendored <- detect_bundled(
      all_comps, root_row$ref, source_dir, root_desc, lookup, detect_lib
    )
    inside <- list(
      components = rbind(inside$components, vendored$components),
      relationships = rbind(inside$relationships, vendored$relationships),
      issues = rbind(inside$issues, vendored$issues)
    )
    all_comps <- rbind(all_comps, inside$components)
    all_comps <- all_comps[order(all_comps$ref, method = "radix"), , drop = FALSE]
    rownames(all_comps) <- NULL
    rels <- rbind(rels, inside$relationships)
    issues <- rbind(issues, inside$issues)
  }
  if (system) {
    sys <- declared_system_requirements(all_comps)
    all_comps <- sys$components
    rels <- rbind(rels, sys$relationships)
    issues <- rbind(issues, sys$issues)
    linked <- linked_system_libraries(all_comps, detect_lib, rels)
    all_comps <- linked$components
    rels <- rbind(rels, linked$relationships)
    issues <- rbind(issues, linked$issues)
  } else {
    all_comps$system_requirements <- NA_character_
  }
  rels <- rels[!duplicated(rels[c("from", "to", "field")]), , drop = FALSE]
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL

  who <- sbom_authorship(author, organization, regid, issues, root_row$ref)
  issues <- who$issues

  suggests_only <- vapply(c(res$packages, res$missing), scope_of, "") == "optional"
  notes <- c(
    if (identical(r$version_is, "minimum") && !is.na(r$version)) {
      paste0("R is listed at the lowest version stated, ", r$stated_spec, ".")
    } else if (is.na(r$version)) {
      "R is listed without a version, since no minimum is stated."
    },
    if (any(suggests_only)) {
      "Packages listed only under Suggests are included, but their own dependencies were not read."
    },
    checksum_note(),
    "Download locations are not recorded, since sbom did not look up any package repository.",
    timestamp_notes(timestamp)
  )
  timestamp <- resolve_timestamp(timestamp)
  new_sbom(
    list(
      root = root_row$ref,
      timestamp = timestamp,
      author = who$author,
      organization = who$organization,
      tool_version = as.character(utils::packageVersion("sbom")),
      notes = notes,
      inputs = inputs,
      regid = who$regid
    ),
    all_comps, rels, issues
  )
}

# `issues` with those about the dependencies in `edges`: each package in
# `res$missing` that a package names but that is not `where` (issue code
# `missing_code`), and each installed package whose version misses a
# constraint on it. `ref_of` gives each package's ref, `lookup` its record,
# and a stand-in root, `root_name`, is named `root_label`.
dependency_issues <- function(issues, edges, res, ref_of, lookup, root_name, root_label,
                              where, missing_code) {
  gone <- edges[edges$to %in% res$missing, , drop = FALSE]
  gone <- gone[!duplicated(gone[c("from", "to")]), , drop = FALSE]
  gone$from[gone$from == root_name] <- root_label
  for (i in seq_len(nrow(gone))) {
    issues <- add_issue(
      issues, ref_of[[gone$to[[i]]]], "dependencies", missing_code,
      paste0(
        gone$to[[i]], " is named as a dependency of ", gone$from[[i]],
        " but is not ", where, ", so its version and ",
        "source are unknown."
      )
    )
  }
  checked <- edges[!is.na(edges$constraint) & edges$to %in% res$packages, , drop = FALSE]
  for (i in seq_len(nrow(checked))) {
    record <- lookup$get(checked$to[[i]])
    have <- if ("Version" %in% names(record)) trimws(record[["Version"]]) else NA_character_
    if (isFALSE(constraint_satisfied(have, checked$constraint[[i]]))) {
      issues <- add_issue(
        issues, ref_of[[checked$to[[i]]]], "version", "constraint-unsatisfied",
        paste0(
          pkg_label(checked$to[[i]], have), " is installed, but ",
          checked$from[[i]], " requires ", checked$spec[[i]], "."
        )
      )
    }
  }
  issues
}

# The relationships of a build: one for each edge between packages, by ref
# (`ref_of` for packages, "R" and "R/<name>" for R and the base packages, and
# `root_ref` for the root, named `root_name` in `edges`), one from R to each
# base package in `base_used`, and, for a library root, one from the root to
# each package it lists instead of its edges.
package_relationships <- function(edges, base_used, ref_of, root_ref, root_name, root_is_library) {
  base <- base_packages()
  ref_for <- function(name) {
    ifelse(name == "R", "R",
      ifelse(name %in% base, paste0("R/", name),
        ifelse(name == root_name, root_ref, unname(ref_of[name]))
      )
    )
  }
  rels <- empty_relationships()
  keep <- if (root_is_library) edges$from != root_name else rep(TRUE, nrow(edges))
  declared <- edges[keep, , drop = FALSE]
  if (nrow(declared) > 0L) {
    rels <- rbind(rels, data.frame(
      from = ref_for(declared$from), to = ref_for(declared$to),
      field = declared$field, spec = declared$spec,
      evidence = if (is.null(declared$evidence)) "declared" else declared$evidence,
      stringsAsFactors = FALSE
    ))
  }
  if (length(base_used) > 0L) {
    rels <- rbind(rels, data.frame(
      from = "R", to = paste0("R/", base_used), field = "contains",
      spec = NA_character_, evidence = "inferred", stringsAsFactors = FALSE
    ))
  }
  if (root_is_library) {
    listed <- ref_for(unique(edges$to[edges$from == root_name & !edges$to %in% base]))
    if (length(listed) > 0L) {
      rels <- rbind(rels, data.frame(
        from = root_ref, to = listed, field = "contains",
        spec = NA_character_, evidence = "observed", stringsAsFactors = FALSE
      ))
    }
  }
  rels
}

# Who made an SBOM, as its metadata stores it (`author`, `organization` and
# `regid`, each NA when not given), and `issues` with those about it added
# at `root`, as info: that no author or organization was given, and that an
# organization was given without a regid.
sbom_authorship <- function(author, organization, regid, issues, root) {
  has_value <- function(x) !is.null(x) && length(x) == 1L && !is.na(x) && nzchar(x)
  authors <- enc2utf8_bytes(as.character(author))
  authors <- authors[!is.na(authors) & nzchar(trimws(authors))]
  organization <- enc2utf8_bytes(as.character(organization))
  if (length(authors) == 0L && !has_value(organization)) {
    issues <- add_issue(
      issues, root, "author", "no-sbom-author",
      paste0(
        "No author or organization was given for this SBOM, so only the tool ",
        "that made it is recorded."
      ),
      severity = "info"
    )
  }
  if (has_value(organization) && !has_value(regid)) {
    issues <- add_issue(
      issues, root, "regid", "regid-missing",
      paste0(
        "No regid was given for ", organization, ", so a SWID tag names it ",
        "with the placeholder http://invalid.unavailable."
      ),
      severity = "info"
    )
  }
  rownames(issues) <- NULL
  list(
    author = if (length(authors) > 0L) authors else NA_character_,
    organization = if (has_value(organization)) organization else NA_character_,
    regid = if (has_value(regid)) as.character(regid) else NA_character_,
    issues = issues
  )
}

# The SBOM note that says which checksums are on record.
checksum_note <- function() {
  "Checksums are only those of files sbom read itself, and a component without one has none on record."
}

# Exact when asked for, or when lib is the library search path. Otherwise the
# highest `R (>= x)` stated by the root or the packages listed, the root
# winning ties.
resolve_r_version <- function(lib, r_version, root_desc, descs) {
  if (!is.null(r_version)) {
    return(list(version = as.character(r_version), version_is = "exact", stated_spec = NA_character_))
  }
  norm <- function(x) normalizePath(as.character(x), mustWork = FALSE)
  if (identical(norm(lib), norm(.libPaths()))) {
    return(list(version = as.character(getRversion()), version_is = "exact", stated_spec = NA_character_))
  }
  best <- list(version = NA_character_, version_is = NA_character_, stated_spec = NA_character_)
  best_v <- NULL
  for (desc in c(list(root_desc), descs)) {
    for (field in c("Depends", "Imports", "LinkingTo")) {
      value <- if (field %in% names(desc)) desc[[field]] else NA_character_
      deps <- parse_dep_field(value, field)
      deps <- deps[deps$name == "R" & grepl("^>=", deps$constraint), , drop = FALSE]
      for (i in seq_len(nrow(deps))) {
        v <- tryCatch(
          package_version(trimws(sub("^>=", "", deps$constraint[[i]]))),
          error = function(e) NULL
        )
        if (!is.null(v) && (is.null(best_v) || v > best_v)) {
          best_v <- v
          best <- list(
            version = as.character(v), version_is = "minimum",
            stated_spec = deps$spec[[i]]
          )
        }
      }
    }
  }
  best
}
