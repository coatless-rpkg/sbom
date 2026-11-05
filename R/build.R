#' Build an SBOM for a package or an R library
#'
#' `sbom_package()` describes one package and everything it depends on.
#' `sbom_installed()` describes the packages in an R library. Both read the
#' `DESCRIPTION` files that are on disk and nothing else: they run no package
#' code and make no network requests.
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
#' `R (>= x)` found, is used as a minimum.
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
#'   regid. It must be a single string. `NULL`, `NA` and an empty or blank
#'   string mean none; then the tag uses the placeholder
#'   `http://invalid.unavailable`, and when an `organization` was given, an
#'   issue is recorded. The default is the `sbom.regid` option, as
#'   `author` and `organization` read `sbom.author` and `sbom.organization`.
#' @param timestamp The creation time, as a date-time or as seconds since
#'   1970-01-01 UTC. An explicit `timestamp` wins. Without one, the
#'   `SOURCE_DATE_EPOCH` environment variable is used when it is set, so that
#'   builds are reproducible, and a note says so; otherwise it is now. Nix sets
#'   `SOURCE_DATE_EPOCH` to 1980-01-01 in every `nix-shell`, and when the
#'   timestamp is that value a note says it is a placeholder.
#' @param overrides Values to assert where `sbom` found none, or found
#'   something different. `NULL`, a data frame or the path to a CSV file, with
#'   the character columns `component` (the `name` or `ref` of one
#'   component; embedded and system components only by `ref`), `field`,
#'   `value`, `asserted_by` and `reason`. `field` is one
#'   of `"version"`, `"license_spdx"`, `"supplier_name"`, `"supplier_url"`,
#'   `"maintainer"`, `"purl"` and `"download_location"`. Rows are applied in
#'   order, and each is recorded with who asserted it and why. An override
#'   that contradicts a found value wins and adds an `override-conflict` issue.
#'   Asserting `"version"` or `"purl"` changes only that field, not the `ref`.
#'   An unknown component or field, or a missing column, is an error.
#' @param embedded Whether to record the code that packages carry inside them.
#'   A package named in `LinkingTo` is recorded as an embedded component of
#'   the package that compiles it in, nested under that package, as
#'   inferred, at the version and with the licence that the library,
#'   lockfile or manifest records for it now. A C or C++ library that a package
#'   copies into its `src/` folder (source packages), or names in its
#'   `COPYRIGHTS` file or `cph` entries (source and installed packages), is
#'   recorded as a vendored component of that package, from the rules in
#'   `inst/extdata/vendored.csv`. The version is read from the library's
#'   header when there is one, and is otherwise unknown. A JavaScript or CSS
#'   library declared in htmlwidgets YAML, or found by the header comment of a
#'   file under `www/`, `htmlwidgets/lib/` or `lib/` (under `inst/` in source
#'   packages), is recorded as an npm component of that package, from the
#'   rules in `inst/extdata/javascript.csv`. Its licence is not read.
#' @param system Whether to detect system libraries. A package's
#'   `SystemRequirements` text is mapped to system libraries and programs
#'   with the rules of the pak package, when it is installed. sbom turns off
#'   pak's update of those rules, so pak uses the rules it has cached or
#'   ships and makes no network request. The shared libraries that installed
#'   compiled code links are read with `otool` (macOS) or `ldd` (Linux).
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
                         embedded = TRUE, system = TRUE) {
  dependencies <- match.arg(dependencies, several.ok = TRUE)
  check_lib(lib)
  regid <- check_regid(regid)
  root_desc <- read_description(path)
  if (!"Package" %in% names(root_desc) || !nzchar(trimws(root_desc[["Package"]]))) {
    cli::cli_abort("The {.file DESCRIPTION} at {.file {path}} has no {.field Package} field.")
  }
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
  inputs <- data.frame(
    kind = c("DESCRIPTION", rep("library", length(lib))),
    path = c(as.character(path), as.character(lib)),
    stringsAsFactors = FALSE
  )
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
  apply_overrides(x, overrides)
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
                           embedded = TRUE, system = TRUE) {
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
  apply_overrides(x, overrides)
}

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

# One string, or NA for none: NULL, NA and blank strings mean no regid.
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
  regid <- enc2utf8_bytes(as.character(regid))
  if (is.na(regid) || !nzchar(trimws(regid))) NA_character_ else regid
}

# Shared by every builder. `root` is list(component, issues). For a library
# root, `root_desc` is a stand-in whose Imports are the listed packages; an
# issue that would name a stand-in names the root component instead.
#
# sbom_renv() already knows its packages, so it passes `resolved`, a list like
# resolve_dependencies() returns whose edges may also have an `evidence`
# column (default "declared"). Its records come from a lock file rather than
# a library: `package_evidence` and `package_source` say so, `where` says
# where a missing dependency is not and `missing_code` is its issue code, `r_evidence` overrides the
# evidence for an exact R version, and `all_required` makes every package
# required, since a lock file lists what the project needs. `not_installed`
# names the records that lacked a field and that no installed copy of the
# same version could fill.
build_sbom <- function(root, lookup, root_desc, fields, root_suggests, lib,
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
  gone <- edges[edges$to %in% res$missing, , drop = FALSE]
  gone <- gone[!duplicated(gone[c("from", "to")]), , drop = FALSE]
  # A stand-in root is named by the root component's name.
  gone$from[gone$from == root_name] <- root_row$name
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

  # Constraints on installed packages.
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

  # Relationships.
  ref_for <- function(name) {
    ifelse(name == "R", "R",
      ifelse(name %in% base, paste0("R/", name),
        ifelse(name == root_name, root_row$ref, unname(ref_of[name]))
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
    listed <- c(
      ref_for(unique(edges$to[edges$from == root_name & !edges$to %in% base]))
    )
    if (length(listed) > 0L) {
      rels <- rbind(rels, data.frame(
        from = root_row$ref, to = listed, field = "contains",
        spec = NA_character_, evidence = "observed", stringsAsFactors = FALSE
      ))
    }
  }
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

  has_value <- function(x) !is.null(x) && length(x) == 1L && !is.na(x) && nzchar(x)
  authors <- enc2utf8_bytes(as.character(author))
  authors <- authors[!is.na(authors) & nzchar(trimws(authors))]
  organization <- enc2utf8_bytes(as.character(organization))
  if (length(authors) == 0L && !has_value(organization)) {
    issues <- add_issue(
      issues, root_row$ref, "author", "no-sbom-author",
      paste0(
        "No author or organization was given for this SBOM, so only the tool ",
        "that made it is recorded."
      ),
      severity = "info"
    )
  }
  if (has_value(organization) && !has_value(regid)) {
    issues <- add_issue(
      issues, root_row$ref, "regid", "regid-missing",
      paste0(
        "No regid was given for ", organization, ", so a SWID tag names it ",
        "with the placeholder http://invalid.unavailable."
      ),
      severity = "info"
    )
  }
  rownames(issues) <- NULL

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
      author = if (length(authors) > 0L) authors else NA_character_,
      organization = if (has_value(organization)) organization else NA_character_,
      tool_version = as.character(utils::packageVersion("sbom")),
      notes = notes,
      inputs = inputs,
      regid = if (has_value(regid)) as.character(regid) else NA_character_
    ),
    all_comps, rels, issues
  )
}

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
