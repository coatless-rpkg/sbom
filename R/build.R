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
#'   (`.tar.gz`). A tarball is also hashed.
#' @param dependencies The `DESCRIPTION` fields to follow, from `"Depends"`,
#'   `"Imports"`, `"LinkingTo"` and `"Suggests"`. Only the root's own
#'   `Suggests` are listed, and the packages they name are not followed.
#' @param lib Library paths to read installed packages from. When a package is
#'   in more than one, the first path wins, as it does when R loads it.
#' @param r_version The R version, as a string, to record exactly. `NULL`
#'   picks it as described in Details.
#' @param author,organization Who made the SBOM, recorded in its metadata.
#'   Without either, an issue is recorded.
#' @param timestamp The creation time. `NULL` means now, unless the
#'   `SOURCE_DATE_EPOCH` environment variable is set.
#' @param overrides Values to assert where `sbom` found none, or found
#'   something different. `NULL`, a data frame or the path to a CSV file, with
#'   the character columns `component` (the `name` or `ref` of one
#'   component), `field`, `value`, `asserted_by` and `reason`. `field` is one
#'   of `"version"`, `"license_spdx"`, `"supplier_name"`, `"supplier_url"`,
#'   `"maintainer"`, `"purl"` and `"download_location"`. Rows are applied in
#'   order, and each is recorded with who asserted it and why. An override
#'   that contradicts a found value wins and adds an `override-conflict` issue.
#'   Asserting `"version"` or `"purl"` changes only that field, not the `ref`.
#'   An unknown component or field, or a missing column, is an error.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
#' x
#' @export
sbom_package <- function(path = ".",
                         dependencies = c("Depends", "Imports", "LinkingTo", "Suggests"),
                         lib = .libPaths(), r_version = NULL,
                         author = getOption("sbom.author"),
                         organization = getOption("sbom.organization"),
                         timestamp = NULL, overrides = NULL) {
  dependencies <- match.arg(dependencies, several.ok = TRUE)
  root_desc <- read_description(path)
  if (!"Package" %in% names(root_desc) || !nzchar(trimws(root_desc[["Package"]]))) {
    cli::cli_abort("The {.file DESCRIPTION} at {.file {path}} has no {.field Package} field.")
  }
  root <- package_component(root_desc, "declared", "package", is_root = TRUE)
  if (file.exists(path) && !dir.exists(path) && grepl("\\.(tar\\.gz|tgz|tar)$", path)) {
    root$component$hashes <- list(data.frame(
      alg = "SHA-256", content = cli::hash_file_sha256(path), of = "source tarball",
      stringsAsFactors = FALSE
    ))
  }
  inputs <- data.frame(
    kind = c("package", rep("library", length(lib))),
    path = c(as.character(path), as.character(lib)),
    stringsAsFactors = FALSE
  )
  x <- build_sbom(
    root = root, db = read_library(lib), root_desc = root_desc,
    fields = intersect(c("Depends", "Imports", "LinkingTo"), dependencies),
    root_suggests = "Suggests" %in% dependencies, lib = lib,
    r_version = r_version, author = author, organization = organization,
    timestamp = timestamp, inputs = inputs
  )
  apply_overrides(x, overrides)
}

#' @rdname sbom_package
#' @param pkgs Names of the installed packages to list. `NULL` lists every
#'   package in `lib`. The dependencies of the listed packages are listed too.
#' @param name The name of the library, used for its root component.
#' @examples
#' sbom_installed("sbom")
#' @export
sbom_installed <- function(pkgs = NULL, lib = .libPaths(), name = "R library",
                           r_version = NULL, author = getOption("sbom.author"),
                           organization = getOption("sbom.organization"),
                           timestamp = NULL, overrides = NULL) {
  db <- read_library(lib)
  base <- base_packages()
  if (is.null(pkgs)) {
    pkgs <- db$package[!db$package %in% base]
    listed_base <- db$package[db$package %in% base]
  } else {
    pkgs <- unique(as.character(pkgs))
    listed_base <- intersect(pkgs, base)
  }
  pkgs <- sort(pkgs, method = "radix")
  # The listed packages are resolved as the Imports of a stand-in root, whose
  # edges are replaced by `contains` below.
  root_desc <- c(Package = installed_root_name(), Imports = paste(pkgs[!pkgs %in% base], collapse = ", "))
  root <- list(
    component = component_row(
      ref = "r-library", name = name, type = "platform", ecosystem = "library",
      is_root = TRUE, scope = "required", evidence = "observed", source_input = "library"
    ),
    issues = empty_issues()
  )
  inputs <- data.frame(
    kind = rep("library", length(lib)), path = as.character(lib),
    stringsAsFactors = FALSE
  )
  x <- build_sbom(
    root = root, db = db, root_desc = root_desc,
    fields = c("Depends", "Imports", "LinkingTo"), root_suggests = FALSE,
    lib = lib, r_version = r_version, author = author,
    organization = organization, timestamp = timestamp, inputs = inputs,
    extra_base = listed_base
  )
  apply_overrides(x, overrides)
}

installed_root_name <- function() ".sbom-library-root"

# Shared by sbom_package() and sbom_installed(). `root` is list(component,
# issues). For a library root, `root_desc` is a stand-in whose Imports are the
# listed packages.
build_sbom <- function(root, db, root_desc, fields, root_suggests, lib,
                       r_version, author, organization, timestamp, inputs,
                       extra_base = character()) {
  root_row <- root$component
  root_is_library <- identical(root_row$ecosystem, "library")
  root_name <- root_desc[["Package"]]
  root_label <- if (root_is_library) root_row$name else root_name
  res <- resolve_dependencies(root_desc, db, fields, root_suggests)
  edges <- res$edges
  base <- base_packages()

  # Scope: optional when no non-Suggests edge reaches the target.
  required_to <- unique(edges$to[edges$field != "Suggests"])
  scope_of <- function(name) if (name %in% required_to) "required" else "optional"

  # Library packages and their issues.
  issues <- root$issues
  comps <- list(root_row)
  ref_of <- character()
  for (pkg in res$packages) {
    i <- match(pkg, db$package)
    out <- package_component(db$desc[[i]], "observed", "library", scope = scope_of(pkg))
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
  pretty_from <- function(from) if (root_is_library && from == root_name) root_label else from
  gone <- edges[edges$to %in% res$missing, , drop = FALSE]
  gone <- gone[!duplicated(gone[c("from", "to")]), , drop = FALSE]
  for (i in seq_len(nrow(gone))) {
    issues <- add_issue(
      issues, ref_of[[gone$to[[i]]]], "dependencies", "dependency-not-installed",
      paste0(
        gone$to[[i]], " is named as a dependency of ", pretty_from(gone$from[[i]]),
        " but is not installed in the library sbom read, so its version and ",
        "source are unknown."
      )
    )
  }

  # Constraints on installed packages.
  checked <- edges[!is.na(edges$constraint) & edges$to %in% res$packages, , drop = FALSE]
  for (i in seq_len(nrow(checked))) {
    have <- db$version[[match(checked$to[[i]], db$package)]]
    if (isFALSE(constraint_satisfied(have, checked$constraint[[i]]))) {
      issues <- add_issue(
        issues, ref_of[[checked$to[[i]]]], "version", "constraint-unsatisfied",
        paste0(
          checked$to[[i]], " ", have, " is installed, but ",
          pretty_from(checked$from[[i]]), " requires ", checked$spec[[i]], "."
        )
      )
    }
  }

  # R and base packages.
  base_edge <- unique(edges$to[edges$to %in% base])
  base_used <- sort(unique(c(base_edge, extra_base)), method = "radix")
  r <- resolve_r_version(lib, r_version, root_desc, db$desc[match(res$packages, db$package)])
  r_rows <- r_components(r$version, r$version_is, r$stated_spec, base_used)
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
      field = declared$field, spec = declared$spec, evidence = "declared",
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
  rels <- rels[!duplicated(rels[c("from", "to", "field")]), , drop = FALSE]
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL

  has_value <- function(x) !is.null(x) && length(x) == 1L && !is.na(x) && nzchar(x)
  if (!has_value(author) && !has_value(organization)) {
    issues <- add_issue(
      issues, root_row$ref, "author", "no-sbom-author",
      paste0(
        "No author or organization was given for this SBOM, so only the tool ",
        "that made it is recorded."
      ),
      severity = "info"
    )
  }
  rownames(issues) <- NULL

  notes <- c(
    if (identical(r$version_is, "minimum") && !is.na(r$version)) {
      paste0("R is listed at the lowest version stated, ", r$stated_spec, ".")
    } else if (is.na(r$version)) {
      "R is listed without a version, since no minimum is stated."
    },
    "Checksums are only those of files sbom read itself, and a component without one has none on record.",
    "Download locations are not recorded, since sbom did not look up any package repository."
  )
  new_sbom(
    list(
      root = root_row$ref,
      timestamp = resolve_timestamp(timestamp),
      author = if (has_value(author)) as.character(author) else NA_character_,
      organization = if (has_value(organization)) as.character(organization) else NA_character_,
      tool_version = as.character(utils::packageVersion("sbom")),
      notes = notes,
      inputs = inputs
    ),
    all_comps, rels, issues
  )
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
