# The <sbom> object: four tables (components, relationships, issues) plus
# metadata. Every later task builds, reads and writes this shape.

component_columns <- function() {
  c(
    "ref", "name", "version", "version_is", "type", "ecosystem", "is_root",
    "scope", "parent_ref", "purl", "supplier_name", "supplier_url",
    "maintainer", "license_as_written", "license_spdx", "license_comment",
    "published", "homepage", "vcs_url", "download_location",
    "package_file_name", "doi", "description", "bioc_release", "evidence",
    "source_input", "deps_known", "hashes", "deps", "asserted"
  )
}

relationship_columns <- function() c("from", "to", "field", "spec", "evidence")

issue_columns <- function() c("ref", "field", "severity", "code", "message")

metadata_names <- function() {
  c("root", "timestamp", "author", "organization", "tool_version", "notes", "inputs",
    "regid")
}

empty_df <- function(cols, logical = character(), list = character()) {
  out <- data.frame(row.names = character())
  for (col in cols) {
    out[[col]] <- if (col %in% logical) {
      logical()
    } else if (col %in% list) {
      vector("list", 0)
    } else {
      character()
    }
  }
  out
}

empty_components <- function() {
  empty_df(
    component_columns(),
    logical = c("is_root", "deps_known"),
    list = c("hashes", "deps", "asserted")
  )
}

empty_relationships <- function() empty_df(relationship_columns())

empty_issues <- function() empty_df(issue_columns())

check_columns <- function(x, required, what, call = parent.frame()) {
  missing <- setdiff(required, names(x))
  if (!is.data.frame(x) || length(missing) > 0) {
    cli::cli_abort(
      c(
        "{.arg {what}} must be a data frame with every required column.",
        "x" = "Missing {cli::qty(length(missing))}column{?s}: {.val {missing}}."
      ),
      call = call
    )
  }
}

new_sbom <- function(metadata, components, relationships, issues) {
  if (!is.list(metadata) || !all(metadata_names() %in% names(metadata))) {
    missing <- setdiff(metadata_names(), names(metadata))
    cli::cli_abort(c(
      "{.arg metadata} must have the elements {.val {metadata_names()}}.",
      "x" = "Missing: {.val {missing}}."
    ))
  }
  check_columns(components, component_columns(), "components")
  check_unique_refs(components$ref)
  check_columns(relationships, relationship_columns(), "relationships")
  check_columns(issues, issue_columns(), "issues")
  structure(
    list(
      metadata = metadata,
      components = components,
      relationships = relationships,
      issues = issues
    ),
    class = "sbom"
  )
}

# Every component has its own ref, which the writers use as its id, so two
# components that share one would make a broken document.
check_unique_refs <- function(refs, call = parent.frame()) {
  twice <- unique(refs[duplicated(refs)])
  if (length(twice) > 0L) {
    cli::cli_abort(
      "More than one component has the ref {.val {twice}}, and each needs its own.",
      call = call
    )
  }
}

add_issue <- function(issues, ref, field, code, message, severity = "warning") {
  row <- data.frame(
    ref = ref, field = field, severity = severity, code = code,
    message = message, stringsAsFactors = FALSE
  )
  rbind(issues, row[, names(issues), drop = FALSE])
}

document_notes <- function(x) {
  c(as.character(x$metadata$notes), unique(x$issues$message))
}

source_date_epoch <- function() Sys.getenv("SOURCE_DATE_EPOCH", unset = "")

# SOURCE_DATE_EPOCH, when set, wins over `timestamp` (spec section 11).
resolve_timestamp <- function(timestamp = NULL) {
  epoch <- source_date_epoch()
  if (nzchar(epoch)) {
    if (!grepl("^[0-9]+$", epoch)) {
      cli::cli_abort(
        "{.envvar SOURCE_DATE_EPOCH} must be integer seconds, not {.val {epoch}}."
      )
    }
    return(as.POSIXct(as.numeric(epoch), origin = "1970-01-01", tz = "UTC"))
  }
  if (is.null(timestamp)) {
    timestamp <- Sys.time()
  }
  # R before 4.3 needs an origin to convert a number.
  out <- if (is.numeric(timestamp)) {
    as.POSIXct(timestamp, origin = "1970-01-01", tz = "UTC")
  } else {
    as.POSIXct(timestamp, tz = "UTC")
  }
  attr(out, "tzone") <- "UTC"
  out
}

#' Read the tables of an sbom object
#'
#' Accessors for the three tables of an `<sbom>` object. Each returns its
#' data frame unchanged.
#'
#' @param x An `<sbom>` object, as returned by [sbom_package()] or
#'   [sbom_installed()].
#' @return A data frame. `sbom_components()` has one row per component,
#'   `sbom_dependencies()` one row per relationship (`from`, `to`, `field`,
#'   `spec`, `evidence`), and `sbom_issues()` one row per recorded issue
#'   (`ref`, `field`, `severity`, `code`, `message`).
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
#' sbom_components(x)
#' sbom_dependencies(x)
#' sbom_issues(x)
#' @export
#' @rdname sbom_components
sbom_components <- function(x) {
  check_sbom(x)
  x$components
}

#' @export
#' @rdname sbom_components
sbom_dependencies <- function(x) {
  check_sbom(x)
  x$relationships
}

#' @export
#' @rdname sbom_components
sbom_issues <- function(x) {
  check_sbom(x)
  x$issues
}

check_sbom <- function(x, arg = "x", call = parent.frame()) {
  if (!inherits(x, "sbom")) {
    cli::cli_abort("{.arg {arg}} must be an {.cls sbom} object.", call = call)
  }
}

#' @param ... Ignored.
#' @return `print.sbom()` returns `x` invisibly.
#' @export
#' @rdname sbom_components
print.sbom <- function(x, ...) {
  comps <- x$components
  root <- comps[comps$is_root %in% TRUE, , drop = FALSE][1, ]
  label <- node_label(root)
  n_issues <- nrow(x$issues)
  cat("<sbom> ", label, "\n", sep = "")
  cat("Components: ", nrow(comps), "\n", sep = "")
  cat("Relationships: ", nrow(x$relationships), "\n", sep = "")
  cat("Issues: ", n_issues,
    if (n_issues > 0) " (see sbom_issues())", "\n",
    sep = ""
  )
  invisible(x)
}
