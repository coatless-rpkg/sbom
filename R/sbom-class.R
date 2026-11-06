# The <sbom> object: four tables (components, relationships, issues and
# advisories) plus metadata. Every later task builds, reads and writes this
# shape.

component_columns <- function() {
  c(
    "ref", "name", "version", "version_is", "type", "ecosystem", "is_root",
    "scope", "parent_ref", "purl", "supplier_name", "supplier_url",
    "maintainer", "license_as_written", "license_spdx", "license_comment",
    "published", "homepage", "vcs_url", "download_location",
    "package_file_name", "doi", "description", "bioc_release", "evidence",
    "source_input", "system_requirements", "deps_known", "hashes", "deps", "asserted"
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

advisory_columns <- function() {
  c("id", "summary", "published", "source_url", "upstream", "ratings", "affects")
}

# The advisories table with no rows, as osv_match() makes it: `upstream` is a
# list of character vectors, `ratings` a list of data frames of
# empty_ratings()'s columns, and `affects` a list of data frames of ref,
# version, fixed and no_fix.
empty_advisories <- function() {
  empty_df(advisory_columns(), list = c("upstream", "ratings", "affects"))
}

# The CVSS ratings of one advisory's upstream records, with no rows.
empty_ratings <- function() {
  data.frame(
    upstream = character(), method = character(), vector = character(),
    score = numeric(), severity = character(), stringsAsFactors = FALSE
  )
}

# metadata$advisories: whether advisories were asked for, where the data came
# from (a URL, or a file's basename), when it was downloaded, the latest
# `modified` time of its records, and the status, "listed", "not-requested"
# or "unavailable".
advisories_metadata <- function(requested = FALSE, source = NA_character_,
                                fetched = as.POSIXct(NA, tz = "UTC"),
                                newest_modified = NA_character_, status = "not-requested") {
  list(
    requested = requested, source = source, fetched = fetched,
    newest_modified = newest_modified, status = status
  )
}

# The status of an <sbom>'s advisories; "not-requested" when it has none
# recorded.
advisories_status <- function(x) {
  status <- x$metadata$advisories$status
  if (is_string(status)) status else "not-requested"
}

# The line of print() and summary() about the advisories.
advisories_line <- function(status, n) {
  switch(status,
    listed = paste0("Advisories: ", n, " listed by OSV for these exact versions."),
    unavailable = "Advisories: unavailable (see sbom_issues()).",
    "Advisories: not requested."
  )
}

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

new_sbom <- function(metadata, components, relationships, issues,
                     advisories = empty_advisories()) {
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
  check_columns(advisories, advisory_columns(), "advisories")
  if (is.null(metadata$advisories)) {
    metadata$advisories <- advisories_metadata()
  }
  structure(
    list(
      metadata = metadata,
      components = components,
      relationships = relationships,
      issues = issues,
      advisories = advisories
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

# The notes a document gives: the metadata's notes, then the issues. A note
# from a SWID tag read back may say that the tag has no place for
# advisories, which is said only in a SWID tag (`swid`); every other format
# leaves that sentence out, and says in its place, once, what is true of
# the file it writes: that no advisory data was on hand for it, unless it
# lists advisories.
document_notes <- function(x, swid = FALSE) {
  notes <- c(as.character(x$metadata$notes), unique(x$issues$message))
  if (swid) {
    return(notes)
  }
  said <- any(grepl(advisory_notes$swid, notes, fixed = TRUE))
  instead <- said && !any(grepl(advisory_notes$no_data, notes, fixed = TRUE)) &&
    nrow(written_advisories(x)) == 0L
  notes_without(notes, advisory_sentences$swid, with = if (instead) advisory_notes$no_data)
}

source_date_epoch <- function() Sys.getenv("SOURCE_DATE_EPOCH", unset = "")

# An explicit `timestamp` wins, then SOURCE_DATE_EPOCH, then the clock (spec
# section 11).
resolve_timestamp <- function(timestamp = NULL) {
  if (is.null(timestamp) && nzchar(source_date_epoch())) {
    epoch <- source_date_epoch()
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

# The notes that say where the timestamp came from: only when it comes from
# SOURCE_DATE_EPOCH, and then also when that is the 1980 placeholder that
# nix-shell and Nix builds set.
timestamp_notes <- function(timestamp = NULL) {
  epoch <- source_date_epoch()
  if (!is.null(timestamp) || !nzchar(epoch)) {
    return(character())
  }
  c(
    "The timestamp comes from the SOURCE_DATE_EPOCH environment variable.",
    if (grepl("^[0-9]+$", epoch) && as.numeric(epoch) == 315532800) {
      paste0(
        "The timestamp is 1980-01-01T00:00:00Z, the placeholder that Nix sets ",
        "in SOURCE_DATE_EPOCH, not the time this SBOM was made."
      )
    }
  )
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
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
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
  label <- printable(node_label(root))
  n_issues <- nrow(x$issues)
  cat("<sbom> ", label, "\n", sep = "")
  cat("Components: ", nrow(comps), "\n", sep = "")
  cat("Relationships: ", nrow(x$relationships), "\n", sep = "")
  cat("Issues: ", n_issues,
    if (n_issues > 0) " (see sbom_issues())", "\n",
    sep = ""
  )
  n_advisories <- if (is.data.frame(x$advisories)) nrow(x$advisories) else 0L
  cat(advisories_line(advisories_status(x), n_advisories), "\n", sep = "")
  invisible(x)
}
