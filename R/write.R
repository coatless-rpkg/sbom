#' Write an SBOM to disk
#'
#' Serializes an `<sbom>` object as UTF-8 text with `"\n"` line endings and a
#' trailing newline. Existing files are overwritten.
#'
#' @param x An `<sbom>` object from [sbom_package()] or [sbom_installed()].
#' @param path A file path, or a directory when `format = "all"` (created if
#'   missing).
#' @param format One of the `format` values in [sbom_formats()], or `"all"`.
#'   When `NULL`, the format is taken from the longest matching extension of
#'   `path`.
#' @param version Specification version. It applies to every format being
#'   written whose versions (see [sbom_formats()]) include it; the others use
#'   their default, so `format = "all"` with `version = "2.2"` writes SPDX 2.2
#'   and the default of each other format. It is an error when no format being
#'   written lists the version. `NULL` uses each format's default.
#'   CycloneDX 1.4 and 1.5 have no field for the organization that made the
#'   SBOM (their `manufacture` is the maker of the described component), so
#'   there it is written as the metadata property `sbom:organization`.
#' @details
#' The formats, with the `format` value, file extension and versions (the
#' default of each is in [sbom_formats()]: 1.6 for CycloneDX, 2.3 for SPDX 2.x):
#'
#' | `format`         | Output           | Extension       | Versions            |
#' |:-----------------|:-----------------|:----------------|:--------------------|
#' | `cyclonedx-json` | CycloneDX JSON   | `.cdx.json`     | 1.4, 1.5, 1.6, 1.7  |
#' | `cyclonedx-xml`  | CycloneDX XML    | `.cdx.xml`      | 1.4, 1.5, 1.6, 1.7  |
#' | `spdx-json`      | SPDX JSON        | `.spdx.json`    | 2.2, 2.3            |
#' | `spdx-yaml`      | SPDX YAML        | `.spdx.yaml`    | 2.2, 2.3            |
#' | `spdx-xml`       | SPDX XML         | `.spdx.xml`     | 2.2, 2.3            |
#' | `spdx-tv`        | SPDX tag-value   | `.spdx`         | 2.2, 2.3            |
#' | `spdx3-jsonld`   | SPDX 3 JSON-LD   | `.spdx3.jsonld` | 3.0.1               |
#' | `swid`           | SWID tag         | `.swidtag`      | 2015                |
#' | `csv`            | CSV inventory    | `.csv`          | none                |
#'
#' `format = "all"` writes the eight standard formats, each at its default
#' version unless `version` names one it lists, into the directory `path`. The
#' files are named after the root component, as `<name>-<version>` followed by
#' the extension, or `<name>` alone when the root has no version. The CSV
#' inventory is not part of `"all"`.
#'
#' The SWID tag names the organization that made the SBOM by its registration
#' id (regid). [sbom_package()] and [sbom_installed()] take it from their
#' `regid` argument, whose default is the `sbom.regid` option; without one the
#' tag uses the placeholder `http://invalid.unavailable`. The tag's `tagId` is
#' the regid without its scheme or a trailing `/`, then a `/` and the root's
#' reference, such as `example.org/pkg:cran/dplyr@1.2.1` (the reference alone
#' without a regid), and its `tagVersion` is the date of the timestamp as
#' `YYYYMMDD`.
#'
#' `format = "csv"` writes a component inventory for spreadsheet review. It is
#' not an SBOM standard, is left out of `format = "all"`, and takes no
#' `version`. In every column, a value that starts with `=`, `+`, `-`, `@`, a
#' tab or a carriage return gets a leading apostrophe, so a spreadsheet does
#' not evaluate it as a formula. Real names, versions, dates and identifiers
#' never start that way, so they are unchanged. The file starts with a UTF-8
#' byte-order mark so that spreadsheets read it as UTF-8; in R, read it with
#' `read.csv(path, fileEncoding = "UTF-8-BOM")`.
#' @return `path`, invisibly.
#' @export
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
#' write_sbom(x, file.path(tempdir(), "sbom.cdx.json"))
write_sbom <- function(x, path, format = NULL, version = NULL) {
  if (!inherits(x, "sbom")) {
    cli::cli_abort("{.arg x} must be an {.cls sbom} object, not {.obj_type_friendly {x}}.")
  }
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    cli::cli_abort("{.arg path} must be a single string.")
  }
  reg <- format_registry()
  exts <- vapply(reg, function(r) r$extension, character(1))
  if (!is.null(format)) {
    if (!is.character(format) || length(format) != 1L ||
          !format %in% c(names(reg), "all")) {
      cli::cli_abort(c(
        "{.arg format} must be one of {.val {c(names(reg), 'all')}}.",
        "i" = "Known extensions: {.val {unname(exts)}}."
      ))
    }
  }
  if (!is.null(version) &&
        (!is.character(version) || length(version) != 1L || is.na(version))) {
    cli::cli_abort("{.arg version} must be a single string.")
  }

  if (identical(format, "all")) {
    keys <- names(reg)[vapply(reg, function(r) isTRUE(r$all), logical(1))]
  } else {
    if (is.null(format)) {
      hit <- names(reg)[endsWith(tolower(path), exts)]
      if (length(hit) == 0L) {
        cli::cli_abort(c(
          "Can't infer the format from {.file {path}}.",
          "i" = "Known extensions: {.val {unname(exts)}}.",
          "i" = "Known formats: {.val {names(reg)}}."
        ))
      }
      format <- hit[which.max(nchar(exts[hit]))]
    }
    keys <- format
  }

  if (!is.null(version)) {
    listed <- vapply(reg[keys], function(r) version %in% r$versions, logical(1))
    if (!any(listed)) {
      each <- vapply(reg[keys], function(r) {
        versions <- if (length(r$versions) > 0L) {
          paste(r$versions, collapse = ", ")
        } else {
          "takes no version"
        }
        paste0(r$name, " (", versions, ")")
      }, character(1))
      names(each) <- rep("*", length(each))
      cli::cli_abort(c(
        "{.arg version} {.val {version}} is not a version of any format being written.",
        each
      ))
    }
  }

  docs <- vapply(keys, function(key) {
    entry <- reg[[key]]
    v <- if (!is.null(version) && version %in% entry$versions) version else entry$default_version
    entry$writer(x, v)
  }, character(1))

  if (identical(format, "all")) {
    dir.create(path, recursive = TRUE, showWarnings = FALSE)
    root <- x$components[x$components$is_root, , drop = FALSE]
    stem <- if (is.na(root$version[1])) root$name[1] else paste0(root$name[1], "-", root$version[1])
    stem <- gsub("[^A-Za-z0-9._-]", "-", stem)
    paths <- file.path(path, paste0(stem, exts[keys]))
  } else {
    paths <- path
  }

  for (i in seq_along(keys)) {
    write_text(docs[[i]], paths[i])
  }
  invisible(path)
}

write_text <- function(txt, path) {
  con <- file(path, open = "wb")
  on.exit(close(con), add = TRUE)
  writeBin(charToRaw(enc2utf8(txt)), con)
}
