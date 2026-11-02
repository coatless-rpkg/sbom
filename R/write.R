#' Write an SBOM to disk
#'
#' Serialises an `<sbom>` object as UTF-8 text with `"\n"` line endings and a
#' trailing newline. Existing files are overwritten.
#'
#' @param x An `<sbom>` object from [sbom_package()] or [sbom_installed()].
#' @param path A file path, or a directory when `format = "all"` (created if
#'   missing).
#' @param format One of the `format` values in [sbom_formats()], or `"all"`.
#'   When `NULL`, the format is taken from the longest matching extension of
#'   `path`.
#' @param version Specification version. Applies to CycloneDX only; `NULL`
#'   uses the default. With `format = "all"` it applies to the CycloneDX files.
#' @return `path`, invisibly.
#' @export
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
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
    keys <- names(reg)
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
    cdx_keys <- keys[!keys %in% "spdx-json"]
    if (length(cdx_keys) == 0L) {
      cli::cli_abort("{.arg version} applies only to CycloneDX formats, not {.val {keys}}.")
    }
    allowed <- unique(unlist(lapply(reg[cdx_keys], function(r) r$versions)))
    if (!version %in% allowed) {
      cli::cli_abort("{.arg version} must be one of {.val {allowed}}, not {.val {version}}.")
    }
  }

  docs <- vapply(keys, function(key) {
    entry <- reg[[key]]
    v <- if (key == "spdx-json" || is.null(version)) entry$default_version else version
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
