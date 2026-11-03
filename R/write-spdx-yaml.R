# SPDX YAML writer: a plain walk of the SPDX JSON document, as R Observatory
# writes it. Every string is a double-quoted JSON string, so no value can be
# read as anything but text. It is written by hand, so it needs no dependency.

yaml_scalar <- function(v) {
  if (is.logical(v)) {
    return(if (isTRUE(v)) "true" else "false")
  }
  if (is.numeric(v)) {
    return(format(v, scientific = FALSE, trim = TRUE))
  }
  as.character(jsonlite::toJSON(as.character(v), auto_unbox = TRUE))
}

# A key that is a plain word is written bare, as R Observatory does; any other
# is quoted like a value.
yaml_key <- function(k) {
  if (grepl("^[A-Za-z_][A-Za-z0-9_]*$", k)) k else yaml_scalar(k)
}

# Lines for the children of `value` (a list) at indent level `level`.
yaml_lines <- function(value, level) {
  pad <- strrep("  ", level)
  is_map <- !is.null(names(value))
  out <- character()
  for (i in seq_along(value)) {
    v <- value[[i]]
    if (!is.list(v) && length(v) != 1L) v <- as.list(v)
    head <- if (is_map) paste0(pad, yaml_key(names(value)[i]), ":") else paste0(pad, "-")
    if (!is.list(v)) {
      out <- c(out, paste0(head, " ", yaml_scalar(v)))
    } else if (length(v) == 0L) {
      out <- c(out, paste0(head, " []"))
    } else if (!is_map && !is.null(names(v))) {
      # A mapping inside a list starts on the dash's own line.
      inner <- yaml_lines(v, level + 1L)
      inner[1L] <- paste0(pad, "- ", substring(inner[1L], nchar(pad) + 3L))
      out <- c(out, inner)
    } else {
      out <- c(out, head, yaml_lines(v, level + 1L))
    }
  }
  out
}

yaml_emit <- function(value) {
  enc2utf8(paste0(paste(yaml_lines(value, 0L), collapse = "\n"), "\n"))
}

spdx_yaml <- function(x, version = "2.3") {
  yaml_emit(spdx_document(x, version))
}
