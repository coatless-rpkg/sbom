# SPDX YAML writer: a plain walk of the SPDX JSON document, as R Observatory
# writes it. Every string is a double-quoted JSON string, so no value can be
# read as anything but text. It is written by hand, so it needs no dependency.

# Strings as jsonlite writes them, in double quotes: a double quote and a
# backslash are escaped, a control character as \b, \t, \n, \f or \r, or
# else as \u00XX, the slash of "</" as "<\/", and anything else is kept as
# it is, in UTF-8. YAML, unlike JSON, does not allow DEL and the C1 controls
# (U+0080 to U+009F) raw, so they are written as \u00XX too. Only those
# characters change, so the bytes are matched as they are, a C1 control
# being the bytes C2 80 to C2 9F in UTF-8, and each string keeps its
# encoding. Calling jsonlite once a string took most of the time of writing
# a large SBOM.
json_quote <- function(x) {
  if (length(x) == 0L) {
    return(character())
  }
  x <- enc2utf8(x)
  hit <- grepl("[\"\\\001-\037\177]|\302[\200-\237]", x, useBytes = TRUE) |
    grepl("</", x, fixed = TRUE, useBytes = TRUE)
  if (any(hit)) {
    y <- x[hit]
    enc <- Encoding(y)
    y <- gsub("\\", "\\\\", y, fixed = TRUE, useBytes = TRUE)
    y <- gsub("\"", "\\\"", y, fixed = TRUE, useBytes = TRUE)
    for (code in 1:31) {
      escape <- switch(as.character(code),
        `8` = "\\b", `9` = "\\t", `10` = "\\n", `12` = "\\f", `13` = "\\r",
        sprintf("\\u%04x", code)
      )
      y <- gsub(rawToChar(as.raw(code)), escape, y, fixed = TRUE, useBytes = TRUE)
    }
    y <- gsub("\177", "\\u007f", y, fixed = TRUE, useBytes = TRUE)
    c1 <- grepl("\302[\200-\237]", y, useBytes = TRUE)
    if (any(c1)) {
      for (code in 0x80:0x9f) {
        y[c1] <- gsub(rawToChar(as.raw(c(0xc2, code))), sprintf("\\u%04x", code), y[c1], fixed = TRUE, useBytes = TRUE)
      }
    }
    y <- gsub("</", "<\\/", y, fixed = TRUE, useBytes = TRUE)
    Encoding(y) <- enc
    x[hit] <- y
  }
  paste0("\"", x, "\"")
}

yaml_scalar <- function(v) {
  if (is.logical(v)) {
    return(if (isTRUE(v)) "true" else "false")
  }
  if (is.numeric(v)) {
    return(format(v, scientific = FALSE, trim = TRUE))
  }
  if (is.character(v) && length(v) == 1L && !is.na(v)) {
    return(json_quote(v))
  }
  as.character(jsonlite::toJSON(as.character(v), auto_unbox = TRUE))
}

# A key that is a plain word is written bare, as R Observatory does; any other
# is quoted like a value. Vectorised over keys.
yaml_key <- function(k) {
  plain <- by_encoding(k, function(k) grepl("^[A-Za-z_][A-Za-z0-9_]*$", k))
  k[!plain] <- vapply(k[!plain], yaml_scalar, "", USE.NAMES = FALSE)
  k
}

# Lines for the children of `value` (a list) at indent level `level`. The
# keys and the strings of a mapping are each written in one call, and the
# lines of each child kept in a list and joined once: one call a string,
# and lines appended one by one, took most of a minute for a large SBOM.
yaml_lines <- function(value, level) {
  pad <- strrep("  ", level)
  is_map <- !is.null(names(value))
  heads <- if (is_map) paste0(pad, yaml_key(names(value)), ":") else rep(paste0(pad, "-"), length(value))
  value <- lapply(value, function(v) if (!is.list(v) && length(v) != 1L) as.list(v) else v)
  scalar <- !vapply(value, is.list, NA)
  text <- scalar & vapply(value, function(v) is.character(v) && length(v) == 1L && !is.na(v), NA)
  out <- vector("list", length(value))
  if (any(text)) {
    out[text] <- as.list(paste0(heads[text], " ", json_quote(as.character(unlist(value[text])))))
  }
  for (i in which(!text)) {
    v <- value[[i]]
    out[[i]] <- if (scalar[[i]]) {
      paste0(heads[[i]], " ", yaml_scalar(v))
    } else if (length(v) == 0L) {
      paste0(heads[[i]], " []")
    } else if (!is_map && !is.null(names(v))) {
      # A mapping inside a list starts on the dash's own line.
      inner <- yaml_lines(v, level + 1L)
      inner[1L] <- paste0(pad, "- ", substring(inner[1L], nchar(pad) + 3L))
      inner
    } else {
      c(heads[[i]], yaml_lines(v, level + 1L))
    }
  }
  as.character(unlist(out, use.names = FALSE))
}

yaml_emit <- function(value) {
  enc2utf8(paste0(paste(yaml_lines(value, 0L), collapse = "\n"), "\n"))
}

spdx_yaml <- function(x, version = "2.3") {
  yaml_emit(spdx_document(x, version))
}
