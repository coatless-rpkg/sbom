# Text from files of any origin, made safe to keep, to show and to quote. A
# control character (C0, DEL or C1) could rewrite the terminal it is printed
# on, and a value of any length quoted in a message could flood a report, so
# read_sbom() strips control characters from what it keeps, the printers show
# them as spaces, and messages quote a value through quote_value().

# `x` as UTF-8 text, whatever the locale: a string that is not marked but is
# valid UTF-8 is marked so, and invalid bytes become U+FFFD. Patterns then
# match characters, not bytes.
text_utf8 <- function(x) {
  x <- as.character(x)
  bad <- !is.na(x) & !validUTF8(x)
  if (any(bad)) {
    x[bad] <- iconv(x[bad], "UTF-8", "UTF-8", sub = "\ufffd")
  }
  unmarked <- !is.na(x) & Encoding(x) == "unknown"
  if (any(unmarked)) {
    y <- x[unmarked]
    Encoding(y) <- "UTF-8"
    x[unmarked] <- y
  }
  x
}

# `f` of the strings `x`, called once for the strings of each encoding. R
# matches strings of several encodings in one call otherwise than it matches
# each alone: in a C locale, a native string that is not ASCII, or a UTF-8
# string beside a Latin-1 one, is then an error. A writer that matched one
# string at a time can thus match many at once and still give the same.
by_encoding <- function(x, f) {
  enc <- Encoding(x)
  if (length(unique(enc)) <= 1L) {
    return(f(x))
  }
  unsplit(lapply(split(x, enc), f), enc)
}

# The pattern of the control characters a value may not keep: every one, or
# every one but tab and newline (`lines = TRUE`).
text_controls <- function(lines = FALSE) {
  if (lines) "[^\\P{Cc}\\t\\n]" else "\\p{Cc}"
}

# Whether each value holds a control character it may not keep.
text_has_controls <- function(x, lines = FALSE) {
  x <- text_utf8(x)
  !is.na(x) & grepl(text_controls(lines), x, perl = TRUE)
}

# `x` with each control character it may not keep replaced with a space.
# Without `lines`, a value that held one is then trimmed, and is NA when
# nothing is left.
text_strip <- function(x, lines = FALSE) {
  x <- text_utf8(x)
  hit <- !is.na(x) & grepl(text_controls(lines), x, perl = TRUE)
  if (!any(hit)) {
    return(x)
  }
  out <- gsub(text_controls(lines), " ", x[hit], perl = TRUE)
  if (!lines) {
    out <- trimws(out, whitespace = "[ \t\r\n]")
    out[!nzchar(out)] <- NA_character_
  }
  x[hit] <- out
  x
}

# Text for the console, where every control character is shown as a space.
printable <- function(x) {
  gsub("\\p{Cc}", " ", text_utf8(x), perl = TRUE)
}

# A value from a document as a message quotes it: printable, and cut to `max`
# characters, the last of them an ellipsis, when it is longer.
quote_value <- function(x, max = 80L) {
  x <- printable(x)
  long <- !is.na(x) & nchar(x, type = "chars") > max
  if (any(long)) {
    x[long] <- paste0(substr(x[long], 1L, max - 1L), "\u2026")
  }
  x
}

# Whether each element of `x` starts with a URL scheme and "://"; FALSE for NA.
is_url <- function(x) {
  !is.na(x) & grepl("^[A-Za-z][A-Za-z0-9+.-]*://", x)
}

# A URL without its credentials (user and password), query string and
# fragment, which can hold tokens. Anything that is not a URL is unchanged.
strip_url <- function(x) {
  url <- is_url(x)
  x[url] <- sub("[?#].*$", "", sub("^([A-Za-z][A-Za-z0-9+.-]*://)[^/]*@", "\\1", x[url]))
  x
}

# Items for a sentence, in the order given, with at most `cap` of them shown:
# "a, b and c", or "a, b, ..., t, and 5 more".
capped_list <- function(x, cap = 20L) {
  if (length(x) <= cap) {
    return(and_list(x))
  }
  paste0(paste(x[seq_len(cap)], collapse = ", "), ", and ", length(x) - cap, " more")
}
