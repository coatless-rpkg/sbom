# Parses Package URLs in the order the purl specification gives. Every component is percent-decoded
# except `qualifiers`, which is the raw text after `?`. A qualifier value may hold unencoded `:` and `/`.
# An invalid purl has `valid` FALSE, a lower-case clause in `problem` and NA components.
purl_parse <- function(x) {
  x <- as.character(x)
  ux <- unique(x)
  parts <- lapply(ux, purl_parse_one)
  i <- match(x, ux)
  field <- function(name, type) vapply(parts, `[[`, type, name)[i]
  data.frame(
    purl = x,
    valid = field("valid", logical(1)),
    problem = field("problem", character(1)),
    type = field("type", character(1)),
    namespace = field("namespace", character(1)),
    name = field("name", character(1)),
    version = field("version", character(1)),
    qualifiers = field("qualifiers", character(1)),
    subpath = field("subpath", character(1)),
    stringsAsFactors = FALSE
  )
}

# The parts of the package URL `x` as a list: valid, problem, type, namespace,
# name, version, qualifiers and subpath. When `x` is invalid, `problem` says why
# and the parts are NA.
purl_parse_one <- function(x) {
  fail <- function(problem) {
    list(valid = FALSE, problem = problem, type = NA_character_, namespace = NA_character_,
         name = NA_character_, version = NA_character_, qualifiers = NA_character_,
         subpath = NA_character_)
  }
  if (is.na(x)) {
    return(fail("it is missing"))
  }
  if (!validUTF8(x)) {
    return(fail("it is not valid UTF-8 text"))
  }
  Encoding(x) <- "UTF-8"
  if (grepl("%(?![0-9A-Fa-f]{2})", x, perl = TRUE)) {
    return(fail("it has a % that is not followed by two hex digits"))
  }
  if (grepl("%00", x, fixed = TRUE)) {
    return(fail("it encodes a NUL character"))
  }

  rest <- x
  subpath <- NA_character_
  if (grepl("#", rest, fixed = TRUE)) {
    subpath <- sub("^[^#]*#", "", rest)
    rest <- sub("#.*$", "", rest)
  }
  qualifiers <- NA_character_
  if (grepl("?", rest, fixed = TRUE)) {
    qualifiers <- sub("^[^?]*\\?", "", rest)
    rest <- sub("\\?.*$", "", rest)
  }
  if (!startsWith(rest, "pkg:")) {
    return(fail("it does not start with pkg:"))
  }
  rest <- sub("^/+", "", substring(rest, 5L))

  if (!grepl("/", rest, fixed = TRUE)) {
    type <- rest
    path <- ""
  } else {
    type <- sub("/.*$", "", rest)
    path <- sub("^[^/]*/", "", rest)
  }
  if (!grepl("^[A-Za-z][A-Za-z0-9.+-]*$", type)) {
    return(fail("it has no valid type"))
  }

  version <- NA_character_
  if (grepl("@", path, fixed = TRUE)) {
    version <- sub("^.*@", "", path)
    path <- sub("@[^@]*$", "", path)
    if (!nzchar(version)) {
      return(fail("it has an empty version after the @"))
    }
    if (grepl("/", version, fixed = TRUE)) {
      return(fail("it has an @ in its namespace or name that is not percent-encoded"))
    }
  }
  segments <- strsplit(path, "/", fixed = TRUE)[[1]]
  segments <- segments[nzchar(segments)]
  if (length(segments) == 0L) {
    return(fail("it has no name"))
  }
  name <- segments[[length(segments)]]
  namespace <- if (length(segments) > 1L) segments[-length(segments)] else character()

  if (!is.na(qualifiers)) {
    problem <- purl_qualifiers_problem(qualifiers)
    if (!is.na(problem)) {
      return(fail(problem))
    }
  }

  sub_segments <- character()
  if (!is.na(subpath)) {
    sub_segments <- strsplit(subpath, "/", fixed = TRUE)[[1]]
    sub_segments <- sub_segments[nzchar(sub_segments)]
    if (any(sub_segments %in% c(".", ".."))) {
      return(fail("it has a subpath segment that is . or .."))
    }
  }

  decoded <- lapply(list(type, namespace, name, version, sub_segments), pct_decode)
  if (!all(vapply(decoded, function(d) all(validUTF8(d)), logical(1)))) {
    return(fail("it has percent-encoding that is not valid UTF-8"))
  }
  list(
    valid = TRUE,
    problem = NA_character_,
    type = decoded[[1]],
    namespace = if (length(namespace)) paste(decoded[[2]], collapse = "/") else NA_character_,
    name = decoded[[3]],
    version = decoded[[4]],
    qualifiers = qualifiers,
    subpath = if (length(sub_segments)) paste(decoded[[5]], collapse = "/") else NA_character_
  )
}

# NA when the raw qualifier text is fine, otherwise a lower-case clause.
purl_qualifiers_problem <- function(qualifiers) {
  pairs <- strsplit(qualifiers, "&", fixed = TRUE)[[1]]
  if (!nzchar(qualifiers) || any(!nzchar(pairs))) {
    return("it has an empty qualifier")
  }
  has_eq <- grepl("=", pairs, fixed = TRUE)
  if (!all(has_eq)) {
    return("it has a qualifier with no = sign")
  }
  keys <- sub("=.*$", "", pairs)
  values <- sub("^[^=]*=", "", pairs)
  if (!all(grepl("^[A-Za-z][A-Za-z0-9._-]*$", keys))) {
    return("it has a qualifier with an invalid key")
  }
  if (anyDuplicated(tolower(keys))) {
    return("it has a qualifier key that appears twice")
  }
  if (!all(nzchar(values))) {
    return("it has a qualifier with an empty value")
  }
  NA_character_
}

# Decodes %XX sequences as UTF-8 bytes. The input has been checked to hold no malformed escape.
pct_decode <- function(x) {
  vapply(x, function(s) {
    if (is.na(s) || !grepl("%", s, fixed = TRUE)) {
      return(s)
    }
    bytes <- charToRaw(s)
    out <- raw()
    k <- 1L
    n <- length(bytes)
    while (k <= n) {
      if (bytes[[k]] == as.raw(0x25) && k + 2L <= n) {
        out <- c(out, as.raw(strtoi(rawToChar(bytes[(k + 1L):(k + 2L)]), 16L)))
        k <- k + 3L
      } else {
        out <- c(out, bytes[[k]])
        k <- k + 1L
      }
    }
    res <- rawToChar(out)
    Encoding(res) <- "UTF-8"
    res
  }, character(1), USE.NAMES = FALSE)
}
