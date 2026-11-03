# Fields whose line breaks are kept until parse_dep_field() splits them.
dep_fields <- c("Depends", "Imports", "LinkingTo", "Suggests", "Enhances")

# Reads a DESCRIPTION from a package directory, a DESCRIPTION file or a
# source tarball. Returns a named character vector in UTF-8. Fields that are
# missing stay absent; the caller decides what that means.
#
# read.dcf() returns the file's bytes marked as native, whatever they are, so
# the text is decoded from those bytes and never through the locale: a
# declared Encoding is converted from, and otherwise valid UTF-8 is marked as
# such and anything else is read as latin1.
read_description <- function(path) {
  file <- description_file(path)
  dcf <- tryCatch(
    read.dcf(file, keep.white = dep_fields),
    error = function(e) {
      cli::cli_abort("Can't read a {.file DESCRIPTION} from {.file {path}}.", parent = e)
    }
  )
  if (nrow(dcf) < 1L) {
    cli::cli_abort("{.file {path}} holds no {.file DESCRIPTION} fields.")
  }
  out <- dcf[1L, ]
  encoding <- if ("Encoding" %in% names(out)) trimws(out[["Encoding"]]) else NA_character_
  converted <- NULL
  if (!is.na(encoding) && !toupper(encoding) %in% c("UTF-8", "UTF8", "")) {
    converted <- tryCatch(
      iconv(out, from = encoding, to = "UTF-8", sub = "byte"),
      error = function(e) NULL
    )
  }
  if (is.null(converted)) {
    # UTF-8, no Encoding or an unsupported one: keep valid UTF-8, read the
    # rest as latin1.
    bad <- !validUTF8(out)
    converted <- out
    converted[bad] <- iconv(out[bad], from = "latin1", to = "UTF-8")
  }
  Encoding(converted) <- "UTF-8"
  out[] <- converted
  out
}

description_file <- function(path) {
  if (!is.character(path) || length(path) != 1L || is.na(path) || !file.exists(path)) {
    cli::cli_abort("{.file {path}} does not exist.")
  }
  if (dir.exists(path)) {
    file <- file.path(path, "DESCRIPTION")
    if (!file.exists(file)) {
      cli::cli_abort("{.file {path}} holds no {.file DESCRIPTION}.")
    }
    return(file)
  }
  if (grepl("\\.(tar\\.gz|tgz|tar)$", path)) {
    members <- tryCatch(
      utils::untar(path, list = TRUE),
      error = function(e) {
        cli::cli_abort("Can't read the archive {.file {path}}.", parent = e)
      }
    )
    member <- members[grepl("^(\\./)?[^/]+/DESCRIPTION$", members)]
    if (length(member) < 1L) {
      cli::cli_abort("{.file {path}} holds no {.file DESCRIPTION}.")
    }
    exdir <- tempfile("sbom-desc-")
    dir.create(exdir)
    utils::untar(path, files = member[[1L]], exdir = exdir)
    return(file.path(exdir, member[[1L]]))
  }
  path
}

# Splits a dependency field into one row per entry.
parse_dep_field <- function(x, field) {
  empty <- data.frame(
    name = character(), constraint = character(), spec = character(),
    field = character(), stringsAsFactors = FALSE
  )
  if (length(x) != 1L || is.na(x) || !nzchar(trimws(x))) {
    return(empty)
  }
  parts <- gsub("\\s+", " ", trimws(strsplit(x, ",", fixed = TRUE)[[1L]]))
  parts <- parts[nzchar(parts)]
  if (length(parts) == 0L) {
    return(empty)
  }
  name <- trimws(sub("\\(.*$", "", parts))
  has_con <- grepl("(", parts, fixed = TRUE)
  constraint <- ifelse(has_con, trimws(sub("\\).*$", "", sub("^[^(]*\\(", "", parts))), NA_character_)
  data.frame(
    name = name, constraint = constraint, spec = parts,
    field = rep(field, length(parts)), stringsAsFactors = FALSE
  )
}

# The name alone, as R Observatory keeps it.
parse_maintainer <- function(x) {
  na <- c(name = NA_character_, email = NA_character_)
  if (length(x) != 1L || is.na(x)) {
    return(na)
  }
  x <- gsub("\\s+", " ", trimws(x))
  email <- regmatches(x, regexpr("<[^>]*>", x))
  email <- if (length(email)) trimws(gsub("^<|>$", "", email)) else NA_character_
  name <- trimws(gsub("\\s*<[^>]*>", "", x))
  name <- gsub("^[ \t\"']+|[ \t\"']+$", "", name)
  c(name = if (nzchar(name)) name else NA_character_,
    email = if (!is.na(email) && nzchar(email)) email else NA_character_)
}

# Evaluates Authors@R only in an environment with no way out. Returns NULL
# when the text can't be read that way.
parse_authors <- function(x) {
  if (length(x) != 1L || is.na(x) || !nzchar(trimws(x))) {
    return(NULL)
  }
  env <- list2env(
    list(
      c = base::c, person = utils::person, list = base::list,
      paste = base::paste, paste0 = base::paste0
    ),
    parent = emptyenv()
  )
  people <- tryCatch(eval(parse(text = x, encoding = "UTF-8"), env), error = function(e) NULL)
  if (!inherits(people, "person") || length(people) == 0L) {
    return(NULL)
  }
  rows <- tryCatch(lapply(unclass(people), function(p) {
    name <- trimws(paste(c(p$given, p$family), collapse = " "))
    email <- if (length(p$email)) p$email[[1L]] else NA_character_
    roles <- if (length(p$role)) paste(p$role, collapse = ", ") else NA_character_
    comment <- p$comment
    orcid <- if (!is.null(names(comment)) && "ORCID" %in% names(comment)) comment[["ORCID"]] else NULL
    data.frame(
      name = if (nzchar(name)) name else NA_character_,
      email = email, roles = roles,
      orcid = if (length(orcid)) orcid[[1L]] else NA_character_,
      stringsAsFactors = FALSE
    )
  }), error = function(e) NULL)
  if (is.null(rows)) {
    return(NULL)
  }
  out <- do.call(rbind, rows)
  # person() strings can come back marked native; the text is UTF-8.
  out[] <- lapply(out, enc2utf8_bytes)
  out
}

# Marks text as UTF-8 when its bytes are valid UTF-8, and leaves NA alone.
# Never converts through the locale.
enc2utf8_bytes <- function(x) {
  ok <- !is.na(x) & validUTF8(x)
  Encoding(x)[ok] <- "UTF-8"
  x
}

# Maintainer, else the cre in Authors@R, else NAs.
desc_maintainer <- function(desc) {
  field <- function(f) if (f %in% names(desc)) desc[[f]] else NA_character_
  m <- field("Maintainer")
  if (!is.na(m) && nzchar(trimws(m))) {
    return(parse_maintainer(m))
  }
  authors <- parse_authors(field("Authors@R"))
  if (!is.null(authors)) {
    cre <- authors[!is.na(authors$roles) & grepl("\\bcre\\b", authors$roles), , drop = FALSE]
    if (nrow(cre) > 0L) {
      return(c(name = cre$name[[1L]], email = cre$email[[1L]]))
    }
  }
  c(name = NA_character_, email = NA_character_)
}
