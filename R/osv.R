# OSV security advisories (spec §9a), opt-in. OSV publishes the R Consortium
# advisory database as a zip of JSON records, CRAN/all.zip. sbom reads that
# zip entry by entry without extracting it, parses its records into two
# tables, matches them locally against the exact versions of an SBOM's CRAN
# packages, and computes CVSS 3 base scores from upstream vectors. The zip,
# downloaded or given as a path, is untrusted: every way it can be damaged is
# one classed error whose reason is a fixed phrase, and no message quotes its
# content beyond an entry name made only of letters, digits, dots,
# underscores and hyphens.

# OSV's CRAN export.
osv_cran_url <- "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip"

# The name of an entry that is an OSV record file, and the characters an
# entry name may be shown with in a message.
osv_entry_pattern <- "^[A-Za-z0-9._-]+\\.json$"
osv_shown_pattern <- "^[A-Za-z0-9._-]+$"

# Whether each id is an OSV id, such as RSEC-2023-0, CVE-2018-1000086 or
# GHSA-xxxx-xxxx-xxxx: a letter, then letters, digits and . _ : -, without
# "..". An id goes into URLs, requests and references, so a record whose id
# is anything else has no id sbom can use, and osv_lookup() sends no other.
osv_id_ok <- function(id) {
  !is.na(id) & grepl("^[A-Za-z][A-Za-z0-9._:-]*$", id, perl = TRUE, useBytes = TRUE) &
    !grepl("..", id, fixed = TRUE, useBytes = TRUE)
}

# The most the zip may unpack to, in mebibytes, and the most entries it may
# hold. Options, read through functions, so that tests can lower them. unz()
# finds each entry by reading the zip's directory from its start, so reading
# takes time in the square of the entry count: 2,000 entries take seconds
# where 10,000 took minutes. OSV's CRAN export holds a few dozen.
osv_max_mb <- function() osv_cap_option("sbom.osv_max_mb", 50)
# The most entries an OSV archive may hold, from the sbom.osv_max_entries
# option.
osv_max_entries <- function() osv_cap_option("sbom.osv_max_entries", 2000)

# The positive number in option `name`, or `default` when the option is unset or
# is not a single positive finite number.
osv_cap_option <- function(name, default) {
  value <- getOption(name, default)
  if (!is.numeric(value) || length(value) != 1L || !is.finite(value) || value <= 0) default else value
}

# A number for a sentence, never in scientific notation.
osv_number <- function(x) {
  format(x, scientific = FALSE, trim = TRUE)
}

# Raises the error whose message is `sentence`, a plain string, which the
# condition also keeps whole in its field `sentence`. Its field `reason` says
# what went wrong in a phrase that names the file by its basename or URL, for
# the issue that advisories_on_error = "continue" records.
osv_abort <- function(sentence, call, reason) {
  cli::cli_abort(
    "{sentence}", class = "sbom_advisories_error", sentence = sentence, reason = reason, call = call
  )
}

#' Where OSV's advisory data comes from
#'
#' @param advisories `TRUE`, for OSV's CRAN export, or the path of a copy of
#'   it.
#' @return `list(kind, location, label)`: kind `"url"` with the URL as
#'   location and label, or kind `"file"` with the path as location and its
#'   basename as label.
#' @noRd
osv_source <- function(advisories) {
  if (isTRUE(advisories)) {
    return(list(kind = "url", location = osv_cran_url, label = osv_cran_url))
  }
  list(kind = "file", location = advisories, label = read_file_label(advisories))
}

#' Fetch and read OSV's advisory data
#'
#' A URL is downloaded through `osv_download()` to a temporary file, which is
#' removed again, and a download larger than `osv_max_mb()` mebibytes is
#' refused before it is read; a local file is read where it is and never
#' touches the network.
#'
#' @param source From `osv_source()`.
#' @param timeout Seconds the download may take.
#' @param call The call errors are reported against.
#' @return `osv_read_zip()`'s list, plus `fetched`: when the download
#'   finished, as POSIXct in UTC, or NA for a local file. Errors have class
#'   `sbom_advisories_error`.
#' @noRd
osv_fetch <- function(source, timeout = 300, call = parent.frame()) {
  if (identical(source$kind, "url")) {
    dest <- tempfile("sbom-osv-", fileext = ".zip")
    on.exit(unlink(dest), add = TRUE)
    done <- osv_download(source$location, dest, timeout = timeout)
    if (!isTRUE(done)) {
      reason <- attr(done, "reason")
      if (!is_string(reason)) reason <- "the connection failed"
      osv_abort(paste0(
        "OSV's advisory data could not be downloaded from ", source$location, " (", reason, ")."
      ), call, paste0("the download failed: ", reason))
    }
    if (isTRUE(file.size(dest) > osv_max_mb() * 2^20)) {
      cap <- paste0(osv_number(osv_max_mb()), " MB")
      osv_abort(
        paste0("OSV's advisory data downloaded from ", source$location, " is larger than ", cap, "."), call,
        paste0("the download is larger than ", cap)
      )
    }
    fetched <- Sys.time()
    attr(fetched, "tzone") <- "UTC"
    path <- dest
  } else {
    path <- source$location
    if (!file.exists(path)) {
      osv_abort(
        paste0("The OSV advisory file ", printable(path), " does not exist."), call,
        paste0(source$label, " does not exist")
      )
    }
    fetched <- as.POSIXct(NA, tz = "UTC")
  }
  c(osv_read_zip(path, source$label, call), list(fetched = fetched))
}

#' Read OSV's zip of advisory records
#'
#' The central directory is read first: every entry must be named like an
#' OSV record file, there must be at most `osv_max_entries()` of them, and
#' together they must unpack to at most `osv_max_mb()` mebibytes. Then each
#' entry, in radix order of names, is read through `unz()`, never extracted,
#' and parsed as `read_document()` parses JSON. Each must have an OSV id and
#' be an OSV record that sbom can read (`osv_record_ok()`). Of two records
#' with one id, the first is kept. A zip none of whose records affects a
#' CRAN package is not OSV's CRAN export, and is damaged too.
#'
#' @param path Path of the zip.
#' @param label The zip's name in messages: a basename or a URL.
#' @param call The call errors are reported against.
#' @return `list(records, affected, newest_modified)`:
#'   * `records`: `data.frame(id, summary, published, modified, withdrawn,
#'     source_url, upstream)`, one row per record, sorted by id. Values are
#'     as written, with control characters as spaces; an empty one is NA.
#'     `source_url` is the first `affected[].database_specific.source`, and
#'     `upstream` a list of character vectors.
#'   * `affected`: `data.frame(id, package, ecosystem, kind, introduced,
#'     fixed, last_affected, version)`: one `"range"` row per interval of an
#'     `ECOSYSTEM` or `SEMVER` range, as `osv_intervals()` makes them from
#'     its events in the order OSV evaluates them, and one `"listed"` row per
#'     listed version. A bound that is an empty string, or not a string, is
#'     `""`, which no version can be compared with.
#'   * `newest_modified`: the latest `modified` time, as written, or NA.
#'
#'   Errors have class `sbom_advisories_error`, and say why the file is
#'   damaged in a fixed phrase.
#' @noRd
osv_read_zip <- function(path, label, call = parent.frame()) {
  damaged <- function(reason) {
    osv_abort(
      paste0("The OSV advisory file ", label, " is damaged: ", reason, "."), call,
      paste0(label, " is damaged: ", reason)
    )
  }
  listing <- tryCatch(
    utils::unzip(path, list = TRUE, unzip = "internal"),
    error = function(e) NULL,
    warning = function(w) NULL
  )
  if (!is.data.frame(listing)) {
    damaged("it is not a zip file")
  }
  entries <- as.character(listing$Name)
  sizes <- suppressWarnings(as.numeric(listing$Length))

  # Names are checked, byte by byte, before anything else is done with them:
  # a name in any other encoding is only bytes.
  fits <- function(pattern) !is.na(entries) & grepl(pattern, entries, perl = TRUE, useBytes = TRUE)
  bad <- which(!fits(osv_entry_pattern))
  if (length(bad) > 0L) {
    first <- bad[[1]]
    shown <- if (fits(osv_shown_pattern)[[first]]) paste0(", ", quote_value(entries[[first]]), ",") else ""
    damaged(paste0("it holds an entry", shown, " that is not an OSV record file"))
  }
  by_name <- order(entries, method = "radix")
  entries <- entries[by_name]
  sizes <- sizes[by_name]
  if (length(entries) > osv_max_entries()) {
    damaged(paste0("it holds more than ", osv_number(osv_max_entries()), " entries"))
  }
  cap <- osv_max_mb() * 2^20
  too_large <- function() damaged(paste0("it unpacks to more than ", osv_number(osv_max_mb()), " MB"))
  if (anyNA(sizes) || sum(sizes) > cap) {
    too_large()
  }

  docs <- vector("list", length(entries))
  ids <- character(length(entries))
  used <- 0
  for (k in seq_along(entries)) {
    entry <- quote_value(entries[[k]])
    # unz() gives no more than an entry declares, so the declared sizes
    # bound what is read. Should it give more, the byte past what is left
    # under the cap shows it.
    left <- cap - used
    bytes <- osv_entry_bytes(path, entries[[k]], min(sizes[[k]], left) + 1)
    if (is.null(bytes)) {
      damaged(paste0("the record ", entry, " is not valid JSON"))
    }
    if (length(bytes) > left) {
      too_large()
    }
    used <- used + length(bytes)
    doc <- osv_parse_record(bytes)
    if (is.null(doc)) {
      damaged(paste0("the record ", entry, " is not valid JSON"))
    }
    id <- osv_text(osv_field(doc, "id"))
    if (!osv_id_ok(id)) {
      damaged(paste0("the record ", entry, " has no id"))
    }
    if (!osv_record_ok(doc)) {
      damaged(paste0("the record ", entry, " is not an OSV record"))
    }
    docs[[k]] <- doc
    ids[[k]] <- id
  }
  keep <- !duplicated(ids)
  docs <- docs[keep]
  ids <- ids[keep]
  by_id <- order(ids, method = "radix")
  docs <- docs[by_id]
  # A zip that holds no CRAN record is not OSV's CRAN export, and would list
  # nothing as if there were nothing to list.
  if (!any(vapply(docs, osv_has_cran, logical(1)))) {
    damaged("it holds no CRAN records")
  }

  records <- osv_records(docs)
  list(
    records = records,
    affected = osv_affected(docs, records$id),
    newest_modified = osv_newest(records$modified)
  )
}

# The bytes of the zip entry `name`, at most `n` of them, or NULL when it
# cannot be read.
osv_entry_bytes <- function(path, name, n) {
  tryCatch(
    {
      con <- unz(path, name, open = "rb")
      on.exit(close(con), add = TRUE)
      readBin(con, "raw", n = n)
    },
    error = function(e) NULL,
    warning = function(w) NULL
  )
}

# A record's bytes parsed as read_document() parses JSON: valid UTF-8 without
# a NUL, no comments or other text outside JSON values, no empty or repeated
# key, and no nesting deeper than json_max_depth levels. NULL otherwise.
osv_parse_record <- function(bytes) {
  tryCatch(
    {
      doc <- json_parse_strict(utf8_text(bytes, "it"))
      if (is.na(json_model_problem(doc))) doc else NULL
    },
    error = function(e) NULL,
    warning = function(w) NULL
  )
}

# Whether a parsed record is one that sbom can read as an OSV record: its
# `affected`, when it has the key, is an array of objects, each with a
# `package` object whose `name` and `ecosystem` are strings that are not
# empty. A record that holds something else would otherwise be read as one
# that affects nothing.
osv_record_ok <- function(doc) {
  if (!"affected" %in% names(doc)) {
    return(TRUE)
  }
  affected <- doc[["affected"]]
  if (!is.list(affected) || !is.null(names(affected))) {
    return(FALSE)
  }
  word <- function(x) is.character(x) && length(x) == 1L && !is.na(x) && nzchar(x)
  all(vapply(affected, function(a) {
    package <- osv_field(a, "package")
    is.list(a) && !is.null(names(a)) && word(osv_field(package, "name")) && word(osv_field(package, "ecosystem"))
  }, logical(1)))
}

# Whether a parsed record has an affected entry of ecosystem CRAN.
osv_has_cran <- function(doc) {
  any(vapply(osv_objects(osv_field(doc, "affected")), function(a) {
    identical(osv_field(osv_field(a, "package"), "ecosystem"), "CRAN")
  }, logical(1)))
}

# The value of key `name` of a parsed JSON object, or NULL when `x` is not an
# object or has no such key.
osv_field <- function(x, name) {
  if (is.list(x) && !is.null(names(x))) x[[name]] else NULL
}

# A scalar JSON value as text, with control characters as spaces, as
# R Observatory takes it with as.character(). NA for null, an array, an
# object or an empty string.
osv_text <- function(x) {
  if (!is.atomic(x) || length(x) != 1L || is.na(x)) {
    return(NA_character_)
  }
  x <- text_strip(as.character(x))
  if (is.na(x) || !nzchar(x)) NA_character_ else x
}

# The scalar values of a JSON array as text, without the NAs.
osv_texts <- function(x) {
  if (!is.list(x) || !is.null(names(x)) || length(x) == 0L) {
    return(character())
  }
  values <- vapply(x, osv_text, "")
  values[!is.na(values)]
}

# The objects of a JSON array, or none when `x` is not an array.
osv_objects <- function(x) {
  if (!is.list(x) || !is.null(names(x))) {
    return(list())
  }
  Filter(function(item) is.list(item) && !is.null(names(item)), x)
}

# A data frame with one row per advisory document in `docs`: its id, summary,
# dates, first source URL and a list column of upstream ids.
osv_records <- function(docs) {
  text <- function(key) vapply(docs, function(d) osv_text(osv_field(d, key)), "")
  source_url <- vapply(docs, function(d) {
    sources <- vapply(osv_objects(osv_field(d, "affected")), function(a) {
      osv_text(osv_field(osv_field(a, "database_specific"), "source"))
    }, "")
    sources <- sources[!is.na(sources)]
    if (length(sources) > 0L) sources[[1]] else NA_character_
  }, "")
  records <- data.frame(
    id = text("id"), summary = text("summary"), published = text("published"),
    modified = text("modified"), withdrawn = text("withdrawn"), source_url = source_url,
    stringsAsFactors = FALSE
  )
  records$upstream <- lapply(docs, function(d) osv_texts(osv_field(d, "upstream")))
  records
}

# One row per interval of each ECOSYSTEM or SEMVER range, and per listed
# version, of each affected package of each record.
osv_affected <- function(docs, ids) {
  parts <- unlist(lapply(seq_along(docs), function(i) {
    lapply(osv_objects(osv_field(docs[[i]], "affected")), function(a) {
      package <- osv_field(a, "package")
      ranges <- Filter(
        function(r) osv_text(osv_field(r, "type")) %in% c("ECOSYSTEM", "SEMVER"),
        osv_objects(osv_field(a, "ranges"))
      )
      intervals <- lapply(ranges, function(r) osv_intervals(osv_field(r, "events")))
      introduced <- unlist(lapply(intervals, `[[`, "introduced"))
      listed <- osv_texts(osv_field(a, "versions"))
      n_range <- length(introduced)
      n_listed <- length(listed)
      missing <- rep(NA_character_, n_listed)
      list(
        id = rep(ids[[i]], n_range + n_listed),
        package = rep(osv_text(osv_field(package, "name")), n_range + n_listed),
        ecosystem = rep(osv_text(osv_field(package, "ecosystem")), n_range + n_listed),
        kind = rep(c("range", "listed"), c(n_range, n_listed)),
        introduced = c(introduced, missing),
        fixed = c(unlist(lapply(intervals, `[[`, "fixed")), missing),
        last_affected = c(unlist(lapply(intervals, `[[`, "last_affected")), missing),
        version = c(rep(NA_character_, n_range), listed)
      )
    })
  }), recursive = FALSE)
  cols <- c("id", "package", "ecosystem", "kind", "introduced", "fixed", "last_affected", "version")
  out <- lapply(cols, function(col) as.character(unlist(lapply(parts, `[[`, col))))
  names(out) <- cols
  data.frame(out, stringsAsFactors = FALSE)
}

# A bound as text: its string, with control characters as spaces, or "" for
# an empty string or a value that is not a string, which no version can be
# compared with.
osv_bound <- function(x) {
  if (!is.character(x) || length(x) != 1L || is.na(x)) {
    return("")
  }
  x <- text_strip(x)
  if (is.na(x)) "" else x
}

# The intervals of one range's events. An event's kind is the key it has
# (introduced, fixed or last_affected; "limit" is not read).
#
# When every bound is a version, the events are taken in the order OSV
# evaluates them: by package_version(), introduced "0" first, and at one
# version introduced before fixed or last_affected. An introduced opens an
# interval unless one is open, a fixed or last_affected closes the open one,
# and an interval still open at the end has no upper bound.
#
# Otherwise the events cannot be put in that order. They are paired as
# written, by R Observatory's events_to_intervals(), and a fixed or
# last_affected with nothing open is kept as an interval without an
# introduced, so that every bound is in some row and osv_match() can tell
# that no version can be compared with this range.
osv_intervals <- function(events) {
  events <- osv_objects(events)
  kinds <- c("introduced", "fixed", "last_affected")
  kind <- vapply(events, function(e) {
    hit <- kinds[vapply(kinds, function(k) !is.null(e[[k]]), logical(1))]
    if (length(hit) > 0L) hit[[1]] else ""
  }, "")
  events <- events[nzchar(kind)]
  kind <- kind[nzchar(kind)]
  value <- vapply(seq_along(events), function(i) osv_bound(events[[i]][[kind[[i]]]]), "")
  zero <- kind == "introduced" & value == "0"
  parsed <- osv_versions(ifelse(zero, "0.0", value))
  ordered <- !any(vapply(parsed, is.null, logical(1)))
  if (ordered && length(value) > 1L) {
    by_version <- order(!zero, xtfrm(do.call(c, parsed)), kind != "introduced", seq_along(kind), method = "radix")
    kind <- kind[by_version]
    value <- value[by_version]
  }
  introduced <- fixed <- last_affected <- rep(NA_character_, length(kind))
  k <- 0L
  open <- FALSE
  for (i in seq_along(kind)) {
    if (kind[[i]] == "introduced") {
      if (open && ordered) next
      k <- k + 1L
      introduced[[k]] <- value[[i]]
      open <- TRUE
      next
    }
    if (!open) {
      if (ordered) next
      k <- k + 1L
    }
    if (kind[[i]] == "fixed") fixed[[k]] <- value[[i]] else last_affected[[k]] <- value[[i]]
    open <- FALSE
  }
  keep <- seq_len(k)
  list(introduced = introduced[keep], fixed = fixed[keep], last_affected = last_affected[keep])
}

# The latest of OSV's RFC 3339 UTC times, as written, or NA when none is one.
# Compared as times, since a fraction of a second sorts before the Z as text.
osv_newest <- function(times) {
  valid <- !is.na(times) &
    grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$", times)
  if (!any(valid)) {
    return(NA_character_)
  }
  parsed <- as.POSIXct(sub("Z$", "", times[valid]), format = "%Y-%m-%dT%H:%M:%OS", tz = "UTC")
  if (all(is.na(parsed))) {
    return(NA_character_)
  }
  times[valid][[which.max(parsed)]]
}

# Each version as a package_version, or NULL where R cannot parse it.
osv_versions <- function(x) {
  lapply(x, function(v) {
    if (is.na(v)) NULL else tryCatch(package_version(v), error = function(e) NULL, warning = function(w) NULL)
  })
}

# Each value when it is a calendar date written YYYY-MM-DD, otherwise NA.
# 2026-02-30 and 2026-13-45 have the shape of a date but are none, and a
# document that gave one as a date would fail its schema.
osv_date <- function(x) {
  x <- as.character(x)
  back <- format(as.Date(x, format = "%Y-%m-%d"), "%Y-%m-%d")
  x[is.na(back) | back != x] <- NA_character_
  x
}

# Whether the version `v` is in an interval, by R Observatory's
# version_in_interval(), from the interval's parsed bounds: `lo` is NULL for
# introduced "0" (from the first version), `fixed_v` is exclusive and
# `last_v` inclusive, and an interval with neither is open.
osv_in_interval <- function(v, lo, fixed_v, last_v) {
  if (!is.null(lo) && v < lo) {
    return(FALSE)
  }
  if (!is.null(fixed_v)) {
    return(v < fixed_v)
  }
  if (!is.null(last_v)) {
    return(v <= last_v)
  }
  TRUE
}

#' Match OSV's advisories with an SBOM's components
#'
#' Matching is local. The candidates are the components whose purl is a
#' `cran` one without a `repository_url` that names Bioconductor
#' (`purl_names_bioconductor()`), whatever their ecosystem, and that have a
#' version that is not a minimum: a version whose `version_is` is NA counts
#' as exact. A record that is withdrawn, or whose ecosystem is not CRAN,
#' never matches. A version matches a listed version that it equals (by
#' `package_version()` when both parse, otherwise as text), or falls in an
#' interval.
#'
#' @param components The components table of an `<sbom>`.
#' @param osv From `osv_read_zip()` or `osv_fetch()`.
#' @return `list(advisories, no_exact, unparsed, not_cran)`:
#'   * `advisories`: `data.frame(id, summary, published, source_url,
#'     upstream, ratings, affects)`, one row per advisory that matched, sorted
#'     by id. `published` is the date, YYYY-MM-DD, or NA when OSV's is not a
#'     calendar date (see `osv_date()`). `ratings` is a list column
#'     of NULLs. `affects` is a list of `data.frame(ref, version, fixed,
#'     no_fix)`, sorted by ref. When the version is in an interval, `no_fix`
#'     is TRUE if any interval it is in is open, and otherwise `fixed` is the
#'     largest fixed version of those intervals (NA when they name none). A
#'     version matched only as a listed version has `fixed` NA and `no_fix`
#'     FALSE.
#'   * `no_exact`: the refs of the components with such a `cran` purl that
#'     have no version, or a minimum one.
#'   * `unparsed`: the refs of candidates whose version `package_version()`
#'     cannot parse, and of candidates of a package one of whose ranges in an
#'     advisory has a bound that is not a version, which keeps every version
#'     of that package from being compared with that advisory's ranges. Such
#'     a component can still match a listed version.
#'   * `not_cran`: the refs of the R packages without a `cran` purl, which
#'     are not known to come from CRAN: the components of sbom's R package
#'     ecosystems but Bioconductor (`osv_r_ecosystems`), other than the root
#'     and the copies embedded in other packages.
#' @noRd
osv_match <- function(components, osv) {
  parsed <- purl_parse(components$purl)
  cran_purl <- parsed$valid %in% TRUE & tolower(parsed$type) %in% "cran"
  cran <- cran_purl & !purl_names_bioconductor(parsed$qualifiers)
  exact <- !is.na(components$version) & !components$version_is %in% "minimum"
  no_exact <- sort(unique(components$ref[cran & !exact]), method = "radix")
  cand <- components[cran & exact, c("ref", "name", "version"), drop = FALSE]
  other <- components$ecosystem %in% osv_r_ecosystems & !cran_purl &
    !components$is_root %in% TRUE & !is_embedded_ref(components$ref)
  not_cran <- sort(unique(components$ref[other]), method = "radix")

  live <- osv$records$id[is.na(osv$records$withdrawn)]
  aff <- osv$affected
  aff <- aff[aff$id %in% live & aff$ecosystem %in% "CRAN" & aff$package %in% cand$name, , drop = FALSE]
  range <- aff$kind == "range"
  zero <- aff$introduced %in% "0"
  lo <- osv_versions(aff$introduced)
  fixed_v <- osv_versions(aff$fixed)
  last_v <- osv_versions(aff$last_affected)
  listed_v <- osv_versions(aff$version)
  cand_v <- osv_versions(cand$version)
  none <- function(x) vapply(x, is.null, logical(1))
  # A range row with a bound that is not a version comes from a range whose
  # events cannot be put in OSV's order, so no version of its package is
  # compared with any range of that advisory.
  bad <- range & ((!zero & none(lo)) | (!is.na(aff$fixed) & none(fixed_v)) |
    (!is.na(aff$last_affected) & none(last_v)))
  pair <- paste(aff$id, aff$package, sep = "\r")
  blind <- range & pair %in% pair[bad]

  found <- lapply(seq_len(nrow(cand)), function(i) {
    rows <- which(aff$package == cand$name[[i]])
    v <- cand_v[[i]]
    hit <- vapply(rows, function(j) {
      if (!range[[j]]) {
        if (!is.null(v) && !is.null(listed_v[[j]])) v == listed_v[[j]] else identical(cand$version[[i]], aff$version[[j]])
      } else if (is.null(v) || blind[[j]]) {
        NA
      } else {
        osv_in_interval(v, if (zero[[j]]) NULL else lo[[j]], fixed_v[[j]], last_v[[j]])
      }
    }, NA)
    list(rows = rows[hit %in% TRUE], unparsed = is.null(v) || anyNA(hit))
  })
  unparsed <- cand$ref[vapply(found, `[[`, logical(1), "unparsed")]
  unparsed <- sort(unique(unparsed), method = "radix")

  # One hit per advisory and component, from every row it matched.
  rows <- as.integer(unlist(lapply(found, `[[`, "rows")))
  who <- rep(seq_len(nrow(cand)), vapply(found, function(f) length(f$rows), integer(1)))
  groups <- split(seq_along(rows), paste(aff$id[rows], cand$ref[who], sep = "\r"))
  one <- lapply(groups, function(g) {
    r <- rows[g]
    r <- r[range[r]]
    open <- any(is.na(aff$fixed[r]) & is.na(aff$last_affected[r]))
    fixes <- aff$fixed[r][!is.na(aff$fixed[r])]
    fixed <- if (open || length(fixes) == 0L) {
      NA_character_
    } else {
      fixes[[which.max(xtfrm(do.call(c, osv_versions(fixes))))]]
    }
    first <- g[[1]]
    list(id = aff$id[rows[[first]]], ref = cand$ref[who[[first]]], version = cand$version[who[[first]]],
         fixed = fixed, no_fix = open)
  })
  field <- function(name, type) vapply(one, `[[`, type, name, USE.NAMES = FALSE)
  hits <- data.frame(
    id = field("id", ""), ref = field("ref", ""), version = field("version", ""),
    fixed = field("fixed", ""), no_fix = field("no_fix", NA), stringsAsFactors = FALSE
  )
  hits <- hits[order(hits$id, hits$ref, method = "radix"), , drop = FALSE]

  ids <- unique(hits$id)
  at <- match(ids, osv$records$id)
  advisories <- data.frame(
    id = ids,
    summary = osv$records$summary[at],
    published = osv_date(substr(osv$records$published[at], 1L, 10L)),
    source_url = osv$records$source_url[at],
    stringsAsFactors = FALSE
  )
  advisories$upstream <- osv$records$upstream[at]
  advisories$ratings <- vector("list", length(ids))
  advisories$affects <- lapply(ids, function(id) {
    h <- hits[hits$id == id, c("ref", "version", "fixed", "no_fix"), drop = FALSE]
    rownames(h) <- NULL
    h
  })
  list(advisories = advisories, no_exact = no_exact, unparsed = unparsed, not_cran = not_cran)
}

# The ecosystems of R packages, as package_ecosystem() gives them, but
# Bioconductor, whose packages OSV does not cover: a component of one of
# them without a `cran` purl is not known to come from CRAN.
osv_r_ecosystems <- c("cran", "repository", "unknown", "local", "github", "gitlab", "bitbucket", "git")

# Whether the repository_url qualifier of each purl names bioconductor.org,
# or a host under it, from purl_parse()'s raw qualifiers (NA for none). A
# value may be percent-encoded.
purl_names_bioconductor <- function(qualifiers) {
  vapply(as.character(qualifiers), function(q) {
    if (is.na(q)) {
      return(FALSE)
    }
    pairs <- strsplit(q, "&", fixed = TRUE)[[1L]]
    urls <- substring(pairs[startsWith(pairs, "repository_url=")], nchar("repository_url=") + 1L)
    urls <- vapply(urls, function(u) tryCatch(utils::URLdecode(u), error = function(e) u), "")
    any(grepl("^[a-z][a-z0-9+.-]*://([^/?#@]*@)?([^/?#:@]*[.])?bioconductor[.]org(?:[:/?#]|$)", tolower(urls)))
  }, logical(1), USE.NAMES = FALSE)
}

#' CVSS 3 base scores, severities and methods
#'
#' `cvss_base_score()` is the base score of a CVSS 3.0 or 3.1 vector by the
#' formula of the CVSS 3.1 specification (section 7.1), a port of R
#' Observatory's `cvss3_base_score()`, and NA for any other text.
#' `cvss_severity()` is the qualitative rating of a score. `cvss_method()` is
#' the CycloneDX rating method of a vector, as R Observatory's
#' `sbom_cdx_rating()` names it. A score describes the upstream flaw.
#'
#' @param vector Vector strings.
#' @param score Base scores.
#' @return A numeric vector; a character vector of `"none"`, `"low"`,
#'   `"medium"`, `"high"`, `"critical"` or NA; a character vector of
#'   `"CVSSv31"`, `"CVSSv3"`, `"CVSSv4"`, `"CVSSv2"` or `"other"`.
#' @noRd
cvss_base_score <- function(vector) {
  vapply(as.character(vector), cvss_score_one, numeric(1), USE.NAMES = FALSE)
}

cvss_weights <- list(
  AV = c(N = 0.85, A = 0.62, L = 0.55, P = 0.2),
  AC = c(L = 0.77, H = 0.44),
  UI = c(N = 0.85, R = 0.62),
  CIA = c(H = 0.56, L = 0.22, N = 0)
)

# Rounds up to one decimal as CVSS 3.1 defines it, immune to float noise.
cvss_roundup <- function(x) {
  i <- round(x * 100000)
  if (i %% 10000 == 0) i / 100000 else (floor(i / 10000) + 1) / 10
}

# The eight base metrics of a CVSS 3.0 or 3.1 vector, by name, or NULL when
# it is not a complete one.
cvss_parse <- function(vector) {
  if (is.na(vector)) {
    return(NULL)
  }
  parts <- strsplit(vector, "/", fixed = TRUE)[[1]]
  if (length(parts) == 0L || !parts[[1]] %in% c("CVSS:3.0", "CVSS:3.1")) {
    return(NULL)
  }
  kv <- strsplit(parts[-1], ":", fixed = TRUE)
  if (any(lengths(kv) != 2L)) {
    return(NULL)
  }
  metrics <- vapply(kv, `[`, "", 2L)
  names(metrics) <- vapply(kv, `[`, "", 1L)
  need <- c("AV", "AC", "PR", "UI", "S", "C", "I", "A")
  # A metric may be given once.
  if (anyDuplicated(names(metrics)) > 0L || !all(need %in% names(metrics))) {
    return(NULL)
  }
  metrics[need]
}

# The CVSS v3 base score of one `vector` string; NA when it does not parse or
# has an unknown metric value.
cvss_score_one <- function(vector) {
  m <- cvss_parse(vector)
  if (is.null(m)) {
    return(NA_real_)
  }
  w <- cvss_weights
  scope_changed <- m[["S"]] == "C"
  pr <- if (scope_changed) c(N = 0.85, L = 0.68, H = 0.5) else c(N = 0.85, L = 0.62, H = 0.27)
  vals <- c(
    w$AV[m[["AV"]]], w$AC[m[["AC"]]], pr[m[["PR"]]], w$UI[m[["UI"]]],
    w$CIA[m[["C"]]], w$CIA[m[["I"]]], w$CIA[m[["A"]]]
  )
  if (anyNA(vals) || !m[["S"]] %in% c("U", "C")) {
    return(NA_real_)
  }
  iss <- 1 - (1 - vals[[5]]) * (1 - vals[[6]]) * (1 - vals[[7]])
  impact <- if (scope_changed) 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)^15 else 6.42 * iss
  exploit <- 8.22 * vals[[1]] * vals[[2]] * vals[[3]] * vals[[4]]
  if (impact <= 0) {
    return(0)
  }
  if (scope_changed) {
    cvss_roundup(min(1.08 * (impact + exploit), 10))
  } else {
    cvss_roundup(min(impact + exploit, 10))
  }
}

#' @rdname cvss_base_score
#' @noRd
cvss_severity <- function(score) {
  out <- ifelse(score == 0, "none", ifelse(score < 4, "low", ifelse(score < 7, "medium",
    ifelse(score < 9, "high", "critical"))))
  as.character(out)
}

#' @rdname cvss_base_score
#' @noRd
cvss_method <- function(vector) {
  vector <- as.character(vector)
  vector[is.na(vector)] <- ""
  as.character(ifelse(startsWith(vector, "CVSS:3.1/"), "CVSSv31",
    ifelse(startsWith(vector, "CVSS:3.0/"), "CVSSv3",
      ifelse(startsWith(vector, "CVSS:4.0/"), "CVSSv4",
        ifelse(grepl("^AV:[LAN]/", vector), "CVSSv2", "other")))))
}
