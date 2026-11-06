# OSV security advisories in an SBOM (spec §9a), opt-in: what the builders
# do with OSV's advisory data (R/osv.R reads and matches it), which is to
# match it with an SBOM after its overrides, look up the upstream ratings,
# and write the notes and issues; the helpers the writers share; and
# sbom_advisories().

# The notes about advisories, in R Observatory's words (sbom.php,
# sbom_notes()), and the sentence a SWID tag, which has no place for
# advisories, gives instead of those that say they are listed.
advisory_notes <- list(
  no_data = "No advisory data was on hand for this file, so it lists no advisories.",
  listed = "Advisories are those OSV lists for these exact versions.",
  bioc = "The advisory database does not cover Bioconductor packages yet.",
  swid = "A SWID tag has no place for advisories, so this tag lists none; the other formats list them."
)

# How the note on where the advisory data came from starts.
advisory_provenance_start <- "Advisory data is OSV's CRAN export, "

# Perl patterns of those sentences, for writers that take them out of notes
# (notes_without()): the note on where the data came from ends at the first
# full stop that ends a sentence, which a file name holding ". " would cut
# short.
advisory_sentences <- list(
  listed = paste0("\\Q", advisory_notes$listed, "\\E"),
  bioc = paste0("\\Q", advisory_notes$bioc, "\\E"),
  provenance = paste0("\\Q", advisory_provenance_start, "\\E(?:downloaded|read) from .+?[.]"),
  swid = paste0("\\Q", advisory_notes$swid, "\\E")
)

# `notes` with every sentence that `pattern`, a perl pattern, matches taken
# out, wherever it is: a whole note, or a sentence inside a note into which
# a document joined several, as SPDX and SWID do. A note left empty goes.
# `with`, when given, takes the place of the first sentence taken out, or is
# added at the end when there was none. A note without such a sentence is
# kept as it is.
notes_without <- function(notes, pattern, with = NULL) {
  sentence <- paste0("(?:^|(?<= ))(?:", pattern, ")(?: |$)")
  hit <- grepl(sentence, notes, perl = TRUE)
  if (!any(hit)) {
    return(c(notes, with))
  }
  strip <- function(x) sub(" +$", "", gsub(sentence, "", x, perl = TRUE))
  first <- which(hit)[[1L]]
  note <- notes[[first]]
  at <- regexpr(sentence, note, perl = TRUE)
  rest <- strip(substring(note, at + attr(at, "match.length")))
  notes[hit] <- strip(notes[hit])
  if (!is.null(with)) {
    notes[[first]] <- paste0(substr(note, 1L, at - 1L), with, if (nzchar(rest)) paste0(" ", rest))
  }
  notes[!hit | nzchar(notes)]
}

# The checks of `advisories` and `advisories_on_error` that every builder
# makes before it reads anything. `on_error` is one of the two modes, or the
# builders' default, both of them, which means "error". Returns the mode.
check_advisories_args <- function(advisories, on_error, call = parent.frame()) {
  path <- is.character(advisories) && length(advisories) == 1L && !is.na(advisories) && nzchar(advisories)
  if (!isTRUE(advisories) && !isFALSE(advisories) && !path) {
    cli::cli_abort(
      paste0(
        "{.arg advisories} must be {.code TRUE}, {.code FALSE} or the path of OSV's CRAN ",
        "{.file all.zip}, not {.obj_type_friendly {advisories}}."
      ),
      call = call
    )
  }
  if (path && !file.exists(advisories)) {
    cli::cli_abort("The OSV advisory file {.file {advisories}} does not exist.", call = call)
  }
  if (path && dir.exists(advisories)) {
    cli::cli_abort("{.file {advisories}} is a folder, not OSV's all.zip.", call = call)
  }
  if (identical(on_error, c("error", "continue"))) {
    return("error")
  }
  if (!is_string(on_error) || !on_error %in% c("error", "continue")) {
    cli::cli_abort(
      "{.arg advisories_on_error} must be {.val error} or {.val continue}, not {.obj_type_friendly {on_error}}.",
      call = call
    )
  }
  on_error
}

#' Match OSV's advisories with an SBOM
#'
#' The last step of every build, after the overrides, so that the advisories
#' match the versions the SBOM lists. Without advisories, it writes R
#' Observatory's note that no advisory data was on hand. It first removes
#' that note, which an earlier call without advisories wrote, so that
#' `sbom()` can call it again on the SBOM its reader built.
#'
#' @param x An `<sbom>`.
#' @param advisories `FALSE`, `TRUE` or a path, checked by
#'   `check_advisories_args()`.
#' @param on_error `"error"` or `"continue"`.
#' @param call The call errors are reported against.
#' @return `x` with `advisories`, `metadata$advisories`, its notes, issues
#'   and `metadata$inputs` set. Advisory data that cannot be read is an error
#'   of class `sbom_advisories_error`, or under `"continue"` an
#'   `advisories-unavailable` issue and a warning of class
#'   `sbom_advisories_unavailable`, since the user asked for advisories that
#'   the SBOM does not list.
#' @noRd
apply_advisories <- function(x, advisories = FALSE, on_error = "error", call = parent.frame()) {
  notes <- as.character(x$metadata$notes)
  notes <- notes[!notes %in% advisory_notes$no_data]
  x$advisories <- empty_advisories()
  x$metadata$advisories <- advisories_metadata()
  if (isFALSE(advisories)) {
    x$metadata$notes <- c(notes, advisory_notes$no_data)
    return(x)
  }
  source <- osv_source(advisories)
  meta <- advisories_metadata(requested = TRUE, source = source$label)
  osv <- if (identical(on_error, "continue")) {
    tryCatch(osv_fetch(source, call = call), sbom_advisories_error = function(e) e)
  } else {
    osv_fetch(source, call = call)
  }
  if (inherits(osv, "error")) {
    reason <- osv$reason
    cli::cli_warn(
      "OSV's advisory data could not be read ({reason}), so this SBOM lists no advisories.",
      class = "sbom_advisories_unavailable", call = call
    )
    meta$status <- "unavailable"
    x$metadata$advisories <- meta
    x$metadata$notes <- c(notes, advisory_notes$no_data)
    x$issues <- add_issue(
      x$issues, x$metadata$root, "advisories", "advisories-unavailable",
      paste0("sbom could not read OSV's advisory data (", reason, "), so this file lists no advisories.")
    )
    rownames(x$issues) <- NULL
    return(x)
  }

  m <- osv_match(x$components, osv)
  adv <- m$advisories
  failed <- character()
  if (identical(source$kind, "url")) {
    looked <- advisory_lookups(osv$records, adv$upstream)
    adv$ratings <- looked$ratings
    failed <- looked$failed
  } else {
    adv$ratings <- rep(list(empty_ratings()), nrow(adv))
  }
  rownames(adv) <- NULL
  x$advisories <- adv

  provenance <- if (identical(source$kind, "url")) {
    paste0(
      advisory_provenance_start, "downloaded from ", source$label, " on ",
      format(osv$fetched, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"), "."
    )
  } else {
    paste0(
      advisory_provenance_start, "read from ", source$label,
      if (!is.na(osv$newest_modified)) paste0(", with records modified up to ", osv$newest_modified),
      "."
    )
  }
  # A Bioconductor package, or one whose CRAN package URL names Bioconductor,
  # is not compared.
  parsed <- purl_parse(x$components$purl)
  bioc <- any(x$components$ecosystem %in% "bioconductor") ||
    any(parsed$valid %in% TRUE & tolower(parsed$type) %in% "cran" & purl_names_bioconductor(parsed$qualifiers))
  x$metadata$notes <- c(notes, advisory_notes$listed, if (bioc) advisory_notes$bioc, provenance)
  x$issues <- advisory_issues(x, m, failed)

  meta$fetched <- osv$fetched
  meta$newest_modified <- osv$newest_modified
  meta$status <- "listed"
  x$metadata$advisories <- meta
  x$metadata$inputs <- rbind(
    x$metadata$inputs,
    data.frame(kind = "advisories", path = as.character(source$location), stringsAsFactors = FALSE)
  )
  x
}

# `one` when `n` is 1, otherwise `many`: the two forms of a sentence.
one_or_many <- function(n, one, many) {
  if (n == 1L) one else many
}

# The issues of `x` with those of a match added, at the root, as info: the
# packages without an exact version, the R packages not known to come from
# CRAN, and those OSV's ranges cannot be compared with, from `m`,
# osv_match()'s list, and the upstream ids in `failed` whose ratings could
# not be looked up. Packages are named, ids quoted, at most 20 of each.
advisory_issues <- function(x, m, failed) {
  issues <- x$issues
  info <- function(issues, code, message) {
    add_issue(issues, x$metadata$root, "advisories", code, message, severity = "info")
  }
  names_of <- function(refs) {
    sort(unique(x$components$name[match(refs, x$components$ref)]), method = "radix")
  }

  no_exact <- names_of(m$no_exact)
  n <- length(no_exact)
  if (n > 0L) {
    named <- capped_list(no_exact)
    issues <- info(issues, "advisories-no-exact-version", one_or_many(
      n,
      paste0("1 package has no exact version, so OSV's advisories were not looked up for it (", named, ")."),
      paste0(n, " packages have no exact version, so OSV's advisories were not looked up for them (", named, ").")
    ))
  }

  not_cran <- names_of(m$not_cran)
  n <- length(not_cran)
  if (n > 0L) {
    named <- capped_list(not_cran)
    issues <- info(issues, "advisories-not-cran", one_or_many(
      n,
      paste0(
        "1 R package is not known to come from CRAN, so OSV's advisories were not looked up for it (", named, ")."
      ),
      paste0(
        n, " R packages are not known to come from CRAN, so OSV's advisories were not looked up for them (",
        named, ")."
      )
    ))
  }

  # A package can be matched by one advisory and still not be comparable with
  # another, so the sentence does not say that none was looked up.
  unparsed <- names_of(m$unparsed)
  n <- length(unparsed)
  if (n > 0L) {
    named <- capped_list(unparsed)
    issues <- info(issues, "advisories-not-compared", one_or_many(
      n,
      paste0(
        "OSV's advisories could not all be compared with the version of 1 package (", named,
        "), so this file may not list every advisory for it."
      ),
      paste0(
        "OSV's advisories could not all be compared with the versions of ", n, " packages (", named,
        "), so this file may not list every advisory for them."
      )
    ))
  }

  n <- length(failed)
  if (n > 0L) {
    named <- capped_list(quote_value(failed))
    issues <- info(issues, "advisories-ratings-unavailable", one_or_many(
      n,
      paste0("The CVSS rating of 1 upstream record could not be looked up, so it is not listed (", named, ")."),
      paste0(
        "The CVSS ratings of ", n, " upstream records could not be looked up, so they are not listed (",
        named, ")."
      )
    ))
  }
  rownames(issues) <- NULL
  issues
}

# The most seconds all the lookups of one build may take together: an
# option, read through a function, so that tests can lower it.
osv_lookup_seconds <- function() osv_cap_option("sbom.osv_lookup_seconds", 120)

# The ratings of each advisory, from `upstream`, the list of its upstream
# ids, and the sorted ids of those upstream records that could not be looked
# up. Every upstream id of the export's records that are not withdrawn is
# looked up once, whether or not its advisory matched, so that what sbom asks
# OSV does not show which packages the SBOM holds. Only an id that
# osv_id_ok() accepts is sent; any other counts as one that could not be
# looked up. The lookups stop after the first that timed out or failed at
# the connection, and once osv_lookup_seconds() have gone by, each taking
# no longer than is left; the ids not looked up count as ones that could
# not be.
advisory_lookups <- function(records, upstream) {
  ids <- as.character(unlist(records$upstream[is.na(records$withdrawn)]))
  ids <- sort(unique(ids[osv_id_ok(ids)]), method = "radix")
  found <- vector("list", length(ids))
  budget <- osv_lookup_seconds()
  start <- Sys.time()
  for (k in seq_along(ids)) {
    left <- budget - as.numeric(difftime(Sys.time(), start, units = "secs"))
    if (left <= 0) {
      break
    }
    got <- osv_lookup(ids[[k]], timeout = max(1, ceiling(min(30, left))))
    if (isFALSE(got)) {
      break
    }
    found[k] <- list(got)
  }
  ratings <- lapply(upstream, function(up) {
    rows <- lapply(up, function(id) {
      at <- match(id, ids)
      if (is.na(at) || is.null(found[[at]])) NULL else upstream_ratings(id, found[[at]])
    })
    out <- do.call(rbind, c(list(empty_ratings()), rows))
    rownames(out) <- NULL
    out
  })
  wanted <- unique(as.character(unlist(upstream)))
  got <- ids[!vapply(found, is.null, logical(1))]
  list(ratings = ratings, failed = sort(wanted[!wanted %in% got], method = "radix"))
}

# The ratings of the upstream record `id`, from its CVSS_V3 and CVSS_V4
# severities: a CVSS 3 vector gives its base score and severity, a CVSS 4.0
# vector neither. A vector is kept only when it looks like one, so that
# nothing else the server sent reaches a document.
upstream_ratings <- function(id, record) {
  sev <- osv_objects(osv_field(record, "severity"))
  type <- vapply(sev, function(s) osv_text(osv_field(s, "type")), "")
  vector <- vapply(sev, function(s) osv_text(osv_field(s, "score")), "")
  keep <- type %in% c("CVSS_V3", "CVSS_V4") & !is.na(vector) &
    grepl("^CVSS:[0-9.]+/[A-Za-z0-9:/._-]+$", vector, perl = TRUE, useBytes = TRUE) &
    nchar(vector, type = "bytes") <= 200L
  type <- type[keep]
  vector <- vector[keep]
  score <- ifelse(type == "CVSS_V3", cvss_base_score(vector), NA_real_)
  data.frame(
    upstream = rep(id, length(vector)), method = cvss_method(vector), vector = vector,
    score = as.numeric(score), severity = cvss_severity(score), stringsAsFactors = FALSE
  )
}

# The page of the OSV advisory `id`, one id, on osv.dev, with the id
# percent-encoded as R Observatory's rawurlencode() does.
osv_vulnerability_url <- function(id) {
  paste0("https://osv.dev/vulnerability/", utils::URLencode(id, reserved = TRUE, repeated = TRUE))
}

# The CVE ids among upstream ids, in their order, and the CVE record of one.
cve_ids <- function(upstream) {
  upstream <- as.character(upstream)
  upstream[grepl("^CVE-[0-9]{4}-[0-9]+$", upstream)]
}

cve_record_url <- function(id) {
  paste0("https://www.cve.org/CVERecord?id=", id)
}

# The advisories of `x` as every writer gives them: sorted by id, each with
# the components it affects sorted by ref. Only components that `x` holds
# are named, and an advisory that affects none of them is left out. A
# publication date that is not a calendar date is NA, and so is a source URL
# that cannot be an IRI reference, which CycloneDX requires.
written_advisories <- function(x) {
  adv <- x$advisories
  if (!is.data.frame(adv) || nrow(adv) == 0L) {
    return(empty_advisories())
  }
  adv$affects <- lapply(adv$affects, function(a) {
    a <- a[a$ref %in% x$components$ref, , drop = FALSE]
    a <- a[order(a$ref, method = "radix"), , drop = FALSE]
    rownames(a) <- NULL
    a
  })
  adv <- adv[vapply(adv$affects, nrow, integer(1)) > 0L, , drop = FALSE]
  adv <- adv[order(adv$id, method = "radix"), , drop = FALSE]
  adv$published <- osv_date(adv$published)
  bad <- !is.na(adv$source_url)
  bad[bad] <- iri_reference_bad(adv$source_url[bad])
  adv$source_url[bad] <- NA_character_
  rownames(adv) <- NULL
  adv
}

#' List the security advisories in an SBOM
#'
#' `sbom_advisories()` lists the OSV advisories in an SBOM built with
#' `advisories = TRUE`, or with the path of a copy of OSV's CRAN `all.zip`:
#' those that OSV lists for the exact versions of its CRAN packages, from
#' the R Consortium advisory database. Matching is local, so no package name
#' leaves the machine; with `advisories = TRUE`, the CVSS ratings of the
#' upstream records are looked up at `https://api.osv.dev`, sending only
#' their public ids. The list is what OSV says about these exact versions:
#' a package without an advisory here is not shown to be free of flaws, and
#' a CVSS rating describes the upstream flaw, not how exposed the R package
#' is.
#'
#' An SBOM read with [read_sbom()] lists the OSV advisory listings its
#' document holds: CycloneDX vulnerabilities, SPDX 2 advisory references and
#' SPDX 3 vulnerabilities, as sbom writes them. Other tools' vulnerabilities
#' and VEX statements are not read. A SWID tag has no place for advisories.
#'
#' @param x An `<sbom>` object.
#' @return A data frame with one row per advisory and component it affects,
#'   sorted by `id`, then `ref`: `id`, the OSV id; the `ref`, `name` and
#'   `version` of the component; the advisory's `summary`; `published`, the
#'   date OSV published it; `fixed`, the version that fixes it, or `NA`;
#'   `no_fix`, `TRUE` when the version is in a range of OSV's that has no
#'   upper bound, so that OSV names no fix, and otherwise `FALSE`: `fixed`
#'   `NA` with `no_fix` `FALSE` means that the fix is not known, as for a
#'   version that OSV only lists; `cves`, its CVE ids joined with
#'   `", "`, or `NA`; `url`, its page on osv.dev; and `source_url`, its
#'   record in the R Consortium advisory database. In an SBOM read from a
#'   document, a value its format does not carry is `NA`: CycloneDX and SPDX
#'   3 do not carry `fixed` or `no_fix`, and SPDX 2 carries only those two.
#'   For an SBOM built without advisories, or whose
#'   advisory data could not be read when it was built, or read from a file
#'   that lists none, it has no rows, and a message says so.
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
#' sbom_advisories(x)
#' @export
sbom_advisories <- function(x) {
  check_sbom(x)
  status <- advisories_status(x)
  if (identical(status, "not-requested") && any(x$metadata$inputs$kind %in% "sbom")) {
    cli::cli_inform("This SBOM was read from a file, and sbom read no advisories from it.")
  } else if (identical(status, "not-requested")) {
    cli::cli_inform(
      "This SBOM was built without advisories; build it with {.code advisories = TRUE} to list them."
    )
  } else if (identical(status, "unavailable")) {
    cli::cli_inform(paste0(
      "OSV's advisory data could not be read when this SBOM was built, so it lists no advisories; ",
      "see {.code sbom_issues()}."
    ))
  }
  out <- data.frame(
    id = character(), ref = character(), name = character(), version = character(),
    summary = character(), published = character(), fixed = character(), no_fix = logical(),
    cves = character(), url = character(), source_url = character(), stringsAsFactors = FALSE
  )
  adv <- x$advisories
  if (!is.data.frame(adv) || nrow(adv) == 0L) {
    return(out)
  }
  comps <- x$components
  rows <- lapply(seq_len(nrow(adv)), function(i) {
    hits <- adv$affects[[i]]
    n <- nrow(hits)
    cves <- cve_ids(adv$upstream[[i]])
    data.frame(
      id = rep(adv$id[[i]], n), ref = hits$ref, name = comps$name[match(hits$ref, comps$ref)],
      version = hits$version, summary = rep(adv$summary[[i]], n),
      published = rep(adv$published[[i]], n), fixed = hits$fixed, no_fix = as.logical(hits$no_fix),
      cves = rep(if (length(cves) > 0L) paste(cves, collapse = ", ") else NA_character_, n),
      url = rep(osv_vulnerability_url(adv$id[[i]]), n),
      source_url = rep(adv$source_url[[i]], n), stringsAsFactors = FALSE
    )
  })
  out <- do.call(rbind, c(list(out), rows))
  out <- out[order(out$id, out$ref, method = "radix"), , drop = FALSE]
  rownames(out) <- NULL
  out
}
