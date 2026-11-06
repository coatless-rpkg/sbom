# Reading the advisories an SBOM lists back into an <sbom>: CycloneDX
# vulnerabilities, SPDX 2 advisory references and SPDX 3
# security_Vulnerability elements, as sbom and R Observatory write them. A
# SWID tag has no place for advisories. Only OSV's advisory listings are
# read, since sbom writes each advisory it holds as one that OSV lists for
# the version: another source's vulnerability, a VEX statement about one, or
# a statement that a component's version is not among those affected, is
# dropped and counted, never written as OSV's. Like every value
# read_sbom() keeps, each comes from a file of any origin: a value of the
# wrong JSON type is absent, an entry whose id osv_id_ok() refuses is
# dropped and counted, URLs are kept as read_urls() keeps them, a date only
# when it is a calendar date, and text holds no control characters.

# An osv.dev vulnerability page, with the id as its last path segment.
osv_page_pattern <- "^https://osv[.]dev/vulnerability/([^/?#]+)$"

#' Read the advisories of a document
#'
#' Each family's reader gives the advisories as written, one record per
#' entry: a vulnerability (CycloneDX, SPDX 3) or an advisory reference (SPDX
#' 2), with whether it is one of OSV's advisory listings and the components
#' it names; `read_advisory_table()` checks and gathers them.
#'
#' @param d What `read_document()` returns.
#' @param t Its tables, from `document_tables()`.
#' @param family `"cdx"`, `"spdx2"`, `"spdx3"` or `"swid"`.
#' @param el The component elements of `t`.
#' @param id,ref,version Each component's id as written, and its ref and
#'   version as `read_sbom_build()` makes them.
#' @param ix For SPDX 3, the graph's index, `tables_spdx3_index()`.
#' @param seen The environment that counts the values that held control
#'   characters (`read_clean()`).
#' @return `list(advisories, dropped, not_listing, no_id, no_component,
#'   unlisted)`: the advisories table, one row per id, sorted by id, each
#'   with the components it affects sorted by ref; the kind of each URL not
#'   kept, as `read_urls()` gives them; the numbers of entries not kept, each
#'   counted once, for the first of these that holds: it is not one of OSV's
#'   advisory listings, its id is not an OSV id, or it names no component of
#'   the document that has a version; and the number of components that an
#'   entry otherwise kept was not read for, since what it states about them
#'   is not a listing.
#' @noRd
read_advisories <- function(d, t, family, el, id, ref, version, ix, seen) {
  raw <- switch(family,
    cdx = read_cdx_advisories(d$doc, id, version, xml = identical(d$format, "cyclonedx-xml")),
    spdx2 = read_spdx2_advisories(el),
    spdx3 = read_spdx3_advisories(d$doc, t, ix, id),
    NULL
  )
  if (is.null(raw)) {
    return(list(
      advisories = empty_advisories(), dropped = character(), not_listing = 0L, no_id = 0L, no_component = 0L,
      unlisted = 0L
    ))
  }
  read_advisory_table(raw, ref, version, seen)
}

# The advisories of a document as written, as every family's reader gives
# them: `records`, one row per entry, with its id, summary, published time
# and source URL, and whether it is one of OSV's advisory listings
# (`listing`); `upstream`, the ids of its references;
# `ratings`; and `hits`, the components it names, each by its index in the
# elements, with the version that fixes it, whether there is none, and
# whether what the entry states about the component is a listing
# (`listed`). Each row of the last three names its record by `advisory`, an
# index into the records.
read_advisory_raw <- function(id, listing, summary = NA_character_, published = NA_character_,
                              source_url = NA_character_, upstream = NULL, ratings = NULL, hits) {
  n <- length(id)
  if (is.null(upstream)) upstream <- data.frame(advisory = integer(), id = character())
  if (is.null(ratings)) {
    ratings <- data.frame(
      advisory = integer(), method = character(), vector = character(), score = numeric(),
      severity = character()
    )
  }
  list(
    records = data.frame(
      id = as.character(id), summary = rep_len(as.character(summary), n),
      published = rep_len(as.character(published), n), source_url = rep_len(as.character(source_url), n),
      listing = rep_len(as.logical(listing), n), stringsAsFactors = FALSE
    ),
    upstream = upstream, ratings = ratings, hits = hits
  )
}

# The hits of `advisory`, the records, on `element`, the elements, with
# their fixes, and whether each is a listing. A format that does not say
# whether there is a fix gives NA for `no_fix`.
read_advisory_hits <- function(advisory, element, fixed = NA_character_, no_fix = NA, listed = TRUE) {
  n <- length(advisory)
  data.frame(
    advisory = as.integer(advisory), element = as.integer(element), fixed = rep_len(as.character(fixed), n),
    no_fix = rep_len(as.logical(no_fix), n), listed = rep_len(as.logical(listed), n), stringsAsFactors = FALSE
  )
}

# A JSON number as a double; NA for anything else.
read_json_number <- function(x) {
  if (is.numeric(x) && length(x) == 1L && is.finite(x)) as.numeric(x) else NA_real_
}

# CycloneDX vulnerabilities: the id, the description as the summary, the
# published time, the first advisory's URL as the source URL, the ids of the
# references, the ratings, and the components `affects` names, matched to
# `id`, the components' ids, whose versions are `version`. A vulnerability
# is one of OSV's listings when its source is named OSV and it holds no
# analysis, which would make it a VEX statement. An affects target is a
# listing of its component unless it gives version statuses none of which
# says that the component's version is affected (read_cdx_target_listed()).
# `xml` says whether `doc` is the model of CycloneDX XML, in which an empty
# element is an object.
read_cdx_advisories <- function(doc, id, version, xml = FALSE) {
  vulns <- json_items(json_member(doc, "vulnerabilities"))
  vulns <- unname(vulns[vapply(vulns, json_is_object, logical(1), empty = xml)])
  first_advisory <- lapply(vulns, function(v) {
    items <- json_items(json_member(v, "advisories"))
    if (length(items) > 0L) items[[1L]]
  })
  refs <- json_flatten(vulns, "references")
  ratings <- json_flatten(vulns, "ratings")
  rated <- vapply(ratings$items, json_is_object, logical(1), empty = xml)
  items <- ratings$items[rated]
  affects <- json_flatten(vulns, "affects")
  element <- match(json_strings(affects$items, "ref"), id, incomparables = NA)
  read_advisory_raw(
    id = json_strings(vulns, "id"),
    listing = json_strings(vulns, c("source", "name")) %in% "OSV" &
      vapply(vulns, function(v) is.null(json_member(v, "analysis")), logical(1)),
    summary = json_strings(vulns, "description"),
    published = json_strings(vulns, "published"),
    source_url = json_strings(first_advisory, "url"),
    upstream = data.frame(advisory = refs$owner, id = json_strings(refs$items, "id"), stringsAsFactors = FALSE),
    ratings = data.frame(
      advisory = ratings$owner[rated], method = json_strings(items, "method"),
      vector = json_strings(items, "vector"),
      score = vapply(items, function(r) read_json_number(json_member(r, "score")), numeric(1)),
      severity = json_strings(items, "severity"), stringsAsFactors = FALSE
    ),
    hits = read_advisory_hits(
      affects$owner, element, listed = read_cdx_target_listed(affects$items, version[element])
    )
  )
}

# Whether each CycloneDX affects target in `targets` lists the version of
# its component, `version` (NA when it names none that has one), as OSV's
# listings do. A target without `versions` does. One with `versions` does
# only when one of them has status "affected" and either names that version
# or gives neither a version nor a range: "unaffected" or "unknown", another
# version, or a range alone, says something other than that OSV lists it.
read_cdx_target_listed <- function(targets, version) {
  vapply(seq_along(targets), function(i) {
    versions <- json_member(targets[[i]], "versions")
    if (is.null(versions)) {
      return(TRUE)
    }
    any(vapply(json_items(versions), function(v) {
      at <- json_member(v, "version")
      states <- identical(json_string(json_member(v, "status")), "affected")
      exact <- !is.na(version[[i]]) && identical(json_string(at), version[[i]])
      states && (exact || (is.null(at) && is.null(json_member(v, "range"))))
    }, logical(1)))
  }, logical(1))
}

# SPDX 2 advisory references, SECURITY in SPDX 2.3 and OTHER in 2.2, of the
# packages `el`: each names its package, and its comment says the fix, or
# that there is none, in the words of spdx_advisory_comment(). A reference
# is one of OSV's listings only when its locator is an osv.dev vulnerability
# page, whose last path segment, percent-decoded, is the id, and its comment
# says in those words that OSV lists the package that holds it, by its exact
# name and version as the document gives them, naming no other id. A
# reference attached to a package for any other reason says nothing OSV
# said about that package.
read_spdx2_advisories <- function(el) {
  refs <- json_flatten(el$raw, "externalRefs")
  advisory <- json_strings(refs$items, "referenceCategory") %in% c("SECURITY", "OTHER") &
    json_strings(refs$items, "referenceType") %in% "advisory"
  items <- refs$items[advisory]
  owner <- refs$owner[advisory]
  locator <- json_strings(items, "referenceLocator")
  on_osv <- !is.na(locator) & grepl(osv_page_pattern, locator)
  id <- rep(NA_character_, length(items))
  id[on_osv] <- read_osv_url_id(sub(osv_page_pattern, "\\1", locator[on_osv]))
  said <- read_spdx2_comment(json_strings(items, "comment"))
  name <- el$name[owner]
  version <- el$version[owner]
  listing <- (on_osv & !is.na(name) & !is.na(version) & !is.na(said$names) &
    said$names == paste(name, version) & (is.na(said$id) | said$id == id)) %in% TRUE
  read_advisory_raw(
    id = id, listing = listing,
    hits = read_advisory_hits(seq_along(items), owner, said$fixed, said$no_fix)
  )
}

# An id percent-encoded as osv_vulnerability_url() encodes it, decoded. Only
# the escapes of characters an OSV id may hold are decoded; any other stays,
# so that osv_id_ok() refuses the id.
read_osv_url_id <- function(x) {
  allowed <- utf8ToInt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
  escapes <- gregexpr("%[0-9A-Fa-f]{2}", x)
  regmatches(x, escapes) <- lapply(regmatches(x, escapes), function(esc) {
    code <- strtoi(substring(esc, 2L), 16L)
    ok <- code %in% allowed
    esc[ok] <- vapply(code[ok], intToUtf8, character(1))
    esc
  })
  x
}

# The parts of each comment in the words of spdx_advisory_comment(),
# "<id>[, <summary>]. OSV lists <name> <version> among the versions it
# affects[, fixed in <version>|, with no fix].", in which the id and the
# summary may be left out: the id (NA when it is left out), the
# "<name> <version>" it names (NA for a comment in other words), the fix,
# and whether it says there is none. The summary may hold anything, line
# breaks and sentences in these words among them, so the sentence read is
# the one the comment ends with.
read_spdx2_comment <- function(comment) {
  pattern <- paste0(
    "(?s)^(?:([^\\s,]+?)(?:, .*)?[.] )?OSV lists (.+) among the versions it affects",
    "(?:, fixed in (.+?)|(, with no fix))?[.]$"
  )
  parts <- regmatches(comment, regexec(pattern, comment, perl = TRUE))
  part <- function(k) {
    vapply(parts, function(p) if (length(p) > k && nzchar(p[[k + 1L]])) p[[k + 1L]] else NA_character_, "")
  }
  list(id = part(1L), names = part(2L), fixed = part(3L), no_fix = !is.na(part(4L)))
}

# SPDX 3 security_Vulnerability elements: the id is the securityOther
# identifier whose locator is an osv.dev vulnerability page, which makes the
# element one of OSV's listings; the summary, or else the description; the
# published time; the first locator of the securityAdvisory reference; the
# cve identifiers; and the packages its hasAssociatedVulnerability
# relationships come from, matched to `id`, the components' ids. No VEX
# relationship is read, but an association beside a VEX relationship of
# the same vulnerability that involves the same package is not a listing
# (read_spdx3_vex_pairs()), as a CycloneDX analysis is not.
read_spdx3_advisories <- function(doc, t, ix, id) {
  graph <- unname(json_items(json_member(doc, "@graph")))
  at <- which(ix$type %in% "security_Vulnerability")
  vulns <- graph[at]
  n <- length(vulns)
  ext <- json_flatten(vulns, "externalIdentifier")
  ext_type <- json_strings(ext$items, "externalIdentifierType")
  ext_id <- json_strings(ext$items, "identifier")
  on_osv <- vapply(ext$items, function(e) {
    locators <- vapply(json_items(json_member(e, "identifierLocator")), json_string, character(1))
    any(!is.na(locators) & grepl(osv_page_pattern, locators))
  }, logical(1))
  osv_other <- ext_type %in% "securityOther" & on_osv
  refs <- json_flatten(vulns, "externalRef")
  locator <- vapply(refs$items, function(x) {
    locators <- json_items(json_member(x, "locator"))
    if (length(locators) > 0L) json_string(locators[[1L]]) else NA_character_
  }, character(1))
  advisory_ref <- json_strings(refs$items, "externalRefType") %in% "securityAdvisory"
  cve <- ext_type %in% "cve"
  rel <- t$relationships[t$relationships$type %in% "hasAssociatedVulnerability", , drop = FALSE]
  vex <- read_spdx3_vex_pairs(graph, ix)
  read_advisory_raw(
    id = read_first(ext_id, ext$owner, n, osv_other),
    listing = seq_len(n) %in% ext$owner[osv_other],
    summary = tables_coalesce(
      tables_present(json_strings(vulns, "summary")), tables_present(json_strings(vulns, "description"))
    ),
    published = json_strings(vulns, "security_publishedTime"),
    source_url = read_first(locator, refs$owner, n, advisory_ref),
    upstream = data.frame(advisory = ext$owner[cve], id = ext_id[cve], stringsAsFactors = FALSE),
    hits = read_advisory_hits(
      match(rel$to, ix$spdx_id[at], incomparables = NA), match(rel$from, id, incomparables = NA),
      listed = !paste(rel$to, rel$from, sep = "\r") %in% vex
    )
  )
}

# Every pair of ends of each SPDX 3 VEX relationship
# (security_Vex*VulnAssessmentRelationship) of the graph, as "a\rb", in both
# orders: its `from`, its `to` and its `security_assessedElement`. No id
# holds a carriage return.
read_spdx3_vex_pairs <- function(graph, ix) {
  at <- which(grepl("^security_Vex[A-Za-z]*VulnAssessmentRelationship$", ix$type))
  unlist(lapply(graph[at], function(r) {
    ends <- c(
      json_string(json_member(r, "from")), vapply(json_items(json_member(r, "to")), json_string, character(1)),
      json_string(json_member(r, "security_assessedElement"))
    )
    ends <- unique(ends[!is.na(ends)])
    pairs <- expand.grid(a = ends, b = ends, stringsAsFactors = FALSE)
    pairs <- pairs[pairs$a != pairs$b, , drop = FALSE]
    paste(pairs$a, pairs$b, sep = "\r")
  }), use.names = FALSE)
}

# The advisories table from what a family's reader gave (read_advisory_raw()),
# as read_advisories() returns it. An entry that is not one of OSV's listings,
# or whose id is not an OSV id, is dropped, and so is a hit on a component
# without a version. A hit that is not a listing is dropped too, and an
# entry that names components and is a listing of none of them is not one
# of OSV's listings. Entries with one id are one advisory, with the fields
# of the first and the components of all, each once; an advisory left with
# no component is dropped. Each entry dropped is counted once, and so is
# each hit that is not a listing in an entry otherwise kept.
read_advisory_table <- function(raw, ref, version, seen) {
  rec <- raw$records
  ids <- text_strip(rec$id)
  hits <- raw$hits
  owned <- !is.na(hits$advisory)
  names_some <- tabulate(hits$advisory[owned], nbins = nrow(rec)) > 0L
  lists_some <- tabulate(hits$advisory[owned & hits$listed], nbins = nrow(rec)) > 0L
  listing <- rec$listing %in% TRUE & (!names_some | lists_some)
  ok <- listing & osv_id_ok(ids)
  unlisted <- owned & !hits$listed
  unlisted[unlisted] <- ok[hits$advisory[unlisted]]
  keep <- owned & hits$listed & !is.na(hits$element)
  keep[keep] <- ok[hits$advisory[keep]] & !is.na(version[hits$element[keep]])
  hits <- hits[keep, , drop = FALSE]
  hit_id <- ids[hits$advisory]
  hit_ref <- ref[hits$element]
  # Neither an OSV id nor a cleaned ref holds a carriage return.
  once <- !duplicated(paste(hit_id, hit_ref, sep = "\r"))
  hits <- hits[once, , drop = FALSE]
  hit_id <- hit_id[once]
  hit_ref <- hit_ref[once]
  found <- sort(unique(hit_id), method = "radix")
  out <- list(
    advisories = empty_advisories(), dropped = character(), not_listing = sum(!listing),
    no_id = sum(listing & !ok), no_component = sum(ok & !ids %in% found), unlisted = sum(unlisted)
  )
  if (length(found) == 0L) {
    return(out)
  }

  at <- match(found, ids)
  # The ids kept are `found`; this counts those that held control characters.
  read_clean(rec$id[at], seen)
  urls <- read_urls(rec$source_url[at])
  up <- raw$upstream
  upstream <- lapply(unname(split(up$id, factor(up$advisory, levels = at))), function(u) unique(cve_ids(u)))
  r <- raw$ratings[raw$ratings$advisory %in% at, , drop = FALSE]
  text <- function(x) read_clean(tables_present(x), seen)
  method <- text(r$method)
  vector <- text(r$vector)
  severity <- text(r$severity)
  ratings <- lapply(unname(split(seq_len(nrow(r)), factor(r$advisory, levels = at))), function(i) {
    data.frame(
      upstream = rep(NA_character_, length(i)), method = method[i], vector = vector[i], score = r$score[i],
      severity = severity[i], stringsAsFactors = FALSE
    )
  })
  fixed <- text(hits$fixed)
  affects <- lapply(unname(split(seq_along(hit_id), factor(hit_id, levels = found))), function(i) {
    i <- i[order(hit_ref[i], method = "radix")]
    data.frame(
      ref = hit_ref[i], version = version[hits$element[i]], fixed = fixed[i], no_fix = hits$no_fix[i],
      stringsAsFactors = FALSE
    )
  })
  adv <- data.frame(
    id = found, summary = read_clean(tables_present(rec$summary[at]), seen, lines = TRUE),
    published = osv_date(read_date(rec$published[at])), source_url = urls$value,
    stringsAsFactors = FALSE
  )
  adv$upstream <- upstream
  adv$ratings <- ratings
  adv$affects <- affects
  out$advisories <- adv
  out$dropped <- urls$dropped
  out
}

# The sentences of the read-advisories-dropped issue, which count entries:
# those that are not OSV's advisory listings, those without an OSV id, and
# those that name no component of the document that has a version; and the
# components that entries otherwise read were not read for (`unlisted`).
read_advisory_messages <- function(not_listing, no_id, no_component, unlisted = 0L) {
  c(
    if (not_listing > 0L) {
      one_or_many(
        not_listing, "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read.",
        paste0(
          not_listing, " vulnerability entries in the document are not OSV advisory listings, so they were not read."
        )
      )
    },
    if (unlisted > 0L) {
      one_or_many(
        unlisted,
        paste0(
          "1 component of a vulnerability entry in the document is given a version status or VEX statement ",
          "that is not an OSV advisory listing, so the entry was not read for it."
        ),
        paste0(
          unlisted, " components of vulnerability entries in the document are given version statuses or VEX ",
          "statements that are not OSV advisory listings, so the entries were not read for them."
        )
      )
    },
    if (no_id > 0L) {
      one_or_many(
        no_id, "1 vulnerability entry in the document has no OSV id, so it was not read.",
        paste0(no_id, " vulnerability entries in the document have no OSV id, so they were not read.")
      )
    },
    if (no_component > 0L) {
      one_or_many(
        no_component,
        "1 vulnerability entry names no component of the document that has a version, so it was not read.",
        paste0(
          no_component,
          " vulnerability entries name no component of the document that has a version, so they were not read."
        )
      )
    }
  )
}
