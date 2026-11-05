# The content layer of validate_sbom(). content_findings() runs the integrity
# checks and a profile's checks on the neutral tables of document_tables(),
# and returns one row per finding: the check's code, its severity, the JSON
# pointer of the value at fault ("" for the document as a whole) and a
# sentence. The checks are vectorised over the tables: licence expressions and
# purls are checked once per distinct value and joined back to their rows,
# duplicate ids are found with duplicated() both ways, and relationship ends
# are matched against one set of ids, so that a document of tens of thousands
# of components is checked in seconds. Values come from files of any origin,
# so a message quotes each through quote_value(), which shows its control
# characters as spaces and cuts it short, and names at most 20 items of a
# list. Patterns are matched on bytes, so that a check gives the same answer
# in every locale.

content_severities <- c("error", "warning", "info")

# The SPDX 2 serializations, which must define each LicenseRef they use in
# hasExtractedLicensingInfos.
content_spdx2_formats <- c("spdx-json", "spdx-yaml", "spdx-xml", "spdx-tv")

# The CycloneDX formats, whose licence expressions are SPDX expressions
# proper, in which NONE and NOASSERTION have no place.
content_cdx_formats <- c("cyclonedx-json", "cyclonedx-xml")

# The individuals SPDX 3 JSON-LD may name where an element is expected, in the
# compact form its context gives them: the constants of Element_derived in
# the bundled schema, which a test pins.
content_spdx3_individuals <- c(
  "NoAssertionElement", "NoneElement", "SpdxOrganization",
  "expandedlicensing_NoAssertionLicense", "expandedlicensing_NoneLicense"
)

#' Check the content of an SBOM
#'
#' The integrity checks (ids, relationships, licences, purls and R package
#' names) always run; the profile adds its own.
#'
#' @param tables What `document_tables()` returns, or tables of its shape.
#' @param format The format the tables were read from, or NA for an `<sbom>`
#'   object, to which the SPDX 2 LicenseRef check and the SWID rules do not
#'   apply.
#' @param profile The name of a profile of `content_profiles()`.
#' @param call The call an error names.
#' @return `data.frame(check, severity, location, message)`, ordered by
#'   severity (error, warning, info), then check, then location in document
#'   order (see `content_location_key()`).
#' @noRd
content_findings <- function(tables, format, profile = "ntia-2021", call = parent.frame()) {
  profiles <- content_profiles()
  if (!is_string(profile) || !profile %in% names(profiles)) {
    cli::cli_abort(
      "{.arg profile} must be one of {.val {names(profiles)}}, not {.val {profile}}.",
      call = call
    )
  }
  findings <- content_bind(list(
    content_duplicate_ids(tables$elements, format),
    content_dangling(tables$relationships, tables$document, format),
    content_licenses(tables$licenses, tables$document, format),
    content_purls(tables$purls, tables$elements),
    profiles[[profile]](tables, format)
  ))
  o <- order(
    match(findings$severity, content_severities), findings$check,
    content_location_key(findings$location), findings$location,
    method = "radix"
  )
  do.call(tables_strings, lapply(findings, `[`, o))
}

# A key that sorts JSON pointers in document order: segment by segment, and a
# segment that is a number as a number (/packages/2 before /packages/10). The
# numbers are padded with zeros to one width and the segments joined by a byte
# below any a pointer holds, so that a radix sort of the keys, the same in
# every locale, puts the pointers in that order.
content_location_key <- function(location) {
  parts <- strsplit(location, "/", fixed = TRUE)
  seg <- as.character(unlist(parts, use.names = FALSE))
  num <- content_grepl("^[0-9]+$", seg)
  if (any(num)) {
    width <- max(nchar(seg[num], type = "bytes"))
    seg[num] <- paste0(strrep("0", width - nchar(seg[num], type = "bytes")), seg[num])
  }
  owner <- factor(rep.int(seq_along(parts), lengths(parts)), levels = seq_along(parts))
  vapply(split(seg, owner), paste, character(1), collapse = "\001", USE.NAMES = FALSE)
}

#' The content profiles
#'
#' @return A named list of functions `function(tables, format = NA)`, each
#'   giving its profile's findings in the shape of `content_findings()`.
#'   `"ntia-2021"` checks the NTIA 2021 minimum elements; `"none"` adds
#'   nothing.
#' @noRd
content_profiles <- function() {
  list(`ntia-2021` = content_ntia, none = content_none)
}

#' A fix hint for each content check
#'
#' @return A named character vector: one sentence per check code.
#' @noRd
check_hints <- function() {
  c(
    `duplicate-id` = "Give each element its own id, so that a relationship names exactly one element.",
    `dangling-relationship` = "Make each relationship name an element the document defines, or add that element.",
    `license-invalid` = "Write the licence as an SPDX licence expression, such as MIT or GPL-2.0-only OR GPL-3.0-only.",
    `license-unknown` = "Use the ids of the SPDX License List, or a LicenseRef- for a licence it does not list.",
    `license-deprecated` = "Replace each deprecated id with the one the SPDX License List now gives for that licence.",
    `license-ref-undefined` = "Add an entry to hasExtractedLicensingInfos for each LicenseRef- the document uses.",
    `purl-invalid` = "Write the purl as the Package URL specification gives it, as in pkg:cran/cli@3.6.0.",
    `r-package-name` = "Check the component's purl: an R package name has at least two characters, only letters, digits and dots, starts with a letter and does not end with a dot.",
    `r-version` = "Check the component's purl: an R package version is two or more numbers separated by dots or hyphens, such as 1.2.3 or 1.2-3.",
    `r-purl-name` = "Make the name in the purl the component's name.",
    `ntia-author` = "Name the person or organization that made the SBOM data as its author; if sbom made this SBOM, give its author or organization argument.",
    `ntia-timestamp` = "Record when the SBOM was made, in a format that has a field for it.",
    `ntia-supplier` = "State each component's supplier; if sbom made this SBOM, assert the ones it cannot find with an override of supplier_name.",
    `ntia-name` = "Give each component a name.",
    `ntia-version` = "State each component's version; if sbom made this SBOM, assert the ones it cannot find with an override of version.",
    `ntia-identifier` = "Give each component a purl, CPE or SWID tag id; if sbom made this SBOM, assert a purl it cannot find with an override of purl.",
    `ntia-relationships` = "Name the component the SBOM describes, and state what it depends on or contains.",
    `swid-links` = "Check the linked tags on their own, or use a format that lists every component."
  )
}

# Findings ---------------------------------------------------------------------

# The findings of one check at one severity: one per location.
content_rows <- function(check, severity, location = character(), message = character()) {
  n <- length(location)
  tables_strings(
    check = rep(check, n), severity = rep(severity, n), location = location, message = message
  )
}

# Binds the findings `parts` into one data frame.
content_bind <- function(parts) {
  cols <- c("check", "severity", "location", "message")
  do.call(tables_strings, lapply(stats::setNames(cols, cols), function(col) tables_column(parts, col)))
}

# Whether each value is present: not NA, not empty or only spaces, and not
# NOASSERTION.
content_present <- function(x) {
  trimmed <- trimws(x, whitespace = "[ \t\r\n]")
  !is.na(x) & nzchar(trimmed) & trimmed != "NOASSERTION"
}

# grepl() on bytes: the patterns are ASCII, and a byte outside them does not
# match.
content_grepl <- function(pattern, x) {
  grepl(pattern, x, perl = TRUE, useBytes = TRUE)
}

# Whether each value is empty or only spaces, which a message cannot quote.
content_blank <- function(x) {
  !nzchar(trimws(x, whitespace = "[ \t\r\n]"))
}

# The label of each element: "<name> <version>", or the name alone, or the id
# when there is no name, or where the element is when it has neither. `start`
# gives the form that begins a sentence.
content_labels <- function(el, start = FALSE) {
  name <- ifelse(content_present(el$name), el$name, NA_character_)
  version <- ifelse(content_present(el$version), el$version, NA_character_)
  id <- ifelse(content_present(el$id), el$id, NA_character_)
  label <- ifelse(is.na(name), id, ifelse(is.na(version), name, paste(name, version)))
  at <- tables_paste(if (start) "The " else "the ", el$kind, " at ", el$location)
  ifelse(is.na(label), at, quote_value(label))
}

# Integrity --------------------------------------------------------------------

# Each element whose id another element also has. A SWID tag defines one id,
# its own; its links name other tags, which may repeat.
content_duplicate_ids <- function(el, format) {
  if (format %in% "swid") {
    return(content_rows("duplicate-id", "error"))
  }
  id <- el$id
  dup <- !is.na(id) & (duplicated(id) | duplicated(id, fromLast = TRUE))
  ids <- id[dup]
  first <- match(ids, ids)
  n <- tabulate(first, length(ids))[first]
  content_rows(
    "duplicate-id", "error", el$location[dup],
    tables_paste("The id ", quote_value(ids), " is used by ", n, " elements; each element needs its own id.")
  )
}

# Each relationship end that names no id of the document. An end may also name
# the SPDX 2 document, NONE or NOASSERTION, an element of another document
# (SPDX 2's DocumentRef-x:y, or an SPDX 3 import), or one of SPDX 3's own
# individuals such as NoneElement, as a full IRI or, in SPDX 3, in compact
# form. A relationship with no target (an empty CycloneDX dependsOn) has
# nothing to dangle. A SWID tag's links name other tags, so they are not
# checked.
#
# A target is reported at its edge. A source is reported once, at the entry
# that states it: a row of the relationships table is one target of an entry
# (a CycloneDX dependencies entry, an SPDX 3 Relationship), whose pointer ends
# in /dependsOn/<i>, /provides/<i> or /to/<i>; an SPDX 2 relationship is its
# own entry.
content_dangling <- function(rel, doc, format) {
  if (format %in% "swid") {
    return(content_rows("dangling-relationship", "error"))
  }
  known <- c(
    doc$ids, doc$external_ids, "SPDXRef-DOCUMENT", "NONE", "NOASSERTION",
    if (format %in% "spdx3-jsonld") content_spdx3_individuals
  )
  dangles <- function(end) {
    !is.na(end) & !end %in% known & !content_grepl("^DocumentRef-[^:]+:.", end) &
      !startsWith(end, "https://spdx.org/rdf/3.")
  }
  entry <- sub("/(dependsOn|provides|to)/[0-9]+$", "", rel$location)
  # An entry has one source, so one finding per entry.
  bad_from <- dangles(rel$from) & !duplicated(entry)
  bad_to <- dangles(rel$to)
  content_rows(
    "dangling-relationship", "error", c(entry[bad_from], rel$location[bad_to]),
    tables_paste(
      "The relationship refers to ", quote_value(c(rel$from[bad_from], rel$to[bad_to])),
      ", which is not an element of this document."
    )
  )
}

# The licence expressions: each distinct one is checked once, and its
# findings go to every row that holds it. Licence names (free text) are not
# checked. NONE and NOASSERTION are whole licences in SPDX, not in CycloneDX.
# An id of the SPDX License List in the wrong place (an exception as a
# licence, a licence after WITH) makes the expression invalid; only an id on
# neither list is unknown.
content_licenses <- function(lic, doc, format) {
  is_expr <- lic$kind == "expression"
  value <- lic$expression[is_expr]
  location <- lic$location[is_expr]
  u <- unique(value)
  k <- match(value, u)
  chk <- license_expression_check(u, special = !format %in% content_cdx_formats)
  version <- spdx_license_list_version()

  # The ids the checker did not take, each looked up once in the list.
  lst <- spdx_license_list()
  unknown <- as.character(unlist(chk$unknown, use.names = FALSE))
  owner <- rep.int(seq_along(u), lengths(chk$unknown))
  kind <- lst$kind[match(tolower(unknown), tolower(lst$id))]
  by_value <- function(keep) {
    unname(split(unknown[keep], factor(owner[keep], levels = seq_along(u))))
  }
  # The first id in the wrong place, as the expression's problem clause.
  listed <- which(!is.na(kind))
  first <- listed[!duplicated(owner[listed])]
  id <- quote_value(unknown[first])
  problem <- chk$problem
  problem[owner[first]] <- ifelse(
    kind[first] == "license",
    paste0("it uses ", id, " after WITH, but ", id, " is a licence, not an exception"),
    paste0("it uses the exception ", id, " as a licence")
  )

  # A message for each distinct expression, NA where the check passes.
  per_value <- function(ids, text) {
    out <- rep(NA_character_, length(u))
    has <- lengths(ids) > 0L
    out[has] <- vapply(which(has), function(i) text(ids[[i]], u[[i]]), character(1))
    out
  }
  invalid <- ifelse(
    is.na(problem), NA_character_,
    ifelse(
      content_blank(u), "An empty licence expression is not a valid SPDX expression.",
      paste0("The licence expression ", quote_value(u), " is not a valid SPDX expression: ", problem, ".")
    )
  )
  unknown_msg <- per_value(by_value(is.na(kind)), function(ids, expr) {
    paste0(
      "The licence expression ", quote_value(expr), " uses ", read_list(quote_value(ids)), ", which ",
      if (length(ids) == 1L) "is" else "are", " not on the SPDX License List ", version, "."
    )
  })
  deprecated <- per_value(chk$deprecated, function(ids, expr) {
    paste0(
      "The licence expression ", quote_value(expr), " uses the deprecated SPDX licence ",
      if (length(ids) == 1L) "id " else "ids ", read_list(quote_value(ids)), "."
    )
  })
  rows <- function(check, severity, message) {
    message <- message[k]
    has <- !is.na(message)
    content_rows(check, severity, location[has], message[has])
  }
  parts <- list(
    rows("license-invalid", "error", invalid),
    rows("license-unknown", "error", unknown_msg),
    rows("license-deprecated", "warning", deprecated)
  )
  if (format %in% content_spdx2_formats) {
    # One finding per reference that the document does not define, all
    # references matched in one pass. A DocumentRef- prefix names another
    # document's licence.
    refs <- as.character(unlist(chk$refs, use.names = FALSE))
    ref_owner <- rep.int(seq_along(u), lengths(chk$refs))
    bad <- startsWith(refs, "LicenseRef-") & !refs %in% doc$defined_refs
    undefined <- unname(split(refs[bad], factor(ref_owner[bad], levels = seq_along(u))))
    n <- lengths(undefined)[k]
    row <- rep.int(seq_along(k), n)
    parts$refs <- content_rows(
      "license-ref-undefined", "error", location[row],
      tables_paste(
        "The licence expression ", quote_value(value[row]), " uses ",
        quote_value(unlist(undefined[k[n > 0L]], use.names = FALSE)),
        ", which the document does not define in hasExtractedLicensingInfos."
      )
    )
  }
  content_bind(parts)
}

# The purls, each distinct one parsed once, and the R checks of the elements
# whose purl says they are CRAN packages.
content_purls <- function(purls, el) {
  u <- unique(c(purls$purl, el$purl[!is.na(el$purl)]))
  parsed <- purl_parse(u)
  k <- match(purls$purl, u)
  bad <- !parsed$valid[k]
  invalid <- content_rows(
    "purl-invalid", "error", purls$location[bad],
    ifelse(
      content_blank(purls$purl[bad]), "An empty purl is not valid.",
      tables_paste("The purl ", quote_value(purls$purl[bad]), " is not valid: ", parsed$problem[k][bad], ".")
    )
  )

  j <- match(el$purl, u, incomparables = NA)
  cran <- parsed$valid[j] %in% TRUE & tolower(parsed$type[j]) %in% "cran"
  name <- el$name
  has_name <- cran & content_present(name)
  bad_name <- has_name & !content_grepl("^[A-Za-z][A-Za-z0-9.]*[A-Za-z0-9]$", name)
  bad_version <- cran & content_present(el$version) &
    !content_grepl("^[0-9]+([.-][0-9]+)+$", el$version)
  pname <- parsed$name[j]
  other <- has_name & pname != name
  content_bind(list(
    invalid,
    content_rows(
      "r-package-name", "error", el$location[bad_name],
      tables_paste(
        quote_value(name[bad_name]), " is not a valid R package name, although its purl says it is a CRAN package."
      )
    ),
    content_rows(
      "r-version", "warning", el$location[bad_version],
      tables_paste(
        content_labels(el[bad_version, , drop = FALSE], start = TRUE),
        " has a version that is not an R package version."
      )
    ),
    content_rows(
      "r-purl-name", "warning", el$location[other],
      tables_paste(
        "The purl ", quote_value(el$purl[other]), " names ", quote_value(pname[other]), ", not ",
        quote_value(name[other]), "."
      )
    )
  ))
}

# Profiles ---------------------------------------------------------------------

content_none <- function(tables, format = NA_character_) {
  content_bind(list())
}

# The NTIA 2021 minimum elements: the document's author and timestamp, each
# component's supplier, name, version and identifier, and the relationships
# of the primary component. A value is present when it is not empty and not
# NOASSERTION; an asserted (override) value is a value like any other. Files
# and snippets, which in CycloneDX are components of type file, are not
# components here. A SWID tag describes only itself, so of its elements only
# the tag gets the component checks, and it has no timestamp.
content_ntia <- function(tables, format = NA_character_) {
  el <- tables$elements
  doc <- tables$document
  swid <- format %in% "swid"
  parts <- list()

  authors <- doc$authors
  if (nrow(authors) == 0L) {
    parts$author <- content_rows("ntia-author", "error", "", "The document names no author.")
  } else if (all(authors$kind %in% "tool")) {
    one <- nrow(authors) == 1L
    parts$author <- content_rows(
      "ntia-author", "warning", authors$location[[1L]],
      paste0(
        "The document names only ", if (one) "a tool" else "tools", " (", read_list(quote_value(authors$name)),
        ") as its ", if (one) "author" else "authors",
        "; NTIA asks for the person or organization that made the SBOM data."
      )
    )
  }

  if (swid) {
    parts$timestamp <- content_rows(
      "ntia-timestamp", "error", "",
      "A SWID tag has no field for the time it was made, so it has no timestamp."
    )
  } else if (!content_present(doc$timestamp)) {
    parts$timestamp <- content_rows("ntia-timestamp", "error", "", "The document has no timestamp.")
  }

  # A CycloneDX component of type file is a file, as SPDX's files are.
  is_comp <- el$kind == "component" & !(format %in% content_cdx_formats & el$type %in% "file")
  checked <- is_comp & (!swid | el$is_root)
  label <- content_labels(el, start = TRUE)
  absent_rows <- function(check, absent, message) {
    hit <- checked & absent
    content_rows(check, "error", el$location[hit], message[hit])
  }
  ident <- el$identifiers
  owner <- rep.int(seq_along(ident), lengths(ident))
  ident <- unlist(ident, use.names = FALSE)
  stated <- content_grepl("^(purl|cpe|swid):", ident) &
    content_present(sub("^(purl|cpe|swid):", "", ident))
  has_ident <- tabulate(owner[stated], nrow(el)) > 0L
  parts$supplier <- absent_rows(
    "ntia-supplier", !content_present(el$supplier) & !content_present(el$originator),
    tables_paste(label, " has no supplier.")
  )
  parts$name <- absent_rows(
    "ntia-name", !content_present(el$name),
    ifelse(
      content_present(el$id), tables_paste("The component ", quote_value(el$id), " has no name."),
      tables_paste("The component at ", el$location, " has no name.")
    )
  )
  parts$version <- absent_rows(
    "ntia-version", !content_present(el$version), tables_paste(label, " has no version.")
  )
  parts$identifier <- absent_rows(
    "ntia-identifier", !has_ident, tables_paste(label, " has no purl, CPE or SWID identifier.")
  )
  parts$relationships <- content_ntia_relationships(el, tables$relationships, doc, is_comp)

  if (swid && sum(!el$is_root) > 0L) {
    n <- sum(!el$is_root)
    parts$links <- content_rows(
      "swid-links", "info", "/links",
      paste0(
        "A SWID tag describes only itself, so the ", n,
        if (n == 1L) " tag it links to was" else " tags it links to were", " not checked."
      )
    )
  }
  content_bind(parts)
}

# The document must name its primary component and, when it lists other
# components, state the primary component's relationships: a relationship
# from it of any type but DESCRIBES (CycloneDX's dependencies entry for it
# counts even when empty), an SPDX 2 relationship to it that reads from the
# other side, such as "x DEPENDENCY_OF root" or "x CONTAINED_BY root", which
# is how SPDX 2 states optional dependencies, or components nested in it,
# which in CycloneDX need no id.
content_ntia_relationships <- function(el, rel, doc, is_comp) {
  if (length(doc$root) == 0L) {
    return(content_rows(
      "ntia-relationships", "error", "", "The document names no primary component."
    ))
  }
  if (sum(is_comp) <= 1L) {
    return(content_rows("ntia-relationships", "error"))
  }
  # SPDX 2 spells it DESCRIBES, SPDX 3 describes.
  counts_from <- !tolower(rel$type) %in% c("describes", "described_by")
  counts_to <- content_grepl("_OF$", rel$type) | rel$type %in% "CONTAINED_BY"
  related <- c(rel$from[counts_from], rel$to[counts_to])
  nests <- el$location %in% el$parent
  lonely <- el$is_root & is_comp & !(!is.na(el$id) & el$id %in% related) & !nests
  content_rows(
    "ntia-relationships", "error", el$location[lonely],
    tables_paste(
      "The document states no relationships for its primary component ",
      content_labels(el[lonely, , drop = FALSE]), "."
    )
  )
}
