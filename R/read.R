# Reading any SBOM into an <sbom>. read_sbom() maps the neutral tables of
# document_tables() to components, relationships, issues and metadata, so that
# an SBOM from sbom or from any other tool can be inspected, compared and
# written again in any format. Values come from files of any origin: a value
# that is not a single string, or is empty, is absent. URLs are kept as sbom
# keeps its own, without credentials, query or fragment and never as a local
# path, and a value that a writer could not write validly (a URL that is not
# an IRI reference, a checksum not every format takes) is dropped and
# counted, so that a read SBOM writes valid documents. A control character
# could rewrite the terminal the SBOM is printed on, and SPDX YAML cannot
# hold one, so every value keeps none (read_clean()). The values of each
# format's elements are read in read-fields.R.

# The checksum algorithms sbom writes in every format, in CycloneDX's
# spelling, with the number of hex digits of each. SPDX 2.2 has no SHA3,
# which its writer leaves out.
read_hash_digits <- c(
  MD5 = 32L, `SHA-1` = 40L, `SHA-256` = 64L, `SHA-384` = 96L, `SHA-512` = 128L,
  `SHA3-256` = 64L, `SHA3-384` = 96L, `SHA3-512` = 128L
)

# Those algorithms in SPDX 3's spelling.
read_spdx3_hashes <- c(
  md5 = "MD5", sha1 = "SHA-1", sha256 = "SHA-256", sha384 = "SHA-384", sha512 = "SHA-512",
  sha3_256 = "SHA3-256", sha3_384 = "SHA3-384", sha3_512 = "SHA3-512"
)

read_evidence <- c("declared", "observed", "inferred", "unknown")

#' Read an SBOM file
#'
#' Reads an SBOM in any of the eight formats that [write_sbom()] writes, made
#' by sbom or by any other tool, into an `<sbom>` object. It can then be
#' inspected with [sbom_components()], compared with [sbom_diff()], or written
#' again in any format.
#'
#' @details
#' `read_sbom()` reads CycloneDX JSON and XML (1.4 to 1.7), SPDX 2.2 and 2.3
#' as JSON, YAML, XML or tag-value, SPDX 3.0.1 JSON-LD, and SWID tags
#' (ISO/IEC 19770-2:2015). It detects the format from the file's content, not
#' from its name, so the file can be named anything. Reading SPDX YAML needs
#' the yaml package. SPDX YAML nested more than 200 levels deep, or holding
#' more than one YAML document, is a read error found before the file is
#' parsed. A crafted SPDX YAML file can still take tens of seconds to refuse.
#'
#' Each component or package the document lists becomes a component (SPDX
#' files and snippets do not), the one the document describes becomes the
#' root, and each dependency between two components becomes a relationship.
#' A component is optional when the document marks it optional, or when every
#' dependency on it is optional. The document's own notes follow a first note
#' that names the file and its format. An element without an id takes its
#' purl as its ref, then `name@version`, then `component-<n>`. The ecosystem
#' is the purl type, and `"unknown"` without a purl. URLs are kept as sbom
#' keeps its own: without credentials, query string or fragment, and never a
#' local path or a `file:` URL, and so are the URLs in a purl's qualifiers,
#' such as `repository_url`. Each control character of a value (C0 but tab
#' and newline, DEL and C1) is replaced with a space, and so are tab and
#' newline in names, versions, refs and purls, which are then trimmed.
#'
#' The OSV advisory listings the document holds, as sbom and R Observatory
#' write them, are read too, for [sbom_advisories()]: CycloneDX
#' vulnerabilities whose source is OSV and that hold no `analysis`; SPDX 2
#' advisory references (category `SECURITY` in SPDX 2.3, `OTHER` in 2.2)
#' whose locator is an osv.dev vulnerability page and whose comment says, in
#' sbom's words, that OSV lists the package that holds it at its version,
#' naming no other id; and SPDX 3
#' `security_Vulnerability` elements whose `securityOther` identifier points
#' to osv.dev, with their `hasAssociatedVulnerability` relationships. Each
#' names the components it affects, at their versions. Other vulnerability
#' entries, such as another tool's vulnerabilities and VEX statements, are
#' not OSV advisory listings: they are not read, since every format sbom
#' writes says that OSV lists each advisory for the version. Nor is an entry
#' read for a component it states something else about: a CycloneDX
#' `affects` target with `versions` none of which has status `affected` for
#' the component's version, or for no version or range, and an SPDX 3
#' association beside a VEX relationship of the same vulnerability that
#' involves the same component. An advisory is
#' kept only when its id is an OSV id and it names a component of the
#' document that has a version. The `<sbom>`'s advisory status is
#' `"listed"` when the document lists an advisory, or says in R
#' Observatory's words that it lists those OSV gives, and `"not-requested"`
#' otherwise.
#'
#' Some values cannot come back from every format:
#'
#' | Format    | Not read back |
#' |:----------|:--------------|
#' | All       | sbom's own ecosystems (`local`, `git`, `repository`, `r`, `base-r`), DESCRIPTION dependency fields and asserted overrides; CPE identifiers; vulnerability entries that are not OSV advisory listings, such as VEX statements; checksums other than MD5, SHA-1, SHA-256, SHA-384, SHA-512 and SHA3; URLs that are not valid IRI references, local paths, and purl qualifiers whose value is a local path; licenses of other SPDX documents (`DocumentRef-`), kept only as written |
#' | CycloneDX | license comments and package file names; a root's maintainer may be the organization in `metadata.manufacture`, which SPDX then writes as a person; the versions that fix an advisory, and the upstream record each rating comes from |
#' | SPDX 2    | refs (SPDX ids replace them, so [sbom_diff()] matches components it identifies by ref only partly), supplier URLs, the license as written, evidence, minimum versions, system requirements and Bioconductor releases; maintainers that are not persons; the descriptions and publication dates that sbom writes in comments; the texts of extracted licenses (`hasExtractedLicensingInfos`), so a document written again says that the text is not included; whether a supplier is a person, so a `Person:` supplier is written again as an `Organization:`; an advisory's summary, publication date, source URL, CVE ids and ratings. SPDX 2.2 has no primary purpose, so every package is a library; SPDX 2.3 gives R the type `application`. SPDX 2.2 cannot carry SHA3 checksums, so they are left out |
#' | SPDX 3    | refs, as in SPDX 2; supplier URLs, the license as written, license comments, evidence, minimum versions, package file names, system requirements and Bioconductor releases; maintainers that are not persons; which component holds another; the descriptions that sbom writes in comments; the versions that fix an advisory, and its ratings |
#' | SWID      | refs of code compiled into a package, which gets no link; for the root, license expressions and comments, checksums, descriptions, publication dates, DOIs, evidence and Bioconductor releases; for the other components, everything but the name, version, purl, minimum version and whether it is optional; relationships other than the root's; advisories, which a tag has no place for. A tag creator with a real regid is the organization, any other is an author, except sbom itself |
#'
#' @section Issues:
#' The `<sbom>` records what could not be read as issues ([sbom_issues()]):
#'
#' * `read-files-skipped` (info): the document lists SPDX files or snippets,
#'   which are not components.
#' * `read-duplicate-id` (warning): elements share an id, so the later ones
#'   get the suffix `-2`, `-3` and so on.
#' * `read-relationships-skipped` (info): relationships of types sbom does not
#'   model.
#' * `read-dangling-relationships` (warning): relationships that name
#'   elements the document does not define.
#' * `read-several-roots` (info): the document describes more than one
#'   component, and the first in id order is the root.
#' * `read-no-root` (warning): the document describes no component, so a
#'   placeholder root with the ref `"document"` is added.
#' * `read-values-dropped` (info): values that sbom's formats cannot carry
#'   were not kept: URLs that are not valid IRI references, local paths
#'   (purl qualifiers among them), checksums of other algorithms or lengths,
#'   DOIs that cannot form a URL, and CPE identifiers.
#' * `read-advisories-dropped` (info): vulnerability entries (CycloneDX
#'   vulnerabilities, SPDX 2 advisory references, SPDX 3 vulnerabilities)
#'   that were not read, each counted once: those that are not OSV advisory
#'   listings, such as VEX statements and other sources' vulnerabilities,
#'   those whose id is not an OSV id, and those that name no component of
#'   the document that has a version; and the components that an entry
#'   otherwise read was not read for, since it gives them version statuses
#'   or VEX statements that are not listings. An entry that is a listing of
#'   none of the components it names is not an OSV advisory listing.
#' * `read-control-characters` (info): values held control characters, which
#'   were replaced with spaces.
#'
#' When the document has no timestamp, or one that is not ISO 8601, the time
#' in the `SOURCE_DATE_EPOCH` environment variable is used when it is set, and
#' otherwise the time it was read, and a note records which of the two it is.
#'
#' @param path Path of the SBOM file.
#' @param format `NULL` to detect the format from the content, or one of the
#'   `format` values of [sbom_formats()] other than `"csv"`, which the file
#'   must then be.
#' @return An `<sbom>` object. Its `metadata$inputs` holds `path`. When the
#'   file is not an SBOM in a format sbom reads, the error has class
#'   `sbom_read_error`.
#' @seealso [validate_sbom()] to check an SBOM file against its schema and the
#'   NTIA minimum elements.
#' @export
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
#' path <- file.path(tempdir(), "sbom.cdx.json")
#' write_sbom(x, path)
#' y <- read_sbom(path)
#' y
#' sbom_components(y)[, c("ref", "name", "version", "license_spdx")]
read_sbom <- function(path, format = NULL) {
  d <- read_document(path, format)
  read_sbom_build(d, document_tables(d))
}

# The family of `format`: "cdx", "spdx3", "swid" or, for the rest, "spdx2".
read_family_of <- function(format) {
  switch(format,
    `cyclonedx-json` = , `cyclonedx-xml` = "cdx",
    `spdx3-jsonld` = "spdx3",
    swid = "swid",
    "spdx2"
  )
}

# The <sbom> of the document `d`, from its tables `t`.
read_sbom_build <- function(d, t) {
  family <- read_family_of(d$format)
  file <- read_file_label(d$path)
  el <- t$elements
  is_comp <- el$kind == "component"
  n_files <- sum(!is_comp)
  el <- el[is_comp, , drop = FALSE]
  n <- nrow(el)
  # The number of values that held control characters.
  seen <- new.env(parent = emptyenv())
  seen$n <- 0L

  # Relationships name elements by their ids as written; the refs are made
  # from the cleaned values.
  id <- tables_present(el$id)
  doc_name <- read_clean(tables_present(el$name), seen)
  version <- read_clean(tables_present(el$version), seen)
  purls <- read_purls(read_clean(tables_present(el$purl), seen))
  purl <- purls$value
  # The <sbom> has no column for a CPE.
  identifiers <- as.character(unlist(el$identifiers, use.names = FALSE))
  n_cpe <- sum(startsWith(identifiers, "cpe:"))
  # The lookups document_tables() made, which are not made again.
  entities <- if (family == "swid") tables_coalesce_attr(t, "entities", tables_swid_entities(d$doc))
  creators <- if (family == "swid") read_swid_creators(entities)
  ix <- if (family == "spdx3") {
    tables_coalesce_attr(t, "index", tables_spdx3_index(unname(json_items(json_member(d$doc, "@graph")))))
  }
  fields <- switch(family,
    cdx = read_cdx_fields(el, d$doc),
    spdx2 = read_spdx2_fields(el),
    spdx3 = read_spdx3_fields(el, ix),
    swid = read_swid_fields(el, d$doc, entities)
  )
  ref_id <- if (family == "swid") read_swid_ref_ids(id, el$location, creators$regid) else id
  # A ref that is a purl is kept as the purl is, without credentials.
  ref_id <- read_purls(read_clean(ref_id, seen))$value
  unique_refs <- read_unique_refs(read_fallback_refs(ref_id, purl, doc_name, version))
  ref <- unique_refs$ref
  licenses <- read_licenses(t$licenses, el, family, fields$written)
  advisories <- read_advisories(d, t, family, el, id, ref, version, ix, seen)
  dropped <- c(fields$dropped, purls$dropped, advisories$dropped, rep(read_dropped_kinds[["cpe"]], n_cpe))
  rels <- read_relationships(t, d$doc, family, id, ref)
  edges <- rels$relationships
  edges$spec <- read_clean(edges$spec, seen, lines = TRUE)

  roots <- which(el$is_root)
  roots <- roots[order(ref[roots], method = "radix")]
  root <- roots[1L]
  depends <- edges[edges$field != "contains", , drop = FALSE]
  # Optional when every dependency on it is optional, and there is one.
  optional_edge <- depends$field %in% c("Suggests", "optional")
  only_optional <- ref %in% depends$to[optional_edge] & !ref %in% depends$to[!optional_edge]
  parent_ref <- switch(family,
    cdx = ref[match(el$parent, el$location, incomparables = NA)],
    spdx2 = read_single_parent(edges, ref),
    rep(NA_character_, n)
  )
  if (!is.na(root)) parent_ref[root] <- NA_character_
  cols <- list(
    ref = ref, name = tables_coalesce(doc_name, "unknown"), version = version,
    version_is = ifelse(
      is.na(version), NA_character_, ifelse(fields$version_is %in% "minimum", "minimum", "exact")
    ),
    type = fields$type, ecosystem = read_ecosystem(purl), is_root = seq_len(n) %in% root,
    scope = ifelse(fields$optional | only_optional, "optional", "required"),
    parent_ref = read_acyclic_parents(parent_ref, ref), purl = purl,
    supplier_name = tables_present(el$supplier), supplier_url = fields$supplier_url,
    maintainer = fields$maintainer, license_as_written = licenses$as_written,
    license_spdx = licenses$spdx, license_comment = fields$license_comment,
    published = fields$published, homepage = fields$homepage, vcs_url = fields$vcs_url,
    download_location = fields$download_location, package_file_name = fields$package_file_name,
    doi = fields$doi, description = fields$description, bioc_release = fields$bioc_release,
    evidence = ifelse(fields$evidence %in% read_evidence, fields$evidence, "declared"),
    source_input = rep(file, n), system_requirements = fields$system_requirements,
    deps_known = ref %in% c(rels$stated, depends$from), hashes = fields$hashes,
    deps = rep(list(empty_deps()), n), asserted = rep(list(empty_asserted()), n)
  )
  cols[read_text_columns] <- lapply(cols[read_text_columns], read_clean, seen = seen, lines = TRUE)
  if (is.na(root)) {
    # "document", or "document-2" and so on when an element has that ref.
    root_ref <- spdx3_unique_local("document", ref)
    placeholder <- list(
      ref = root_ref, name = tables_coalesce(read_clean(tables_present(t$document$name), seen), file),
      type = "application", ecosystem = "unknown", is_root = TRUE, scope = "required",
      evidence = "unknown", source_input = file, deps_known = FALSE
    )
    cols <- lapply(stats::setNames(names(cols), names(cols)), function(col) {
      value <- placeholder[[col]]
      if (is.list(cols[[col]])) {
        empty <- switch(col, hashes = empty_hashes(), deps = empty_deps(), asserted = empty_asserted())
        c(cols[[col]], list(empty))
      } else {
        c(cols[[col]], if (is.null(value)) NA_character_ else value)
      }
    })
  } else {
    root_ref <- ref[root]
  }
  o <- order(cols$ref, method = "radix")
  components <- read_frame(lapply(cols, function(col) col[o]))

  metadata <- read_metadata(d, t, family, root_ref, file, creators, seen)
  # Listed when the document lists advisories, or says, in R Observatory's
  # words, that it lists those OSV gives, although none matched.
  listed <- nrow(advisories$advisories) > 0L || any(grepl(advisory_notes$listed, metadata$notes, fixed = TRUE))
  metadata$advisories <- advisories_metadata(requested = listed, status = if (listed) "listed" else "not-requested")
  issues <- read_issues(
    unique_refs, root_ref, length(roots), is.na(root), n_files, rels, dropped, seen$n,
    read_advisory_messages(
      advisories$not_listing, advisories$no_id, advisories$no_component, advisories$unlisted
    )
  )
  new_sbom(metadata, components, edges, issues, advisories$advisories)
}

# The component columns of free text that read_sbom_build() cleans keeping
# tab and newline. The others are names, versions, refs and purls, cleaned
# before the refs are made, or values from a fixed set.
read_text_columns <- c(
  "supplier_name", "supplier_url", "maintainer", "license_as_written", "license_spdx",
  "license_comment", "published", "homepage", "vcs_url", "download_location",
  "package_file_name", "doi", "description", "bioc_release", "system_requirements"
)

# The values `x` as the <sbom> keeps them: each control character replaced
# with a space, keeping tab and newline when `lines`, and otherwise trimmed
# (text_strip()). Adds the number of values that held one to `seen$n`.
read_clean <- function(x, seen, lines = FALSE) {
  seen$n <- seen$n + sum(text_has_controls(x, lines))
  text_strip(x, lines)
}

# The name of the file at `path` as sentences and the <sbom> give it: its
# basename, without control characters.
read_file_label <- function(path) {
  tables_coalesce(text_strip(basename(path)), "The file")
}

# At most `max` items of a list taken from the document, as a sentence's
# list: "a, b and c", or the first `max` then ", and <k> more". The callers
# quote each item with quote_value().
read_list <- function(x, max = 20L) {
  if (length(x) <= max) {
    return(and_list(x))
  }
  paste0(paste(x[seq_len(max)], collapse = ", "), ", and ", length(x) - max, " more")
}

# The issues of a read: one for each id that elements shared, then those about
# the document, which name the root. `dropped` holds the kind of each value
# that was not kept, `n_controls` counts the values that held control
# characters, and `advisories_dropped` holds the sentences of
# read_advisory_messages().
read_issues <- function(unique_refs, root_ref, n_roots, placeholder, n_files, rels, dropped,
                        n_controls = 0L, advisories_dropped = character()) {
  issues <- empty_issues()
  if (length(unique_refs$id) > 0L) {
    issues <- add_issue(
      issues, unique_refs$id, "ref", "read-duplicate-id",
      paste0(
        unique_refs$count, " elements share the id ", quote_value(unique_refs$id), ", so sbom renamed the later ",
        ifelse(unique_refs$count == 2L, "one ", "ones "), unique_refs$renamed, "."
      )
    )
  }
  document_issue <- function(issues, field, code, message, severity) {
    add_issue(issues, root_ref, field, code, message, severity = severity)
  }
  if (n_roots > 1L) {
    issues <- document_issue(
      issues, "root", "read-several-roots",
      paste0(
        "The document has ", n_roots, " root components, so sbom took ", quote_value(root_ref),
        ", the first in id order, as the root."
      ),
      "info"
    )
  }
  if (placeholder) {
    issues <- document_issue(
      issues, "root", "read-no-root",
      paste0(
        "The document names no root component, so sbom added a placeholder root with the ref ",
        quote_value(root_ref), "."
      ),
      "warning"
    )
  }
  if (n_files > 0L) {
    issues <- document_issue(
      issues, "component", "read-files-skipped",
      if (n_files == 1L) {
        "1 file or snippet in the document is not a component, so it is not listed."
      } else {
        paste0(n_files, " files and snippets in the document are not components, so they are not listed.")
      },
      "info"
    )
  }
  if (rels$n_skipped > 0L) {
    types <- rels$skipped_types
    issues <- document_issue(
      issues, "dependencies", "read-relationships-skipped",
      paste0(
        rels$n_skipped, if (rels$n_skipped == 1L) " relationship" else " relationships",
        if (length(types) == 1L) " of a type" else " of types", " sbom does not model (",
        read_list(quote_value(types)), if (rels$n_skipped == 1L) ") was not read." else ") were not read."
      ),
      "info"
    )
  }
  if (rels$n_dangling > 0L) {
    issues <- document_issue(
      issues, "dependencies", "read-dangling-relationships",
      if (rels$n_dangling == 1L) {
        "1 relationship names an element that is not a component of the document, so it was not read."
      } else {
        paste0(
          rels$n_dangling, " relationships name elements that are not components of the document, ",
          "so they were not read."
        )
      },
      "warning"
    )
  }
  if (length(dropped) > 0L) {
    one <- length(dropped) == 1L
    issues <- document_issue(
      issues, "component", "read-values-dropped",
      paste0(
        length(dropped), if (one) " value was" else " values were",
        " not kept because sbom's formats cannot carry ", if (one) "it" else "them", " (",
        paste(read_dropped_kinds[read_dropped_kinds %in% dropped], collapse = "; "), ")."
      ),
      "info"
    )
  }
  for (message in advisories_dropped) {
    issues <- document_issue(issues, "advisories", "read-advisories-dropped", message, "info")
  }
  if (n_controls > 0L) {
    issues <- document_issue(
      issues, "component", "read-control-characters",
      paste0(
        n_controls, if (n_controls == 1L) " value in the document" else " values in the document",
        " held control characters, which sbom replaced with spaces."
      ),
      "info"
    )
  }
  rownames(issues) <- NULL
  issues
}

# Per-format values -----------------------------------------------------------

# Refs and ecosystems -----------------------------------------------------------

# Licenses ----------------------------------------------------------------------

# Relationships -----------------------------------------------------------------

# Metadata ----------------------------------------------------------------------

# A timestamp in ISO 8601 (date, time and an optional UTC offset) as a time in
# UTC; NULL when there is none or it is not one.
read_timestamp <- function(x) {
  pattern <- paste0(
    "^([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt ]([0-9]{2}:[0-9]{2}:[0-9]{2})([.,][0-9]+)?",
    "([Zz]|[+-][0-9]{2}(:?[0-9]{2})?)?$"
  )
  if (is.na(x) || !grepl(pattern, x)) {
    return(NULL)
  }
  time <- as.POSIXct(
    paste(sub(pattern, "\\1", x), sub(pattern, "\\2", x)),
    format = "%Y-%m-%d %H:%M:%S", tz = "UTC"
  )
  if (is.na(time)) {
    return(NULL)
  }
  zone <- sub(pattern, "\\4", x)
  if (grepl("^[+-]", zone)) {
    digits <- gsub("[^0-9]", "", zone)
    minutes <- as.integer(substr(digits, 1L, 2L)) * 60L + as.integer(paste0("0", substr(digits, 3L, 4L)))
    seconds <- minutes * 60L
    # A clock time ahead of UTC (+hh:mm) is that much earlier in UTC.
    time <- if (startsWith(zone, "+")) time - seconds else time + seconds
  }
  time
}

# `creators` is what read_swid_creators() returns, for a SWID tag. The
# values are cleaned as read_clean() cleans them, and counted in `seen`.
read_metadata <- function(d, t, family, root, file, creators = NULL, seen = NULL) {
  if (is.null(seen)) {
    seen <- new.env(parent = emptyenv())
    seen$n <- 0L
  }
  doc <- t$document
  authors <- doc$authors
  person <- authors$name[authors$kind %in% "person"]
  organization <- authors$name[authors$kind %in% "organization"][1L]
  regid <- NA_character_
  if (family == "cdx" && is.na(organization)) {
    # CycloneDX 1.4 and 1.5 have no field for it, so sbom writes a property.
    props <- json_items(json_member(json_member(d$doc, "metadata"), "properties"))
    named <- json_strings(props, "name") %in% "sbom:organization"
    organization <- tables_present(json_strings(props[named], "value"))[1L]
  } else if (family == "swid") {
    person <- creators$authors
    organization <- creators$organization
    regid <- creators$regid
  }
  person <- tables_present(sub("[ \t\r\n]*\\([^()]*\\)[ \t\r\n]*$", "", person))
  person <- read_clean(person[!is.na(person)], seen)
  person <- person[!is.na(person)]
  organization <- read_clean(organization, seen)
  regid <- read_clean(regid, seen)
  tool_version <- read_clean(doc$tools$version[doc$tools$name %in% "sbom"][1L], seen)
  timestamp <- read_timestamp(doc$timestamp)
  notes <- c(
    paste0("Read from ", file, " (", read_format_name(d$format), " ", quote_value(d$version), ")."),
    read_clean(doc$notes, seen, lines = TRUE),
    if (is.null(timestamp)) {
      if (nzchar(source_date_epoch())) {
        "The document has no timestamp, so the time in SOURCE_DATE_EPOCH is used."
      } else {
        "The document has no timestamp, so the time it was read is used."
      }
    }
  )
  list(
    root = root,
    timestamp = resolve_timestamp(timestamp),
    author = if (length(person) > 0L) person else NA_character_,
    organization = organization,
    tool_version = tool_version,
    notes = notes,
    inputs = data.frame(kind = "sbom", path = d$path, stringsAsFactors = FALSE),
    regid = regid
  )
}
