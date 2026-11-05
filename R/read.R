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
# hold one, so every value keeps none (read_clean()).

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
#' A component is optional when the document says so, or when every
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
#' Some values cannot come back from every format:
#'
#' | Format    | Not read back |
#' |:----------|:--------------|
#' | All       | sbom's own ecosystems (`local`, `git`, `repository`, `r`, `base-r`), DESCRIPTION dependency fields and asserted overrides; CPE identifiers; checksums other than MD5, SHA-1, SHA-256, SHA-384, SHA-512 and SHA3; URLs that are not valid IRI references, local paths, and purl qualifiers whose value is a local path; licences of other SPDX documents (`DocumentRef-`), kept only as written |
#' | CycloneDX | licence comments and package file names; a root's maintainer may be the organization in `metadata.manufacture`, which SPDX then writes as a person |
#' | SPDX 2    | refs (SPDX ids replace them, so [sbom_diff()] matches components it identifies by ref only partly), supplier URLs, the licence as written, evidence, minimum versions, system requirements and Bioconductor releases; maintainers that are not persons; the descriptions and publication dates that sbom writes in comments; the texts of extracted licences (`hasExtractedLicensingInfos`), so a document written again says that the text is not included; whether a supplier is a person, so a `Person:` supplier is written again as an `Organization:`. SPDX 2.2 has no primary purpose, so every package is a library; SPDX 2.3 gives R the type `application`. SPDX 2.2 cannot carry SHA3 checksums, so they are left out |
#' | SPDX 3    | refs, as in SPDX 2; supplier URLs, the licence as written, licence comments, evidence, minimum versions, package file names, system requirements and Bioconductor releases; maintainers that are not persons; which component holds another; the descriptions that sbom writes in comments |
#' | SWID      | refs of code compiled into a package, which gets no link; for the root, licence expressions and comments, checksums, descriptions, publication dates, DOIs, evidence and Bioconductor releases; for the other components, everything but the name, version, purl, minimum version and whether it is optional; relationships other than the root's. A tag creator with a real regid is the organization, any other is an author, except sbom itself |
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
#' * `read-control-characters` (info): values held control characters, which
#'   were replaced with spaces.
#'
#' When the document has no timestamp, or one that is not ISO 8601, the time
#' in the `SOURCE_DATE_EPOCH` environment variable is used when it is set, and
#' otherwise the time it was read, and a note says so.
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
  fields <- switch(family,
    cdx = read_cdx_fields(el, d$doc),
    spdx2 = read_spdx2_fields(el),
    spdx3 = read_spdx3_fields(el, tables_coalesce_attr(
      t, "index", tables_spdx3_index(unname(json_items(json_member(d$doc, "@graph"))))
    )),
    swid = read_swid_fields(el, d$doc, entities)
  )
  ref_id <- if (family == "swid") read_swid_ref_ids(id, el$location, creators$regid) else id
  # A ref that is a purl is kept as the purl is, without credentials.
  ref_id <- read_purls(read_clean(ref_id, seen))$value
  unique_refs <- read_unique_refs(read_fallback_refs(ref_id, purl, doc_name, version))
  ref <- unique_refs$ref
  licenses <- read_licenses(t$licenses, el, family, fields$written)
  dropped <- c(fields$dropped, purls$dropped, rep(read_dropped_kinds[["cpe"]], n_cpe))
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
  issues <- read_issues(
    unique_refs, root_ref, length(roots), is.na(root), n_files, rels, dropped, seen$n
  )
  new_sbom(metadata, components, edges, issues)
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
# that was not kept, and `n_controls` counts the values that held control
# characters.
read_issues <- function(unique_refs, root_ref, n_roots, placeholder, n_files, rels, dropped,
                        n_controls = 0L) {
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

# A data frame of the columns `cols`, list columns included, built without
# data.frame()'s per-column work.
read_frame <- function(cols) {
  structure(cols, class = "data.frame", row.names = c(NA_integer_, -length(cols[[1L]])))
}

# The first value of `value` for each of `n` owners, among the items `keep`;
# NA for an owner with none.
read_first <- function(value, owner, n, keep) {
  out <- rep(NA_character_, n)
  keep <- keep & !is.na(value)
  hit <- owner[keep]
  first <- !duplicated(hit)
  out[hit[first]] <- value[keep][first]
  out
}

# The kinds of value that are not kept, as the read-values-dropped issue
# names them, in this order and separated by semicolons, since each but local
# paths ends in a clause that an "and" would run on into the next.
read_dropped_kinds <- c(
  iri = "URLs that are not valid IRI references", path = "local paths",
  hash = "checksums of algorithms or lengths sbom does not write",
  doi = "DOIs that cannot form a valid URL", cpe = "CPE identifiers"
)

# A file: URL or a local path: absolute, from the home folder, relative to the
# current folder or its parent, or on a Windows drive.
read_path_pattern <- "^(file:|/|\\\\|~|\\.\\.?([/\\\\]|$)|[A-Za-z]:[/\\\\])"

# URLs as sbom keeps its own (remote_vcs_url()): without credentials, query or
# fragment (strip_url()). A file: URL or a local path would leak a machine
# path, and a value that cannot be an IRI reference cannot be written where a
# format needs one, so those are dropped. Returns list(value, dropped), with
# the kind of each value dropped.
read_urls <- function(x) {
  x <- strip_url(tables_present(x))
  path <- !is.na(x) & grepl(read_path_pattern, x, ignore.case = TRUE)
  bad <- !is.na(x) & !path
  bad[bad] <- iri_reference_bad(x[bad])
  x[path | bad] <- NA_character_
  dropped <- c(rep(read_dropped_kinds[["path"]], sum(path)), rep(read_dropped_kinds[["iri"]], sum(bad)))
  list(value = x, dropped = dropped)
}

# Purls as read_sbom() keeps them, as it keeps URLs (read_urls()): a
# qualifier whose value is a URL, holding "://", loses its credentials, query
# and fragment (strip_url()), and a qualifier whose value is a file: URL or a
# local path is dropped. Values are compared percent-decoded, and a value
# that changes is written again with %, &, #, ? and spaces encoded. Each
# distinct purl is cleaned once. Returns list(value, dropped), with the kind
# of each qualifier dropped.
read_purls <- function(x) {
  has <- !is.na(x) & grepl("?", x, fixed = TRUE)
  if (!any(has)) {
    return(list(value = x, dropped = character()))
  }
  distinct <- unique(x[has])
  cleaned <- lapply(distinct, read_purl_qualifiers)
  at <- match(x[has], distinct)
  x[has] <- vapply(cleaned, `[[`, character(1), "value")[at]
  n <- vapply(cleaned, `[[`, integer(1), "dropped")[at]
  list(value = x, dropped = rep(read_dropped_kinds[["path"]], sum(n)))
}

# One purl with a `?`, cleaned as read_purls() says: list(value, dropped),
# the number of qualifiers dropped.
read_purl_qualifiers <- function(purl) {
  head <- sub("\\?.*$", "", purl)
  rest <- substring(purl, nchar(head) + 2L)
  subpath <- if (grepl("#", rest, fixed = TRUE)) sub("^[^#]*", "", rest) else ""
  qualifiers <- sub("#.*$", "", rest)
  pairs <- strsplit(qualifiers, "&", fixed = TRUE)[[1]]
  value <- sub("^[^=]*=", "", pairs)
  key <- substr(pairs, 1L, nchar(pairs) - nchar(value))
  valued <- grepl("=", pairs, fixed = TRUE)
  decoded <- value
  ok <- valued & !grepl("%(?![0-9A-Fa-f]{2})", value, perl = TRUE)
  decoded[ok] <- pct_decode(value[ok])
  decoded[!validUTF8(decoded)] <- value[!validUTF8(decoded)]
  path <- valued & grepl(read_path_pattern, decoded, ignore.case = TRUE)
  url <- valued & !path & grepl("://", decoded, fixed = TRUE)
  stripped <- strip_url(decoded)
  changed <- url & stripped != decoded
  pairs[changed] <- paste0(key[changed], read_purl_encode(stripped[changed]))
  pairs <- pairs[!path]
  value <- paste0(head, if (length(pairs) > 0L) paste0("?", paste(pairs, collapse = "&")), subpath)
  list(value = value, dropped = sum(path))
}

# Percent-encodes the characters a purl qualifier's value cannot hold as
# they are.
read_purl_encode <- function(x) {
  for (ch in c("%", "&", "#", "?", " ")) {
    x <- gsub(ch, sprintf("%%%02X", utf8ToInt(ch)), x, fixed = TRUE)
  }
  x
}

# DOIs, which the writers also give as https://doi.org/<doi>: one that cannot
# be part of an IRI reference is dropped. Returns list(value, dropped).
read_dois <- function(x) {
  x <- tables_present(x)
  bad <- !is.na(x)
  bad[bad] <- iri_reference_bad(x[bad])
  x[bad] <- NA_character_
  list(value = x, dropped = rep(read_dropped_kinds[["doi"]], sum(bad)))
}

# The date part, YYYY-MM-DD, of a date or timestamp; NA for anything else.
read_date <- function(x) {
  x <- tables_present(x)
  ifelse(grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}", x), substr(x, 1L, 10L), NA_character_)
}

# NONE and NOASSERTION are SPDX's words for no value.
read_spdx_value <- function(x) {
  x <- tables_present(x)
  x[x %in% c("NONE", "NOASSERTION")] <- NA_character_
  x
}

# One checksum table per owner, of the checksums whose algorithm every format
# takes (`alg` in CycloneDX's spelling) and whose value has that algorithm's
# number of hex digits. Returns list(value, dropped): a checksum with an
# algorithm and a value that is not kept is dropped.
read_hashes <- function(alg, content, owner, n) {
  out <- rep(list(empty_hashes()), n)
  alg <- unname(alg)
  digits <- unname(read_hash_digits[alg])
  ok <- !is.na(digits) & !is.na(content) & nchar(content) == digits & grepl("^[0-9A-Fa-f]+$", content)
  groups <- split(which(ok), owner[ok])
  out[as.integer(names(groups))] <- lapply(groups, function(i) {
    structure(
      list(alg = alg[i], content = content[i], of = rep(NA_character_, length(i))),
      class = "data.frame", row.names = c(NA_integer_, -length(i))
    )
  })
  stated <- !is.na(tables_present(alg)) & !is.na(tables_present(content))
  list(value = out, dropped = rep(read_dropped_kinds[["hash"]], sum(stated & !ok)))
}

# SPDX's primary purpose as a type. SPDX 2 spells it APPLICATION, SPDX 3
# application; only SPDX 3 has platform.
read_purpose_type <- function(purpose) {
  ifelse(purpose %in% c("APPLICATION", "application"), "application",
    ifelse(purpose %in% c("FILE", "file"), "file", ifelse(purpose %in% "platform", "platform", "library"))
  )
}

# Per-format values -----------------------------------------------------------

# Each returns, for the components `el`, the values the tables do not carry:
# supplier_url, maintainer, license_comment, written (the licence as written,
# when the format states it apart from the licences), homepage, vcs_url,
# download_location, doi, description, published, package_file_name,
# system_requirements, bioc_release, evidence and version_is (as stated),
# hashes, type, optional (whether the element itself says so), and dropped
# (the kind of each value not kept).
read_values <- function(n, ...) {
  none <- rep(NA_character_, n)
  given <- list(...)
  keys <- c(
    "supplier_url", "maintainer", "license_comment", "written", "homepage", "vcs_url",
    "download_location", "doi", "description", "published", "package_file_name",
    "system_requirements", "bioc_release", "evidence", "version_is"
  )
  out <- lapply(stats::setNames(keys, keys), function(key) {
    if (is.null(given[[key]])) none else given[[key]]
  })
  out$hashes <- if (is.null(given$hashes)) rep(list(empty_hashes()), n) else given$hashes
  out$type <- given$type
  out$optional <- if (is.null(given$optional)) rep(FALSE, n) else given$optional
  out$dropped <- if (is.null(given$dropped)) character() else given$dropped
  out
}

# The first URL of a CycloneDX organizational entity.
read_cdx_party_url <- function(party) {
  urls <- json_items(json_member(party, "url"))
  if (length(urls) > 0L) json_string(urls[[1L]]) else NA_character_
}

read_cdx_fields <- function(el, doc) {
  raw <- el$raw
  n <- length(raw)
  meta <- json_member(doc, "metadata")
  props <- json_flatten(raw, "properties")
  prop_name <- json_strings(props$items, "name")
  prop_value <- tables_present(json_strings(props$items, "value"))
  prop <- function(key) read_first(prop_value, props$owner, n, prop_name %in% key)
  refs <- json_flatten(raw, "externalReferences")
  ref_type <- json_strings(refs$items, "type")
  read_types <- c(homepage = "website", vcs_url = "vcs", download_location = "distribution")
  ref_url <- read_urls(ifelse(ref_type %in% read_types, json_strings(refs$items, "url"), NA_character_))
  external <- function(type) read_first(ref_url$value, refs$owner, n, ref_type %in% type)
  doi <- read_dois(prop("sbom:doi"))
  hashes <- json_flatten(raw, "hashes")
  hashes <- read_hashes(
    json_strings(hashes$items, "alg"), json_strings(hashes$items, "content"), hashes$owner, n
  )

  # The root takes the metadata's supplier and manufacturer when it names
  # neither itself, as the tables' supplier does.
  supplier_url <- vapply(raw, function(x) read_cdx_party_url(json_member(x, "supplier")), character(1))
  own <- !is.na(tables_present(json_strings(raw, c("supplier", "name"))))
  for_root <- el$is_root & !own
  supplier_url[for_root] <- read_cdx_party_url(json_member(meta, "supplier"))
  supplier_url <- read_urls(supplier_url)
  maintainer <- tables_coalesce(tables_present(json_strings(raw, "publisher")), prop("sbom:maintainer"))
  manufacture <- tables_present(json_string(json_member(json_member(meta, "manufacture"), "name")))
  maintainer[el$is_root] <- tables_coalesce(maintainer[el$is_root], manufacture)

  read_values(n,
    supplier_url = supplier_url$value, maintainer = maintainer,
    written = prop("sbom:license-as-written"), homepage = external("website"),
    vcs_url = external("vcs"), download_location = external("distribution"),
    doi = doi$value, description = tables_present(json_strings(raw, "description")),
    published = prop("sbom:published"), system_requirements = prop("sbom:system-requirements"),
    bioc_release = prop("sbom:bioconductor-release"), evidence = prop("sbom:evidence"),
    version_is = prop("sbom:version-is"), hashes = hashes$value,
    type = ifelse(el$type %in% c("application", "library", "platform", "file"), el$type, "library"),
    optional = el$scope %in% c("optional", "excluded"),
    dropped = c(supplier_url$dropped, ref_url$dropped, doi$dropped, hashes$dropped)
  )
}

read_spdx2_fields <- function(el) {
  raw <- el$raw
  n <- length(raw)
  originator <- tables_present(json_strings(raw, "originator"))
  person <- !is.na(originator) & grepl("^Person:", originator)
  refs <- json_flatten(raw, "externalRefs")
  other <- json_strings(refs$items, "referenceCategory") %in% "OTHER"
  ref_type <- json_strings(refs$items, "referenceType")
  locator <- tables_present(json_strings(refs$items, "referenceLocator"))
  vcs <- read_urls(ifelse(other & ref_type %in% "vcs", locator, NA_character_))
  doi <- read_dois(ifelse(other & ref_type %in% "doi", locator, NA_character_))
  homepage <- read_urls(read_spdx_value(json_strings(raw, "homepage")))
  download <- read_urls(read_spdx_value(json_strings(raw, "downloadLocation")))
  checksums <- json_flatten(raw, "checksums")
  alg <- json_strings(checksums$items, "algorithm")
  # The writer's inverse: SHA256 is SHA-256.
  alg <- ifelse(grepl("^SHA(1|256|384|512)$", alg), sub("^SHA", "SHA-", alg), alg)
  hashes <- read_hashes(alg, json_strings(checksums$items, "checksumValue"), checksums$owner, n)

  read_values(n,
    maintainer = ifelse(person, tables_present(sub("^Person:[ \t\r\n]*", "", originator)), NA_character_),
    license_comment = tables_present(json_strings(raw, "licenseComments")),
    homepage = homepage$value,
    vcs_url = read_first(vcs$value, refs$owner, n, rep(TRUE, length(vcs$value))),
    download_location = download$value,
    doi = read_first(doi$value, refs$owner, n, rep(TRUE, length(doi$value))),
    description = tables_present(json_strings(raw, "description")),
    published = read_date(json_strings(raw, "releaseDate")),
    package_file_name = tables_present(json_strings(raw, "packageFileName")),
    hashes = hashes$value, type = read_purpose_type(el$type),
    dropped = c(homepage$dropped, vcs$dropped, download$dropped, doi$dropped, hashes$dropped)
  )
}

# `ix` is the graph's index, tables_spdx3_index().
read_spdx3_fields <- function(el, ix) {
  raw <- el$raw
  n <- length(raw)
  originators <- json_flatten(raw, "originatedBy")
  agents <- tables_spdx3_agents(originators$items, ix)
  refs <- json_flatten(raw, "externalRef")
  locator <- vapply(refs$items, function(x) {
    locators <- json_items(json_member(x, "locator"))
    if (length(locators) > 0L) json_string(locators[[1L]]) else NA_character_
  }, character(1))
  vcs <- read_urls(ifelse(json_strings(refs$items, "externalRefType") %in% "vcs", locator, NA_character_))
  ids <- json_flatten(raw, "externalIdentifier")
  doi <- read_dois(ifelse(
    json_strings(ids$items, "comment") %in% "DOI", json_strings(ids$items, "identifier"), NA_character_
  ))
  homepage <- read_urls(json_strings(raw, "software_homePage"))
  download <- read_urls(json_strings(raw, "software_downloadLocation"))
  hashes <- json_flatten(raw, "verifiedUsing")
  algorithm <- json_strings(hashes$items, "algorithm")
  # The writer's inverse; any other algorithm is kept as written, to be
  # counted as dropped.
  alg <- unname(read_spdx3_hashes[algorithm])
  alg[is.na(alg)] <- algorithm[is.na(alg)]
  hashes <- read_hashes(alg, json_strings(hashes$items, "hashValue"), hashes$owner, n)

  read_values(n,
    maintainer = read_first(agents$name, originators$owner, n, agents$type %in% "Person"),
    homepage = homepage$value,
    vcs_url = read_first(vcs$value, refs$owner, n, rep(TRUE, length(vcs$value))),
    download_location = download$value,
    doi = read_first(doi$value, ids$owner, n, rep(TRUE, length(doi$value))),
    description = tables_present(json_strings(raw, "description")),
    published = read_date(json_strings(raw, "releaseTime")),
    hashes = hashes$value, type = read_purpose_type(el$type),
    dropped = c(homepage$dropped, vcs$dropped, download$dropped, doi$dropped, hashes$dropped)
  )
}

# `ent` is what tables_swid_entities() gives.
read_swid_fields <- function(el, doc, ent) {
  n <- nrow(el)
  root <- el$location == "/tag"
  links <- json_items(json_member(doc, "links"))
  meta <- json_items(json_member(doc, "meta"))
  entity_names <- ent$name
  # The first entity with the role and a name.
  entity <- function(role) {
    which(ent$has_role(role) & !is.na(entity_names))[1L]
  }
  distributor <- entity("distributor")
  supplier_url <- read_urls(ent$regid[distributor])
  rel <- tables_swid_values(links, "rel")
  pages <- rel %in% c("describedby", "related", "installationmedia")
  href <- read_urls(ifelse(pages, tables_swid_values(links, "href"), NA_character_))
  link <- function(type) href$value[rel %in% type & !is.na(href$value)][1L]
  media <- which(rel %in% "installationmedia")[1L]
  meta_value <- function(key) {
    values <- tables_present(tables_swid_values(meta, key))
    values[!is.na(values)][1L]
  }
  # The tag describes only its root.
  on_root <- function(value) ifelse(root, value, NA_character_)

  read_values(n,
    supplier_url = on_root(supplier_url$value),
    maintainer = on_root(entity_names[entity("maintainer")]),
    homepage = on_root(link("describedby")), vcs_url = on_root(link("related")),
    download_location = on_root(link("installationmedia")),
    package_file_name = on_root(if (is.na(media)) NA_character_ else {
      tables_present(tables_swid_value(links[[media]], "artifact"))
    }),
    system_requirements = on_root(meta_value("sbom:systemRequirements")),
    version_is = tables_present(tables_swid_values(el$raw, "sbom:versionIs")),
    type = ifelse(root, "application", "library"),
    optional = el$scope %in% "optional",
    dropped = c(supplier_url$dropped, href$dropped)
  )
}

# What the SWID tag creators say: the regid of the first one with a real
# regid, the organization it names, and the authors. A tag creator with the
# placeholder regid http://invalid.unavailable (the default when it has none)
# is an author, unless it is sbom itself, the tool. `ent` is what
# tables_swid_entities() gives.
read_swid_creators <- function(ent) {
  creator <- ent$has_role("tagCreator")
  name <- ent$name[creator]
  regid <- ent$regid[creator]
  real <- !is.na(regid) & regid != swid_placeholder_regid
  organization <- which(real & !is.na(name))[1L]
  list(
    regid = regid[real][1L],
    organization = name[organization],
    authors = name[!real & !is.na(name) & name != "sbom"]
  )
}

# The refs of a SWID tag's elements, without what the writer adds: the
# authority of the tag creator's regid before the root's tagId, and swid: and
# that authority before each link's href.
read_swid_ref_ids <- function(id, location, regid) {
  authority <- swid_authority(regid)
  link <- location != "/tag" & !is.na(id)
  id[link] <- sub("^swid:", "", id[link])
  if (!is.na(authority)) {
    prefix <- paste0(authority, "/")
    strip <- !is.na(id) & startsWith(id, prefix) & nchar(id) > nchar(prefix)
    id[strip] <- substring(id[strip], nchar(prefix) + 1L)
  }
  id
}

# The attribute `which` of the tables `t`, or `default` when they lack it,
# as tables built by hand may.
tables_coalesce_attr <- function(t, which, default) {
  value <- attr(t, which, exact = TRUE)
  if (is.null(value)) default else value
}

# Refs and ecosystems -----------------------------------------------------------

# Each element's id, or its purl, then name@version, then component-<n>.
read_fallback_refs <- function(id, purl, name, version) {
  name_version <- ifelse(is.na(name) | is.na(version), NA_character_, paste0(name, "@", version))
  tables_coalesce(id, purl, name_version, paste0("component-", seq_along(id)))
}

# Refs made unique: the first element with a ref keeps it, and the later ones
# get the suffixes after the highest -<k> already taken, so -2, -3 and so on
# when none is. Also, for each ref that was shared, in radix order, the
# number of elements that shared it and the refs the later ones got (at most
# 20 named).
read_unique_refs <- function(ref) {
  first <- !duplicated(ref)
  if (all(first)) {
    return(list(ref = ref, id = character(), count = integer(), renamed = character()))
  }
  later <- which(!first)
  shared <- ref[later]
  # The highest suffix each shared ref already has among all refs.
  pattern <- "^(.*)-([0-9]{1,9})$"
  suffixed <- grepl(pattern, ref)
  stem <- sub(pattern, "\\1", ref[suffixed])
  number <- as.integer(sub(pattern, "\\2", ref[suffixed]))
  hit <- stem %in% shared
  start <- rep(1L, length(later))
  if (any(hit)) {
    highest <- tapply(number[hit], stem[hit], max)
    at <- match(shared, names(highest))
    start[!is.na(at)] <- highest[at[!is.na(at)]]
  }
  o <- order(shared, later, method = "radix")
  rank <- integer(length(later))
  rank[o] <- sequence(rle(shared[o])$lengths)
  out <- ref
  k <- start + rank
  repeat {
    # A suffix can clash only with a ref of more than nine digits.
    out[later] <- paste0(shared, "-", k)
    clash <- out[later] %in% out[first] | duplicated(out[later])
    if (!any(clash)) break
    k[clash] <- k[clash] + length(later)
  }
  groups <- split(out[later], factor(shared, levels = sort(unique(shared), method = "radix")))
  list(
    ref = out, id = names(groups), count = lengths(groups) + 1L,
    renamed = vapply(groups, function(g) read_list(quote_value(g)), character(1), USE.NAMES = FALSE)
  )
}

# The ecosystem of each purl: its type, in lower case, except that a cran purl
# whose repository_url names bioconductor.org is "bioconductor". A component
# without a valid purl is "unknown". Each distinct purl is parsed once.
read_ecosystem <- function(purl) {
  out <- rep("unknown", length(purl))
  has <- !is.na(purl)
  if (!any(has)) {
    return(out)
  }
  distinct <- unique(purl[has])
  parsed <- purl_parse(distinct)
  type <- tolower(parsed$type)
  bioc <- vapply(parsed$qualifiers, function(q) {
    if (is.na(q)) {
      return(FALSE)
    }
    pairs <- strsplit(q, "&", fixed = TRUE)[[1]]
    key <- tolower(sub("=.*$", "", pairs))
    value <- sub("^[^=]*=", "", pairs)
    any(key == "repository_url" & grepl("bioconductor.org", value, fixed = TRUE, useBytes = TRUE))
  }, logical(1), USE.NAMES = FALSE)
  type[type %in% "cran" & bioc] <- "bioconductor"
  type[is.na(type)] <- "unknown"
  out[has] <- type[match(purl[has], distinct)]
  out
}

# Licences ----------------------------------------------------------------------

# license_spdx and license_as_written for the components `el`, from the
# licence rows of the field each format declares licences in. One valid
# expression is license_spdx. The licence as written is what the format
# states apart (`written`), or else free text, an expression that does not
# parse, several licences joined with ", ", or, in CycloneDX, whose writer
# leaves out the licence as written when it is the expression, that one
# expression. Each distinct expression is checked once.
read_licenses <- function(licenses, el, family, written) {
  n <- nrow(el)
  field <- switch(family,
    cdx = "licenses", spdx2 = "licenseDeclared", spdx3 = "hasDeclaredLicense", swid = "license"
  )
  keep <- licenses$field == field & !is.na(tables_present(licenses$expression))
  licenses <- licenses[keep, , drop = FALSE]
  owner <- switch(family,
    cdx = match(sub("^(.*)/licenses/[0-9]+/.*$", "\\1", licenses$location), el$location),
    spdx2 = match(sub("/licenseDeclared$", "", licenses$location), el$location),
    spdx3 = match(licenses$id, el$id, incomparables = NA),
    swid = rep(match("/tag", el$location), nrow(licenses))
  )
  expression <- licenses$expression[!is.na(owner)]
  kind <- licenses$kind[!is.na(owner)]
  owner <- owner[!is.na(owner)]
  single <- tabulate(owner, n)[owner] == 1L
  valid <- kind == "expression" & license_expression_check(expression, special = FALSE)$valid
  # A licence of another SPDX document needs that document's reference, which
  # is not kept, so it is kept as written only.
  other_document <- grepl("DocumentRef-", expression, fixed = TRUE)
  spdx <- rep(NA_character_, n)
  as_written <- rep(NA_character_, n)
  if (family != "swid") {
    keep <- single & valid & !other_document
    spdx[owner[keep]] <- expression[keep]
  }
  if (family %in% c("spdx2", "spdx3")) {
    as_written[owner[single & other_document]] <- expression[single & other_document]
  } else {
    stated <- single & (family == "cdx" | !valid)
    as_written[owner[stated]] <- expression[stated]
    joined <- vapply(split(expression[!single], owner[!single]), paste, character(1), collapse = ", ")
    as_written[as.integer(names(joined))] <- joined
    as_written <- tables_coalesce(written, as_written)
  }
  list(spdx = spdx, as_written = as_written)
}

# Relationships -----------------------------------------------------------------

# The comment of each relationship row at `location`: SPDX 2's on the
# relationship, SPDX 3's on the relationship node. NA elsewhere.
read_relationship_comments <- function(location, family, doc) {
  out <- rep(NA_character_, length(location))
  pattern <- switch(family, spdx2 = "^/relationships/([0-9]+)$", spdx3 = "^/@graph/([0-9]+)/to/[0-9]+$")
  if (is.null(pattern)) {
    return(out)
  }
  items <- json_items(json_member(doc, if (family == "spdx2") "relationships" else "@graph"))
  hit <- grepl(pattern, location)
  at <- as.integer(sub(pattern, "\\1", location[hit])) + 1L
  out[hit] <- json_strings(items[at], "comment")
  out
}

# The fields the SPDX writers state in a dependency's comment as
# "<Field>: <spec>" (relationship_comment()), each with the field it reads
# back as: those of DESCRIPTION and renv.lock, and SystemRequirements.
read_comment_fields <- c(
  Depends = "Depends", Imports = "Imports", LinkingTo = "LinkingTo",
  Requirements = "Requirements", SystemRequirements = "system_requirement"
)

# The field and spec of each relationship of type `type`, and whether its
# ends are swapped so that `from` is the dependent. A field of NA is a type
# sbom does not model.
read_relationship_fields <- function(type, comment, family) {
  n <- length(type)
  field <- rep(NA_character_, n)
  spec <- rep(NA_character_, n)
  swap <- rep(FALSE, n)
  if (family == "cdx") {
    field[type == "dependsOn"] <- "depends_on"
    field[type == "contains"] <- "contains"
  } else if (family == "swid") {
    field[] <- "depends_on"
  } else {
    pattern <- "^([A-Za-z]+): (.*)$"
    stated <- !is.na(comment) & grepl(pattern, comment)
    stated_field <- ifelse(stated, sub(pattern, "\\1", comment), NA_character_)
    stated_spec <- ifelse(stated, tables_present(sub(pattern, "\\2", comment)), NA_character_)
    s3 <- family == "spdx3"
    depends <- type %in% if (s3) "dependsOn" else "DEPENDS_ON"
    written <- depends & stated_field %in% names(read_comment_fields)
    field[depends] <- "depends_on"
    field[written] <- read_comment_fields[stated_field[written]]
    spec[written] <- stated_spec[written]
    field[type %in% if (s3) "contains" else "CONTAINS"] <- "contains"
    field[type %in% if (s3) "hasDynamicLink" else "DYNAMIC_LINK"] <- "dynamic_link"
    optional <- type %in% if (s3) "hasOptionalDependency" else "OPTIONAL_DEPENDENCY_OF"
    suggests <- optional & stated_field %in% "Suggests"
    field[optional] <- "optional"
    field[suggests] <- "Suggests"
    spec[suggests] <- stated_spec[suggests]
    if (s3) {
      field[type %in% "hasProvidedDependency"] <- "provided_dependency_of"
    } else {
      # SPDX 2 states these from the dependency to the dependent.
      other <- !optional & grepl("^([A-Z]+_)?DEPENDENCY_OF$", type)
      field[other] <- tolower(type[other])
      swap <- optional | other
    }
  }
  list(field = unname(field), spec = spec, swap = swap)
}

# Whether each id is one the document defines, one of another document's
# elements, or SPDX 2's NONE or NOASSERTION.
read_known_ids <- function(x, document, family) {
  known <- x %in% document$ids
  if (family == "spdx2") {
    external <- grepl(":", x, fixed = TRUE) & sub(":.*$", "", x) %in% document$external_ids
    known <- known | x %in% c("NONE", "NOASSERTION") | external
  } else if (family == "spdx3") {
    known <- known | x %in% document$external_ids
  }
  known
}

# The relationships between components, the components the document states
# the dependencies of without an edge (CycloneDX's dependencies entries,
# SPDX 2's DEPENDS_ON NONE), and the counts of relationships skipped for
# their type and of those that name elements the document lacks.
read_relationships <- function(t, doc, family, id, ref) {
  rel <- t$relationships
  ref_of <- function(x) ref[match(x, id, incomparables = NA)]
  stated <- switch(family,
    cdx = ref_of(rel$from[rel$type != "contains"]),
    spdx2 = ref_of(rel$from[rel$type %in% "DEPENDS_ON" & rel$to %in% "NONE"])
  )
  rel <- rel[!is.na(rel$to), , drop = FALSE]
  m <- read_relationship_fields(rel$type, read_relationship_comments(rel$location, family, doc), family)
  from_id <- rel$from
  to_id <- rel$to
  from_id[m$swap] <- rel$to[m$swap]
  to_id[m$swap] <- rel$from[m$swap]
  from <- ref_of(from_id)
  to <- ref_of(to_id)
  known_from <- is.na(from) & read_known_ids(from_id, t$document, family)
  known_to <- is.na(to) & read_known_ids(to_id, t$document, family)
  modelled <- !is.na(m$field)
  edge <- modelled & !is.na(from) & !is.na(to)
  # A relationship that names an element which is not a component but which
  # the document defines (the document itself, a file, an agent) is left out
  # without an issue.
  dangling <- modelled & ((is.na(from) & !known_from) | (is.na(to) & !known_to))
  skipped <- !modelled & !known_from & !known_to
  out <- data.frame(
    from = from[edge], to = to[edge], field = m$field[edge], spec = m$spec[edge],
    evidence = rep("declared", sum(edge)), stringsAsFactors = FALSE
  )
  out <- out[!duplicated(out[c("from", "to", "field")]), , drop = FALSE]
  out <- out[order(out$from, out$to, out$field, method = "radix"), , drop = FALSE]
  rownames(out) <- NULL
  list(
    relationships = out, stated = stated, n_skipped = sum(skipped),
    skipped_types = sort(unique(rel$type[skipped]), method = "radix"), n_dangling = sum(dangling)
  )
}

# The parent of each component that exactly one contains relationship names
# as its target: the source of that relationship.
read_single_parent <- function(rels, ref) {
  contains <- rels[rels$field == "contains", , drop = FALSE]
  single <- !contains$to %in% contains$to[duplicated(contains$to)]
  out <- rep(NA_character_, length(ref))
  out[match(contains$to[single], ref)] <- contains$from[single]
  out
}

# Parents with every cycle broken: a component whose chain of parents never
# ends, because it is in a cycle or below one, gets none. Each step doubles
# the distance of the ancestor looked at, so the work is n log n.
read_acyclic_parents <- function(parent_ref, ref) {
  ancestor <- match(parent_ref, ref)
  for (i in seq_len(ceiling(log2(length(ref) + 1L)))) {
    ancestor <- ancestor[ancestor]
  }
  parent_ref[!is.na(ancestor)] <- NA_character_
  parent_ref
}

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
