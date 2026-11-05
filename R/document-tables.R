# Neutral tables of any SBOM's raw model. document_tables() turns what
# read_document() returns, in any of the four families, into elements,
# licences, purls, relationships and document facts, each row carrying the
# JSON pointer (RFC 6901, 0-based) of the value it came from. read_sbom() maps
# them to an <sbom>, and the content checks run on them.
#
# The models come from files of any origin, so no value is trusted: a field of
# the wrong JSON type reads as absent, and an array item that is not an object
# is skipped, never an error. Fields are read with `[[`, never `$`, which
# matches names partially. A party or a note that is empty is absent. Spaces
# are matched as [ \t\r\n], never [[:space:]], whose meaning depends on the
# locale. Each column is built once over all elements, so that a document of
# tens of thousands of components takes seconds; the raw column holds the
# elements' own lists, which R shares rather than copies.

# JSON values ---------------------------------------------------------------

# paste0(), but of length zero when any argument is: paste0() alone turns
# paste0("/x/", integer()) into "/x/".
tables_paste <- function(...) paste0(..., recycle0 = TRUE)

# The JSON pointer of member `key` of the value at `pointer`, and of item
# `index` (0-based) of that member when `index` is given. Vectorised. A key
# escapes "~" as "~0" and "/" as "~1".
json_pointer <- function(pointer, key, index = NULL) {
  key <- gsub("/", "~1", gsub("~", "~0", key, fixed = TRUE), fixed = TRUE)
  out <- tables_paste(pointer, "/", key)
  if (is.null(index)) out else tables_paste(out, "/", index)
}

# Whether `x` is a JSON object: a named list (`{}` is an empty named list). In
# the JSON and YAML models an empty unnamed list is the array `[]`, which is
# not an object. The CycloneDX XML model gives an empty unnamed list for an
# empty element such as <component/>, which is one: `empty = TRUE` there.
json_is_object <- function(x, empty = FALSE) {
  is.list(x) && (!is.null(names(x)) || (empty && length(x) == 0L))
}

# Member `key` of an object; NULL for anything else.
json_member <- function(x, key) {
  if (is.list(x) && !is.null(names(x))) x[[key]]
}

# The items of an array; none for anything else.
json_items <- function(x) {
  if (is.list(x) && is.null(names(x))) x else list()
}

json_string <- function(x) {
  if (is_string(x)) x else NA_character_
}

# The string at the path of keys `path` in each of `items`, NA where there is
# none.
json_strings <- function(items, path) {
  vapply(items, function(x) {
    for (key in path) x <- json_member(x, key)
    json_string(x)
  }, character(1), USE.NAMES = FALSE)
}

# The items of the array at `key` in each of `items`, as one list, with the
# position in `items` each came from (`owner`) and its 0-based index in its
# array.
json_flatten <- function(items, key) {
  arrays <- lapply(items, function(x) json_items(json_member(x, key)))
  n <- lengths(arrays)
  list(
    items = if (sum(n) == 0L) list() else do.call(c, unname(arrays)),
    owner = rep.int(seq_along(arrays), n),
    index = sequence(n) - 1L
  )
}

# Every string under the key `key` anywhere in `x`, in document order. Keys
# are unique within an object: read_document() refuses repeated ones. `[[`
# gives NULL for a key an object lacks, and for any key of an array.
json_key_strings <- function(x, key) {
  walk <- function(x) {
    value <- x[[key]]
    own <- if (is.character(value) && length(value) == 1L && !is.na(value)) value
    lists <- vapply(x, is.list, NA, USE.NAMES = FALSE)
    if (!any(lists)) {
      return(own)
    }
    c(list(own), lapply(.subset(x, lists), walk))
  }
  out <- if (is.list(x)) unlist(walk(x), use.names = FALSE)
  if (is.null(out)) character() else out
}

# The first value that is not NA, element by element. A shorter fallback is
# recycled.
tables_coalesce <- function(...) {
  values <- list(...)
  out <- values[[1L]]
  for (x in values[-1L]) {
    na <- is.na(out)
    out[na] <- rep_len(x, length(out))[na]
  }
  out
}

# A value that is empty, or only spaces, is absent.
tables_present <- function(x) {
  x[!is.na(x) & !nzchar(trimws(x))] <- NA_character_
  x
}

# The values of `value` grouped by `owner`, an index into n elements: one
# character vector per element, in order of appearance.
tables_group <- function(value, owner, n) {
  unname(split(as.character(value), factor(owner, levels = seq_len(n))))
}

# Concatenates the column `col` of each of the lists `parts`: vectors of the
# type of `empty`, or lists, which are joined, not flattened, when `empty` is
# a list.
tables_column <- function(parts, col, empty = character()) {
  values <- lapply(parts, function(p) p[[col]])
  out <- if (is.list(empty)) do.call(c, unname(values)) else unlist(values, use.names = FALSE)
  if (is.null(out)) empty else out
}

# Binds the lists `parts`, each a set of columns of one length, into the
# character columns `cols`, with the rows ordered by the integer columns `by`.
tables_bind <- function(parts, by, cols) {
  keys <- lapply(by, function(b) tables_column(parts, b, integer()))
  o <- do.call(order, c(keys, list(method = "radix")))
  lapply(stats::setNames(cols, cols), function(col) tables_column(parts, col)[o])
}

# Splits a tool's text into name and version: the version starts at the first
# hyphen followed by a digit (`sep = "-"`, SPDX 2's "Tool: name-1.0"), or is
# the last word when it starts with a digit (`sep = " "`, as in "sbom 1.0").
tables_tool <- function(text, sep) {
  text <- text[!is.na(tables_present(text))]
  pattern <- if (sep == "-") "^(.+?)-([0-9].*)$" else "^(.+?)[ \t\r\n]+([0-9][^ \t\r\n]*)$"
  hit <- grepl(pattern, text, perl = TRUE)
  name <- ifelse(hit, sub(pattern, "\\1", text, perl = TRUE), text)
  version <- ifelse(hit, sub(pattern, "\\2", text, perl = TRUE), NA_character_)
  tables_strings(name = name, version = version)
}

# Table constructors ----------------------------------------------------------

tables_frame <- function(...) {
  cols <- list(...)
  n <- length(cols[[1L]])
  rows <- if (n > 0L) c(NA_integer_, -n) else integer()
  structure(cols, class = "data.frame", row.names = rows)
}

# A data frame of character columns.
tables_strings <- function(...) {
  do.call(tables_frame, lapply(list(...), as.character))
}

tables_elements <- function(location, id, kind, name, version, supplier, originator, purl,
                            identifiers, type, scope, is_root, parent, raw) {
  chr <- as.character
  tables_frame(
    location = chr(location), id = chr(id), kind = chr(kind), name = chr(name),
    version = chr(version), supplier = chr(supplier), originator = chr(originator),
    purl = chr(purl), identifiers = unname(as.list(identifiers)), type = chr(type),
    scope = chr(scope), is_root = as.logical(is_root), parent = chr(parent),
    raw = unname(as.list(raw))
  )
}

# `field` is where the licence came from: the SPDX 2 key, the SPDX 3
# relationship type, "licenses" for CycloneDX and "license" for SWID.
tables_licenses <- function(location = character(), id = character(), expression = character(),
                            kind = rep("expression", length(location)), field = character()) {
  tables_strings(location = location, id = id, expression = expression, kind = kind, field = field)
}

tables_purls <- function(location = character(), id = character(), purl = character()) {
  tables_strings(location = location, id = id, purl = purl)
}

tables_relationships <- function(location = character(), from = character(), to = character(),
                                 type = character()) {
  tables_strings(location = location, from = from, to = to, type = type)
}

# Only authors with a name are listed.
tables_authors <- function(name = character(), kind = character(), location = character()) {
  keep <- !is.na(tables_present(name))
  tables_strings(name = name[keep], kind = kind[keep], location = location[keep])
}

tables_document <- function(name = NA_character_, timestamp = NA_character_,
                            timestamp_location = NA_character_, authors = tables_authors(),
                            tools = tables_tool(character(), "-"), root = character(),
                            root_location = character(), notes = character(),
                            defined_refs = character(), external_ids = character(),
                            ids = character()) {
  if (is.na(timestamp)) timestamp_location <- NA_character_
  tools <- tools[!is.na(tables_present(tools$name)), , drop = FALSE]
  known <- function(x) unique(x[!is.na(x)])
  list(
    name = name, timestamp = timestamp, timestamp_location = timestamp_location,
    authors = authors, tools = tools, root = as.character(root),
    root_location = as.character(root_location), notes = notes[!is.na(tables_present(notes))],
    defined_refs = defined_refs[!is.na(defined_refs)], external_ids = known(external_ids),
    ids = known(ids)
  )
}

#' Turn a raw SBOM model into neutral tables
#'
#' One extractor per family (CycloneDX, SPDX 2, SPDX 3, SWID) reads the model
#' `read_document()` returned. Every row's `location` is a JSON pointer into
#' that model. Values that are not a single string read as NA.
#'
#' @param d What `read_document()` returns.
#' @return A list:
#'   * `elements`: `data.frame(location, id, kind, name, version, supplier,
#'     originator, purl, identifiers, type, scope, is_root, parent, raw)`.
#'     `kind` is `"component"`, `"file"` or `"snippet"`; `identifiers` is a
#'     list of character vectors (`"purl:<x>"`, `"cpe:<x>"`, `"swid:<x>"`);
#'     `type` and `scope` are the format's own words (SWID's link `use` is
#'     its scope); `parent` is the id of the nesting parent (CycloneDX only);
#'     `raw` is each element's own list (a named character vector for SWID).
#'   * `licenses`: `data.frame(location, id, expression, kind, field)`, `kind` being
#'     `"expression"` or `"name"` (free text), and `field` where it came from:
#'     the SPDX 2 key (`licenseDeclared` and so on), the SPDX 3 relationship
#'     type (`hasDeclaredLicense` or `hasConcludedLicense`), `"licenses"` for
#'     CycloneDX, or `"license"` for SWID's `sbom:license`.
#'   * `purls`: `data.frame(location, id, purl)`, one row per purl.
#'   * `relationships`: `data.frame(location, from, to, type)`, with the
#'     format's own types. `from` is always an id. `to` is NA only in the row
#'     a CycloneDX `dependencies` entry that lists no dependency gives, which
#'     records that its component's dependencies were stated. SPDX 3 licence
#'     relationships are licence rows instead.
#'   * `document`: `list(name, timestamp, timestamp_location, authors, tools,
#'     root, root_location, notes, defined_refs, external_ids)`. `authors` is
#'     `data.frame(name, kind, location)`, with only named authors; `tools`
#'     is `data.frame(name, version)`. `root` holds the root ids the document
#'     states, NA for a root without one, and `root_location` where each is
#'     stated. `ids` is every id the document defines: every CycloneDX
#'     bom-ref (services' and licences' too), SPDX 2's document id and its
#'     elements' SPDXIDs, every SPDX 3 node's spdxId, or the SWID tagId.
#' @noRd
document_tables <- function(d) {
  doc <- d[["doc"]]
  switch(d[["format"]],
    `cyclonedx-json` = tables_cdx(doc, xml = FALSE),
    `cyclonedx-xml` = tables_cdx(doc, xml = TRUE),
    `spdx-json` = , `spdx-yaml` = , `spdx-xml` = , `spdx-tv` = tables_spdx2(doc),
    `spdx3-jsonld` = tables_spdx3(doc),
    swid = tables_swid(doc),
    cli::cli_abort("{.arg d} must be what {.fn read_document} returns.", .internal = TRUE)
  )
}

# CycloneDX -------------------------------------------------------------------

# The components in the array `items` at pointer `at`, nested in the component
# whose id is `parent`, and every component nested in them, depth-first: a
# list of chunks, each list(raw, location, parent). `empty` says whether an
# empty unnamed list is an object (the XML model) or the array [] (JSON).
tables_cdx_walk <- function(items, at, parent, empty) {
  keep <- vapply(items, json_is_object, logical(1), empty = empty)
  items <- unname(items[keep])
  chunk <- list(
    raw = items, location = tables_paste(at, "/", which(keep) - 1L),
    parent = rep(parent, length(items))
  )
  kids <- lapply(items, function(x) json_items(json_member(x, "components")))
  nested <- which(lengths(kids) > 0L)
  if (length(nested) == 0L) {
    return(list(chunk))
  }
  ids <- json_strings(items[nested], "bom-ref")
  slice <- function(idx) lapply(chunk, function(col) col[idx])
  # Each component with nested ones is followed by them.
  pieces <- vector("list", 2L * length(nested) + 1L)
  start <- 1L
  for (k in seq_along(nested)) {
    i <- nested[k]
    pieces[[2L * k - 1L]] <- list(slice(start:i))
    at_kids <- json_pointer(chunk$location[i], "components")
    pieces[[2L * k]] <- tables_cdx_walk(kids[[i]], at_kids, ids[k], empty)
    start <- i + 1L
  }
  if (start <= length(items)) pieces[[length(pieces)]] <- list(slice(start:length(items)))
  do.call(c, pieces)
}

# `xml` says whether `doc` is the model of CycloneDX XML.
tables_cdx <- function(doc, xml) {
  meta <- json_member(doc, "metadata")
  root <- json_member(meta, "component")
  has_root <- json_is_object(root, empty = xml)
  components <- json_items(json_member(doc, "components"))
  chunks <- tables_cdx_walk(components, "/components", NA_character_, xml)
  if (has_root) {
    root_id <- json_string(json_member(root, "bom-ref"))
    inner <- json_items(json_member(root, "components"))
    chunks <- c(
      list(list(raw = list(root), location = "/metadata/component", parent = NA_character_)),
      tables_cdx_walk(inner, "/metadata/component/components", root_id, xml),
      chunks
    )
  }
  raw <- tables_column(chunks, "raw", list())
  location <- tables_column(chunks, "location")
  parent <- tables_column(chunks, "parent")
  n <- length(raw)
  id <- json_strings(raw, "bom-ref")
  purl <- json_strings(raw, "purl")
  is_root <- location == "/metadata/component"
  party <- function(path) tables_present(json_strings(raw, path))
  first_author <- lapply(raw, function(x) {
    authors <- json_items(json_member(x, "authors"))
    if (length(authors) > 0L) authors[[1L]]
  })
  # The metadata's supplier and manufacture (CycloneDX 1.2 to 1.6) are those
  # of the component the BOM describes, when it names none itself.
  for_root <- function(key) {
    ifelse(is_root, tables_present(json_strings(list(meta), c(key, "name"))), NA_character_)
  }
  supplier <- tables_coalesce(party(c("supplier", "name")), for_root("supplier"))
  originator <- tables_coalesce(
    party(c("manufacturer", "name")), party("publisher"),
    tables_present(json_strings(first_author, "name")),
    party("author"), for_root("manufacture")
  )
  cpe <- json_strings(raw, "cpe")
  swid <- json_strings(raw, c("swid", "tagId"))
  ident <- c(tables_paste("purl:", purl), tables_paste("cpe:", cpe), tables_paste("swid:", swid))
  ident_owner <- rep.int(seq_len(n), 3L)
  has <- !is.na(c(purl, cpe, swid))
  elements <- tables_elements(
    location = location, id = id, kind = rep("component", n),
    name = json_strings(raw, "name"), version = json_strings(raw, "version"),
    supplier = supplier, originator = originator, purl = purl,
    identifiers = tables_group(ident[has], ident_owner[has], n),
    type = json_strings(raw, "type"), scope = json_strings(raw, "scope"),
    is_root = is_root, parent = parent, raw = raw
  )

  # Licences: an expression or a licence id is an expression, a licence name
  # free text.
  lic <- json_flatten(raw, "licenses")
  expr <- json_strings(lic$items, "expression")
  lic_id <- json_strings(lic$items, c("license", "id"))
  lic_name <- json_strings(lic$items, c("license", "name"))
  value <- tables_coalesce(expr, lic_id, lic_name)
  at <- json_pointer(location[lic$owner], "licenses", lic$index)
  lic_loc <- ifelse(
    !is.na(expr), json_pointer(at, "expression"),
    json_pointer(json_pointer(at, "license"), ifelse(!is.na(lic_id), "id", "name"))
  )
  keep <- !is.na(value)
  kind <- ifelse(is.na(expr) & is.na(lic_id), "name", "expression")
  licenses <- tables_licenses(
    lic_loc[keep], id[lic$owner][keep], value[keep], kind[keep], rep("licenses", sum(keep))
  )

  has_purl <- !is.na(purl)
  purls <- tables_purls(json_pointer(location[has_purl], "purl"), id[has_purl], purl[has_purl])

  list(
    elements = elements,
    licenses = licenses,
    purls = purls,
    relationships = tables_cdx_relationships(doc, elements),
    document = tables_cdx_document(doc, meta, root, has_root)
  )
}

# Nesting ("contains", from the element walk), then the dependencies entries:
# "dependsOn" and "provides" rows, and for an entry that lists neither, one
# "dependsOn" row with no target.
tables_cdx_relationships <- function(doc, elements) {
  nest <- !is.na(elements$parent) & !is.na(elements$id)
  deps <- json_items(json_member(doc, "dependencies"))
  ref <- json_strings(deps, "ref")
  entry_at <- function(i) tables_paste("/dependencies/", i - 1L)
  parts <- list()
  for (type in c("dependsOn", "provides")) {
    fl <- json_flatten(deps, type)
    to <- vapply(fl$items, json_string, character(1))
    keep <- !is.na(ref[fl$owner]) & !is.na(to)
    entry <- fl$owner[keep]
    parts[[type]] <- list(
      entry = entry, rank = rep(if (type == "dependsOn") 1L else 2L, length(entry)),
      index = fl$index[keep], location = json_pointer(entry_at(entry), type, fl$index[keep]),
      from = ref[entry], to = to[keep], type = rep(type, length(entry))
    )
  }
  empty <- setdiff(which(!is.na(ref)), c(parts$dependsOn$entry, parts$provides$entry))
  zero <- rep(0L, length(empty))
  parts$empty <- list(
    entry = empty, rank = zero, index = zero, location = entry_at(empty), from = ref[empty],
    to = rep(NA_character_, length(empty)), type = rep("dependsOn", length(empty))
  )
  deps <- tables_bind(parts, c("entry", "rank", "index"), c("location", "from", "to", "type"))
  tables_relationships(
    location = c(elements$location[nest], deps$location),
    from = c(elements$parent[nest], deps$from),
    to = c(elements$id[nest], deps$to),
    type = c(rep("contains", sum(nest)), deps$type)
  )
}

tables_cdx_document <- function(doc, meta, root, has_root) {
  authors <- json_items(json_member(meta, "authors"))
  manufacturer <- json_member(meta, "manufacturer")
  tools <- json_member(meta, "tools")
  # An array in 1.4; {components, services} from 1.5.
  tools <- if (is.list(tools) && !is.null(names(tools))) {
    c(json_items(json_member(tools, "components")), json_items(json_member(tools, "services")))
  } else {
    json_items(tools)
  }
  props <- json_items(json_member(meta, "properties"))
  note <- json_strings(props, "name") %in% "sbom:note"
  tables_document(
    timestamp = json_string(json_member(meta, "timestamp")),
    timestamp_location = "/metadata/timestamp",
    authors = tables_authors(
      name = c(json_strings(authors, "name"), json_string(json_member(manufacturer, "name"))),
      kind = c(rep("person", length(authors)), "organization"),
      location = c(
        tables_paste("/metadata/authors/", seq_along(authors) - 1L), "/metadata/manufacturer"
      )
    ),
    tools = tables_strings(
      name = json_strings(tools, "name"), version = json_strings(tools, "version")
    ),
    root = if (has_root) json_string(json_member(root, "bom-ref")),
    root_location = if (has_root) "/metadata/component",
    notes = json_strings(props[note], "value"),
    ids = json_key_strings(doc, "bom-ref")
  )
}

# SPDX 2 ----------------------------------------------------------------------

# The SPDX 2 arrays of elements, with their kinds, name fields and licence
# fields: single values, then the array of values.
tables_spdx2_groups <- list(
  packages = list(
    kind = "component", name = "name",
    single = c("licenseConcluded", "licenseDeclared"), multi = "licenseInfoFromFiles"
  ),
  files = list(
    kind = "file", name = "fileName", single = "licenseConcluded", multi = "licenseInfoInFiles"
  ),
  snippets = list(
    kind = "snippet", name = "name", single = "licenseConcluded", multi = "licenseInfoInSnippets"
  )
)

# A supplier or originator without its "Organization: " or "Person: " prefix;
# NOASSERTION is NA.
tables_spdx2_party <- function(x) {
  x[x %in% "NOASSERTION"] <- NA_character_
  tables_present(sub("^(Organization|Person):[ \t\r\n]*", "", x))
}

tables_spdx2 <- function(doc) {
  doc_id <- tables_coalesce(json_string(json_member(doc, "SPDXID")), "SPDXRef-DOCUMENT")
  groups <- lapply(names(tables_spdx2_groups), function(key) {
    items <- json_items(json_member(doc, key))
    keep <- vapply(items, json_is_object, logical(1))
    list(raw = unname(items[keep]), location = tables_paste("/", key, "/", which(keep) - 1L))
  })
  raw <- tables_column(groups, "raw", list())
  location <- tables_column(groups, "location")
  group <- rep(names(tables_spdx2_groups), vapply(groups, function(g) length(g$raw), integer(1)))
  n <- length(raw)
  id <- json_strings(raw, "SPDXID")
  pkg <- group == "packages"
  none <- rep(NA_character_, n)
  package_field <- function(key) replace(none, pkg, json_strings(raw[pkg], key))
  name <- none
  for (key in names(tables_spdx2_groups)) {
    name[group == key] <- json_strings(raw[group == key], tables_spdx2_groups[[key]]$name)
  }

  # Purls, CPEs and SWID tag ids from the packages' external references.
  refs <- json_flatten(raw, "externalRefs")
  category <- json_strings(refs$items, "referenceCategory")
  ref_type <- json_strings(refs$items, "referenceType")
  locator <- json_strings(refs$items, "referenceLocator")
  prefix <- c(purl = "purl:", cpe22Type = "cpe:", cpe23Type = "cpe:", swid = "swid:")[ref_type]
  # A purl is a package manager reference, whichever spelling of the
  # category the version used.
  prefix[ref_type %in% "purl" & !category %in% c("PACKAGE-MANAGER", "PACKAGE_MANAGER")] <- NA
  is_ref <- pkg[refs$owner] & !is.na(prefix) & !is.na(locator)
  is_purl <- is_ref & ref_type %in% "purl"
  purl_owner <- refs$owner[is_purl]
  # A swid locator is a swid: URI, which the prefix replaces.
  ident <- ifelse(ref_type %in% "swid", sub("^swid:", "", locator), locator)

  elements <- tables_elements(
    location = location, id = id,
    kind = vapply(tables_spdx2_groups, function(g) g$kind, character(1))[group],
    name = name,
    version = package_field("versionInfo"),
    supplier = tables_spdx2_party(package_field("supplier")),
    originator = tables_spdx2_party(package_field("originator")),
    purl = locator[is_purl][match(seq_len(n), purl_owner)],
    identifiers = tables_group(tables_paste(prefix[is_ref], ident[is_ref]), refs$owner[is_ref], n),
    type = package_field("primaryPackagePurpose"),
    scope = none, is_root = rep(FALSE, n), parent = none, raw = raw
  )
  ref_at <- json_pointer(location[purl_owner], "externalRefs", refs$index[is_purl])
  purls <- tables_purls(json_pointer(ref_at, "referenceLocator"), id[purl_owner], locator[is_purl])

  relationships <- tables_spdx2_relationships(doc, doc_id, elements, pkg)
  rel <- relationships
  describes <- rel$type == "DESCRIBES" & rel$from == doc_id
  states <- describes | (rel$type == "DESCRIBED_BY" & rel$to == doc_id)
  root <- ifelse(describes, rel$to, rel$from)[states]
  root_location <- rel$location[states][!duplicated(root)]
  root <- root[!duplicated(root)]
  elements$is_root <- elements$id %in% root

  ci <- json_member(doc, "creationInfo")
  creators <- vapply(json_items(json_member(ci, "creators")), json_string, character(1))
  pattern <- "^(Person|Organization|Tool):[ \t\r\n]*(.*)$"
  hit <- !is.na(creators) & grepl(pattern, creators)
  word <- sub(pattern, "\\1", creators[hit])
  text <- trimws(sub(pattern, "\\2", creators[hit]))
  # "Person: name (email)" and "Organization: name (email)".
  party <- trimws(sub("[ \t\r\n]*\\([^()]*\\)$", "", text))
  extracted <- json_items(json_member(doc, "hasExtractedLicensingInfos"))
  external <- json_items(json_member(doc, "externalDocumentRefs"))
  list(
    elements = elements,
    licenses = tables_spdx2_licenses(raw, location, id, group),
    purls = purls,
    relationships = relationships,
    document = tables_document(
      name = json_string(json_member(doc, "name")),
      timestamp = json_string(json_member(ci, "created")),
      timestamp_location = "/creationInfo/created",
      authors = tables_authors(
        name = ifelse(word == "Tool", text, party),
        kind = c(Person = "person", Organization = "organization", Tool = "tool")[word],
        location = tables_paste("/creationInfo/creators/", which(hit) - 1L)
      ),
      tools = tables_tool(text[word == "Tool"], "-"),
      root = root, root_location = root_location,
      notes = json_string(json_member(doc, "comment")),
      defined_refs = json_strings(extracted, "licenseId"),
      external_ids = json_strings(external, "externalDocumentId"),
      ids = c(doc_id, id)
    )
  )
}

# The licence rows of every element, element by element: its single licence
# fields, then the items of its array of licences, all SPDX expressions.
tables_spdx2_licenses <- function(raw, location, id, group) {
  part <- function(element, rank, index, at, value, field) {
    list(
      element = element, rank = rep(rank, length(element)), index = index,
      location = at, id = id[element], expression = value, field = rep(field, length(element))
    )
  }
  parts <- list()
  for (key in names(tables_spdx2_groups)) {
    g <- tables_spdx2_groups[[key]]
    at <- which(group == key)
    for (k in seq_along(g$single)) {
      value <- json_strings(raw[at], g$single[k])
      element <- at[!is.na(value)]
      parts[[length(parts) + 1L]] <- part(
        element, k, rep(0L, length(element)), json_pointer(location[element], g$single[k]),
        value[!is.na(value)], g$single[k]
      )
    }
    fl <- json_flatten(raw[at], g$multi)
    value <- vapply(fl$items, json_string, character(1))
    keep <- !is.na(value)
    element <- at[fl$owner[keep]]
    index <- fl$index[keep]
    parts[[length(parts) + 1L]] <- part(
      element, length(g$single) + 1L, index, json_pointer(location[element], g$multi, index),
      value[keep], g$multi
    )
  }
  rows <- tables_bind(
    parts, c("element", "rank", "index"), c("location", "id", "expression", "field")
  )
  tables_licenses(rows$location, rows$id, rows$expression, field = rows$field)
}

# documentDescribes as DESCRIBES rows, the relationships as written, and the
# packages' hasFiles as CONTAINS rows.
tables_spdx2_relationships <- function(doc, doc_id, elements, pkg) {
  describes <- vapply(json_items(json_member(doc, "documentDescribes")), json_string, character(1))
  rels <- json_items(json_member(doc, "relationships"))
  from <- json_strings(rels, "spdxElementId")
  to <- json_strings(rels, "relatedSpdxElement")
  type <- json_strings(rels, "relationshipType")
  ok <- !is.na(from) & !is.na(to) & !is.na(type)
  files <- json_flatten(elements$raw[pkg], "hasFiles")
  file_to <- vapply(files$items, json_string, character(1))
  file_from <- elements$id[pkg][files$owner]
  file_ok <- !is.na(file_from) & !is.na(file_to)
  tables_relationships(
    location = c(
      tables_paste("/documentDescribes/", which(!is.na(describes)) - 1L),
      tables_paste("/relationships/", which(ok) - 1L),
      json_pointer(elements$location[pkg][files$owner[file_ok]], "hasFiles", files$index[file_ok])
    ),
    from = c(rep(doc_id, sum(!is.na(describes))), from[ok], file_from[file_ok]),
    to = c(describes[!is.na(describes)], to[ok], file_to[file_ok]),
    type = c(rep("DESCRIBES", sum(!is.na(describes))), type[ok], rep("CONTAINS", sum(file_ok)))
  )
}

# SPDX 3 ----------------------------------------------------------------------

tables_spdx3_kinds <- c(
  software_Package = "component", ai_AIPackage = "component", dataset_DatasetPackage = "component",
  software_File = "file", software_Snippet = "snippet"
)

tables_spdx3_agent_kinds <- c(
  Person = "person", Organization = "organization", SoftwareAgent = "tool", Agent = "organization"
)

tables_spdx3_license_types <- c("hasDeclaredLicense", "hasConcludedLicense")

# The graph indexed once: each node's location, type, name, spdxId and key
# (its spdxId, or its @id for a blank node), with `find()` matching ids to
# nodes in one match() per call. Also the creationInfo objects given inline
# on a node, with their @id, which other nodes may name.
tables_spdx3_index <- function(graph) {
  spdx_id <- json_strings(graph, "spdxId")
  key <- tables_coalesce(spdx_id, json_strings(graph, "@id"))
  creation <- lapply(graph, json_member, key = "creationInfo")
  list(
    location = tables_paste(json_pointer("", "@graph"), "/", seq_along(graph) - 1L),
    type = json_strings(graph, "type"),
    name = json_strings(graph, "name"),
    spdx_id = spdx_id,
    key = key,
    find = function(ids) match(ids, key, incomparables = NA),
    creation = creation,
    creation_id = json_strings(creation, "@id")
  )
}

# The agents `values` name, each an id in the graph or an object given inline,
# as list(name, type). Anything else, or an id the graph lacks, gives NA.
tables_spdx3_agents <- function(values, ix) {
  at <- ix$find(vapply(values, json_string, character(1)))
  inline <- vapply(values, json_is_object, logical(1))
  name <- ifelse(inline, json_strings(values, "name"), ix$name[at])
  type <- ifelse(inline, json_strings(values, "type"), ix$type[at])
  agent <- type %in% names(tables_spdx3_agent_kinds) & !is.na(tables_present(name))
  list(name = ifelse(agent, name, NA_character_), type = ifelse(agent, type, NA_character_))
}

tables_spdx3 <- function(doc) {
  graph <- unname(json_items(json_member(doc, "@graph")))
  ix <- tables_spdx3_index(graph)
  el <- which(ix$type %in% names(tables_spdx3_kinds))
  raw <- graph[el]
  location <- ix$location[el]
  n <- length(raw)
  none <- rep(NA_character_, n)
  id <- ix$spdx_id[el]
  supplier <- tables_spdx3_agents(lapply(raw, json_member, key = "suppliedBy"), ix)$name
  originator <- tables_spdx3_agents(lapply(raw, function(x) {
    agents <- json_items(json_member(x, "originatedBy"))
    if (length(agents) > 0L) agents[[1L]]
  }), ix)$name

  # Purls, CPEs and SWID tag ids: the package URL, then the external
  # identifiers.
  main <- json_strings(raw, "software_packageUrl")
  has_main <- !is.na(main)
  ext <- json_flatten(raw, "externalIdentifier")
  ext_type <- json_strings(ext$items, "externalIdentifierType")
  ext_id <- json_strings(ext$items, "identifier")
  prefix <- c(packageUrl = "purl:", cpe22 = "cpe:", cpe23 = "cpe:", swid = "swid:")[ext_type]
  is_ext <- !is.na(prefix) & !is.na(ext_id)
  is_purl <- is_ext & ext_type %in% "packageUrl"
  purl_owner <- ext$owner[is_purl]
  elements <- tables_elements(
    location = location, id = id, kind = tables_spdx3_kinds[ix$type[el]],
    name = ix$name[el], version = json_strings(raw, "software_packageVersion"),
    supplier = supplier, originator = originator,
    purl = tables_coalesce(main, ext_id[is_purl][match(seq_len(n), purl_owner)]),
    identifiers = tables_group(
      c(tables_paste("purl:", main[has_main]), tables_paste(prefix[is_ext], ext_id[is_ext])),
      c(which(has_main), ext$owner[is_ext]), n
    ),
    type = json_strings(raw, "software_primaryPurpose"),
    scope = none, is_root = rep(FALSE, n), parent = none, raw = raw
  )
  ext_at <- json_pointer(location[purl_owner], "externalIdentifier", ext$index[is_purl])
  purls <- tables_bind(
    list(
      list(
        element = which(has_main), rank = rep(1L, sum(has_main)), index = rep(0L, sum(has_main)),
        location = json_pointer(location[has_main], "software_packageUrl"),
        id = id[has_main], purl = main[has_main]
      ),
      list(
        element = purl_owner, rank = rep(2L, length(purl_owner)), index = ext$index[is_purl],
        location = json_pointer(ext_at, "identifier"), id = id[purl_owner], purl = ext_id[is_purl]
      )
    ),
    c("element", "rank", "index"), c("location", "id", "purl")
  )

  rel_type <- json_strings(graph, "relationshipType")
  from <- json_strings(graph, "from")
  is_license <- rel_type %in% tables_spdx3_license_types
  is_rel <- !is.na(rel_type) & !is.na(from)
  root <- tables_spdx3_root(graph, ix)
  elements$is_root <- elements$id %in% root$id
  list(
    elements = elements,
    licenses = tables_spdx3_licenses(graph, ix, which(is_rel & is_license), rel_type, from, id),
    purls = tables_purls(purls$location, purls$id, purls$purl),
    relationships = tables_spdx3_relationships(
      graph, ix, which(is_rel & !is_license), rel_type, from
    ),
    document = tables_spdx3_document(graph, ix, root)
  )
}

# One row for each id in the `to` array of each relationship node at `rels`.
tables_spdx3_relationships <- function(graph, ix, rels, rel_type, from) {
  to <- json_flatten(graph[rels], "to")
  to_id <- vapply(to$items, json_string, character(1))
  keep <- !is.na(to_id)
  owner <- rels[to$owner[keep]]
  tables_relationships(
    location = json_pointer(ix$location[owner], "to", to$index[keep]),
    from = from[owner], to = to_id[keep], type = rel_type[owner]
  )
}

# The licence each licence relationship at `rels` points to: the text of a
# LicenseExpression in the graph, NOASSERTION or NONE for those individuals,
# or the id in an SPDX License List IRI (described in the graph or not). The
# field is the relationship type. Rows go element by element (the elements
# with ids `element_ids`, then any other subject), each in relationship order.
tables_spdx3_licenses <- function(graph, ix, rels, rel_type, from, element_ids) {
  to <- json_flatten(graph[rels], "to")
  to_id <- vapply(to$items, json_string, character(1))
  at <- ix$find(to_id)
  expression <- rep(NA_character_, length(to_id))
  expression[!is.na(at)] <- json_strings(graph[at[!is.na(at)]], "simplelicensing_licenseExpression")
  in_graph <- !is.na(expression)
  individual <- paste0(
    "^(expandedlicensing_|https://spdx\\.org/rdf/3\\.[^/]+/terms/ExpandedLicensing/)",
    "(NoAssertion|None)License$"
  )
  special <- is.na(expression) & grepl(individual, to_id)
  expression[special] <- toupper(sub(individual, "\\2", to_id[special]))
  listed <- is.na(expression) & grepl("^https://spdx\\.org/licenses/[^/]+$", to_id)
  expression[listed] <- sub("^https://spdx\\.org/licenses/", "", to_id[listed])
  owner <- rels[to$owner]
  location <- ifelse(
    in_graph, json_pointer(ix$location[at], "simplelicensing_licenseExpression"),
    json_pointer(ix$location[owner], "to", to$index)
  )
  element <- match(from[owner], element_ids, incomparables = NA)
  element[is.na(element)] <- length(element_ids) + 1L
  o <- which(!is.na(expression))
  o <- o[order(element[o], owner[o], to$index[o], method = "radix")]
  tables_licenses(
    location = location[o], id = from[owner][o], expression = expression[o],
    kind = rep("expression", length(o)), field = rel_type[owner][o]
  )
}

# The document's roots. The walk starts at the SpdxDocument's rootElement, or
# at the first SBOM's when the SpdxDocument has none or there is no
# SpdxDocument. A root that is itself a collection (an SBOM, a bundle) is
# replaced by its own roots. Every rootElement entry in the graph is resolved
# to its node in one match(), and each collection is expanded at most once,
# so the walk is linear in the graph and ends whatever its cycles.
tables_spdx3_root <- function(graph, ix) {
  entries <- json_flatten(graph, "rootElement")
  entry_id <- vapply(entries$items, json_string, character(1))
  entry_at <- ix$find(entry_id)
  count <- tabulate(entries$owner, nbins = length(graph))
  first <- match(seq_along(graph), entries$owner)
  collection <- count > 0L & !ix$type %in% names(tables_spdx3_kinds)
  start <- c(
    match("SpdxDocument", ix$type),
    which(ix$type %in% "software_Sbom" & count > 0L)[1L]
  )
  start <- start[!is.na(start) & count[start] > 0L][1L]
  kept <- integer(length(entry_id))
  n_kept <- 0L
  stack <- integer(length(entry_id))
  top <- 0L
  seen <- logical(length(graph))
  if (!is.na(start)) {
    seen[start] <- TRUE
    top <- count[start]
    stack[seq_len(top)] <- (first[start] + top - 1L):first[start]
  }
  # Depth first, so the roots keep their order; the stack holds entries.
  while (top > 0L) {
    e <- stack[top]
    top <- top - 1L
    k <- entry_at[e]
    if (is.na(k) || !collection[k]) {
      n_kept <- n_kept + 1L
      kept[n_kept] <- e
    } else if (!seen[k]) {
      seen[k] <- TRUE
      m <- count[k]
      stack[top + seq_len(m)] <- (first[k] + m - 1L):first[k]
      top <- top + m
    }
  }
  kept <- kept[seq_len(n_kept)]
  ids <- entry_id[kept]
  locations <- json_pointer(ix$location[entries$owner[kept]], "rootElement", entries$index[kept])
  keep <- !is.na(ids) & !duplicated(ids)
  list(id = ids[keep], location = locations[keep])
}

# The document's facts, from the SpdxDocument (or the first SBOM when there
# is none) and its creationInfo: given inline, or named by its @id, as a node
# of the graph or inline on another node. Without a document node, the
# creationInfo is the first CreationInfo node, or the first one given inline.
tables_spdx3_document <- function(graph, ix, root) {
  at <- match("SpdxDocument", ix$type)
  if (is.na(at)) at <- match("software_Sbom", ix$type)
  node <- if (!is.na(at)) graph[[at]]
  ci_value <- json_member(node, "creationInfo")
  ci <- NULL
  ci_location <- NA_character_
  if (json_is_object(ci_value)) {
    ci <- ci_value
    ci_location <- json_pointer(ix$location[at], "creationInfo")
  } else {
    ref <- json_string(ci_value)
    top <- if (is.null(node)) match("CreationInfo", ix$type) else ix$find(ref)
    inline <- if (is.null(node)) {
      which(vapply(ix$creation, json_is_object, logical(1)))[1L]
    } else {
      match(ref, ix$creation_id, incomparables = NA)
    }
    if (!is.na(top)) {
      ci <- graph[[top]]
      ci_location <- ix$location[top]
    } else if (!is.na(inline)) {
      ci <- ix$creation[[inline]]
      ci_location <- json_pointer(ix$location[inline], "creationInfo")
    }
  }
  created_by <- json_items(json_member(ci, "createdBy"))
  agents <- tables_spdx3_agents(created_by, ix)
  created_using <- json_items(json_member(ci, "createdUsing"))
  tool_at <- ix$find(vapply(created_using, json_string, character(1)))
  inline <- vapply(created_using, json_is_object, logical(1))
  tool_name <- ifelse(inline, json_strings(created_using, "name"), ix$name[tool_at])
  imports <- json_flatten(graph, "import")
  tables_document(
    name = json_string(json_member(node, "name")),
    timestamp = json_string(json_member(ci, "created")),
    timestamp_location = json_pointer(ci_location, "created"),
    authors = tables_authors(
      name = agents$name, kind = unname(tables_spdx3_agent_kinds[agents$type]),
      location = json_pointer(ci_location, "createdBy", seq_along(created_by) - 1L)
    ),
    tools = tables_tool(tool_name, " "),
    root = root$id, root_location = root$location,
    notes = json_string(json_member(node, "comment")),
    external_ids = json_strings(imports$items, "externalSpdxId"),
    ids = ix$spdx_id
  )
}

# SWID ------------------------------------------------------------------------

# Attribute `key` of a SWID element, a named character vector; NA when absent.
tables_swid_value <- function(x, key) {
  at <- if (is.character(x)) match(key, names(x)) else NA_integer_
  if (is.na(at)) NA_character_ else unname(x[[at]])
}

tables_swid_values <- function(items, key) {
  vapply(items, tables_swid_value, character(1), key = key, USE.NAMES = FALSE)
}

# The links that name other software as part of the tag's: requires and
# component. Other links (describedby, related and so on) point to pages and
# media, not to software.
tables_swid_rels <- c("requires", "component")

tables_swid <- function(doc) {
  tag <- json_member(doc, "tag")
  entities <- json_items(json_member(doc, "entities"))
  links <- json_items(json_member(doc, "links"))
  meta <- json_items(json_member(doc, "meta"))
  roles <- strsplit(tables_coalesce(tables_swid_values(entities, "role"), ""), "[ \t\r\n]+")
  entity_names <- tables_present(tables_swid_values(entities, "name"))
  named <- function(role) {
    has <- vapply(roles, function(r) role %in% r, logical(1)) & !is.na(entity_names)
    entity_names[has][1L]
  }
  meta_purl <- tables_swid_values(meta, "sbom:purl")
  purl_at <- which(!is.na(meta_purl))[1L]
  tag_id <- tables_swid_value(tag, "tagId")

  rel <- tables_swid_values(links, "rel")
  at <- which(rel %in% tables_swid_rels)
  link_raw <- links[at]
  href <- tables_swid_values(link_raw, "href")
  link_purl <- tables_swid_values(link_raw, "sbom:purl")
  link_location <- tables_paste("/links/", at - 1L)
  n <- length(at) + 1L
  none <- rep(NA_character_, n - 1L)
  id <- c(tag_id, href)
  purl <- c(meta_purl[purl_at], link_purl)
  swid <- c(tag_id, ifelse(startsWith(href, "swid:"), substring(href, 6L), NA_character_))
  ident <- c(tables_paste("swid:", swid), tables_paste("purl:", purl))
  has <- !is.na(c(swid, purl))
  elements <- tables_elements(
    location = c("/tag", link_location), id = id, kind = rep("component", n),
    name = c(tables_swid_value(tag, "name"), tables_swid_values(link_raw, "sbom:name")),
    version = c(tables_swid_value(tag, "version"), tables_swid_values(link_raw, "sbom:version")),
    supplier = c(named("distributor"), none),
    originator = c(tables_coalesce(named("softwareCreator"), named("maintainer")), none),
    purl = purl, identifiers = tables_group(ident[has], rep.int(seq_len(n), 2L)[has], n),
    type = c(NA_character_, none), scope = c(NA_character_, tables_swid_values(link_raw, "use")),
    is_root = c(TRUE, rep(FALSE, n - 1L)), parent = c(NA_character_, none),
    raw = c(list(tag), link_raw)
  )
  purl_location <- c(
    if (!is.na(purl_at)) json_pointer(tables_paste("/meta/", purl_at - 1L), "sbom:purl"),
    json_pointer(link_location[!is.na(link_purl)], "sbom:purl")
  )
  edge <- !is.na(tag_id) & !is.na(href)
  creator <- vapply(roles, function(r) "tagCreator" %in% r, logical(1))
  # sbom's own licence attribute holds the licence as written: free text.
  license <- tables_swid_values(meta, "sbom:license")
  has_license <- which(!is.na(license))
  list(
    elements = elements,
    licenses = tables_licenses(
      location = json_pointer(tables_paste("/meta/", has_license - 1L), "sbom:license"),
      id = rep(tag_id, length(has_license)), expression = license[has_license],
      kind = rep("name", length(has_license)), field = rep("license", length(has_license))
    ),
    purls = tables_purls(purl_location, id[!is.na(purl)], purl[!is.na(purl)]),
    relationships = tables_relationships(
      link_location[edge], rep(tag_id, sum(edge)), href[edge], rel[at][edge]
    ),
    document = tables_document(
      name = tables_swid_value(tag, "name"),
      authors = tables_authors(
        name = entity_names[creator], kind = rep("organization", sum(creator)),
        location = tables_paste("/entities/", which(creator) - 1L)
      ),
      tools = tables_tool(tables_swid_values(meta, "generator"), " "),
      root = tag_id, root_location = "/tag",
      notes = tables_swid_values(meta, "description"),
      ids = tag_id
    )
  )
}
