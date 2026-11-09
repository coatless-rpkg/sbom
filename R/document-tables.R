# Neutral tables of any SBOM's raw model. document_tables() turns what
# read_document() returns, in any of the four families, into elements,
# licenses, purls, relationships and document facts, each row carrying the
# JSON pointer (RFC 6901, 0-based) of the value it came from. read_sbom() maps
# them to an <sbom>, and the content checks run on them. The SPDX tables are
# made in document-tables-spdx.R.
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

# `x` when it is a string, else NA.
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

# A data frame of the columns in `...`, built without checking or copying
# them; the columns must have equal lengths.
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

# The elements table from one vector or list per column, with the types the
# table needs.
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

# `field` is where the license came from: the SPDX 2 key, the SPDX 3
# relationship type, "licenses" for CycloneDX and "license" for SWID.
tables_licenses <- function(location = character(), id = character(), expression = character(),
                            kind = rep("expression", length(location)), field = character()) {
  tables_strings(location = location, id = id, expression = expression, kind = kind, field = field)
}

# A data frame of the purls: `location`, element `id` and `purl`.
tables_purls <- function(location = character(), id = character(), purl = character()) {
  tables_strings(location = location, id = id, purl = purl)
}

# A data frame of relationships: `location`, `from`, `to` and `type`.
tables_relationships <- function(location = character(), from = character(), to = character(),
                                 type = character()) {
  tables_strings(location = location, from = from, to = to, type = type)
}

# Only authors with a name are listed: one that is empty or NOASSERTION is
# none, as the NTIA profile says of every value (content_present()).
tables_authors <- function(name = character(), kind = character(), location = character()) {
  keep <- content_present(name)
  tables_strings(name = name[keep], kind = kind[keep], location = location[keep])
}

# The `document` table: the document-level facts with each field given
# defaults, dropping NA authors, tools, notes and ids, and unique ids.
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
#'     its scope); `parent` is the location of the nesting parent (CycloneDX
#'     only), which may have no id;
#'     `raw` is each element's own list (a named character vector for SWID).
#'   * `licenses`: `data.frame(location, id, expression, kind, field)`, `kind` being
#'     `"expression"` or `"name"` (free text), and `field` where it came from:
#'     the SPDX 2 key (`licenseDeclared` and so on), the SPDX 3 relationship
#'     type (`hasDeclaredLicense` or `hasConcludedLicense`), `"licenses"` for
#'     CycloneDX, or `"license"` for SWID's `sbom:license`.
#'   * `purls`: `data.frame(location, id, purl)`, one row per purl.
#'   * `relationships`: `data.frame(location, from, to, type)`, with the
#'     format's own types. CycloneDX also gives an `"affects"` row for each
#'     target of a vulnerability's `affects`, at
#'     `/vulnerabilities/<i>/affects/<j>`. `from` is always an id, except
#'     that it is NA in the `"affects"` rows of a vulnerability without a
#'     bom-ref. `to` is NA only in the row
#'     a CycloneDX `dependencies` entry that lists no dependency gives, which
#'     records that its component's dependencies were stated. SPDX 3 license
#'     relationships are license rows instead.
#'   * For SPDX 3, the attribute `index` holds the graph's index
#'     (`tables_spdx3_index()`), and for SWID the attribute `entities` holds
#'     the entities' roles (`tables_swid_entities()`), so that `read_sbom()`
#'     builds neither again.
#'   * `document`: `list(name, timestamp, timestamp_location, authors, tools,
#'     root, root_location, notes, defined_refs, external_ids)`. `authors` is
#'     `data.frame(name, kind, location)`, with only named authors, `kind`
#'     being `"person"`, `"organization"` or `"tool"` (SPDX 2's "Tool:"
#'     creators, SPDX 3 software agents, CycloneDX tools, and sbom as a SWID
#'     tag creator); `tools` is `data.frame(name, version)`. `root` holds the root ids the document
#'     states, NA for a root without one, and `root_location` where each is
#'     stated. `ids` is every id the document defines: every CycloneDX
#'     bom-ref (services', licenses' and vulnerabilities' too), SPDX 2's
#'     document id and its elements' SPDXIDs, every SPDX 3 node's spdxId, or
#'     the SWID tagId.
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
# at the location `parent`, and every component nested in them, depth-first:
# a list of chunks, each list(raw, location, parent). A parent is named by its
# location, since it may have no bom-ref. `empty` says whether an empty
# unnamed list is an object (the XML model) or the array [] (JSON).
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
  slice <- function(idx) lapply(chunk, function(col) col[idx])
  # Each component with nested ones is followed by them.
  pieces <- vector("list", 2L * length(nested) + 1L)
  start <- 1L
  for (k in seq_along(nested)) {
    i <- nested[k]
    pieces[[2L * k - 1L]] <- list(slice(start:i))
    at_kids <- json_pointer(chunk$location[i], "components")
    pieces[[2L * k]] <- tables_cdx_walk(kids[[i]], at_kids, chunk$location[i], empty)
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
    inner <- json_items(json_member(root, "components"))
    chunks <- c(
      list(list(raw = list(root), location = "/metadata/component", parent = NA_character_)),
      tables_cdx_walk(inner, "/metadata/component/components", "/metadata/component", xml),
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

  # Licenses: an expression or a license id is an expression, a license name
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

# Nesting ("contains", from the element walk, between components that both
# have an id), then the dependencies entries: "dependsOn" and "provides" rows,
# and for an entry that lists neither, one "dependsOn" row with no target.
# Then one "affects" row per target a vulnerability names, from the
# vulnerability's bom-ref, NA when it has none.
tables_cdx_relationships <- function(doc, elements) {
  parent_id <- elements$id[match(elements$parent, elements$location, incomparables = NA)]
  nest <- !is.na(parent_id) & !is.na(elements$id)
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
  vulns <- json_items(json_member(doc, "vulnerabilities"))
  affects <- json_flatten(vulns, "affects")
  target <- json_strings(affects$items, "ref")
  hit <- !is.na(target)
  vuln <- affects$owner[hit]
  tables_relationships(
    location = c(
      elements$location[nest], deps$location,
      json_pointer(tables_paste("/vulnerabilities/", vuln - 1L), "affects", affects$index[hit])
    ),
    from = c(parent_id[nest], deps$from, json_strings(vulns, "bom-ref")[vuln]),
    to = c(elements$id[nest], deps$to, target[hit]),
    type = c(rep("contains", sum(nest)), deps$type, rep("affects", length(vuln)))
  )
}

# The tools are authors of kind tool, as SPDX 2's "Tool:" creators are.
tables_cdx_document <- function(doc, meta, root, has_root) {
  authors <- json_items(json_member(meta, "authors"))
  manufacturer <- json_member(meta, "manufacturer")
  tools <- json_member(meta, "tools")
  # An array in 1.4; {components, services} from 1.5.
  if (is.list(tools) && !is.null(names(tools))) {
    components <- json_items(json_member(tools, "components"))
    services <- json_items(json_member(tools, "services"))
    tools <- c(components, services)
    tool_at <- c(
      tables_paste("/metadata/tools/components/", seq_along(components) - 1L),
      tables_paste("/metadata/tools/services/", seq_along(services) - 1L)
    )
  } else {
    tools <- json_items(tools)
    tool_at <- tables_paste("/metadata/tools/", seq_along(tools) - 1L)
  }
  props <- json_items(json_member(meta, "properties"))
  note <- json_strings(props, "name") %in% "sbom:note"
  tables_document(
    timestamp = json_string(json_member(meta, "timestamp")),
    timestamp_location = "/metadata/timestamp",
    authors = tables_authors(
      name = c(
        json_strings(authors, "name"), json_string(json_member(manufacturer, "name")),
        json_strings(tools, "name")
      ),
      kind = c(rep("person", length(authors)), "organization", rep("tool", length(tools))),
      location = c(
        tables_paste("/metadata/authors/", seq_along(authors) - 1L), "/metadata/manufacturer",
        tool_at
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

# SPDX 3 ----------------------------------------------------------------------

# SWID ------------------------------------------------------------------------

# Attribute `key` of a SWID element, a named character vector; NA when absent.
tables_swid_value <- function(x, key) {
  at <- if (is.character(x)) match(key, names(x)) else NA_integer_
  if (is.na(at)) NA_character_ else unname(x[[at]])
}

# Attribute `key` of each of `items`, as tables_swid_value() gives it.
tables_swid_values <- function(items, key) {
  vapply(items, tables_swid_value, character(1), key = key, USE.NAMES = FALSE)
}

# The links that name other software as part of the tag's: requires and
# component. Other links (describedby, related and so on) point to pages and
# media, not to software.
tables_swid_rels <- c("requires", "component")

# The entities of a SWID tag, looked up once: each one's name, regid and
# roles, and a function giving, for a role, which entities have it.
tables_swid_entities <- function(doc) {
  entities <- json_items(json_member(doc, "entities"))
  roles <- strsplit(tables_coalesce(tables_swid_values(entities, "role"), ""), "[ \t\r\n]+")
  list(
    name = tables_present(tables_swid_values(entities, "name")),
    regid = tables_present(tables_swid_values(entities, "regid")),
    has_role = function(role) vapply(roles, function(r) role %in% r, logical(1))
  )
}

# The tables of a SWID tag document `doc`.
tables_swid <- function(doc) {
  tag <- json_member(doc, "tag")
  ent <- tables_swid_entities(doc)
  links <- json_items(json_member(doc, "links"))
  meta <- json_items(json_member(doc, "meta"))
  entity_names <- ent$name
  named <- function(role) {
    has <- ent$has_role(role) & !is.na(entity_names)
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
  creator <- ent$has_role("tagCreator")
  # A tag creator with a real regid is an organization. Without one (the
  # placeholder http://invalid.unavailable is the default) it is a person,
  # unless it is sbom itself, the tool, as read_sbom() reads it.
  real <- !is.na(ent$regid) & trimws(ent$regid) != swid_placeholder_regid
  creator_kind <- ifelse(real, "organization", ifelse(entity_names %in% "sbom", "tool", "person"))
  # sbom's own license attribute holds the license as written: free text.
  license <- tables_swid_values(meta, "sbom:license")
  has_license <- which(!is.na(license))
  out <- list(
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
        name = entity_names[creator], kind = creator_kind[creator],
        location = tables_paste("/entities/", which(creator) - 1L)
      ),
      tools = tables_tool(tables_swid_values(meta, "generator"), " "),
      root = tag_id, root_location = "/tag",
      notes = tables_swid_values(meta, "description"),
      ids = tag_id
    )
  )
  structure(out, entities = ent)
}
