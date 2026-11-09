# The SPDX 2 and SPDX 3 halves of document_tables().

# The SPDX 2 arrays of elements, with their kinds, name fields and license
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

# The tables of an SPDX 2 document `doc`.
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

# The license rows of every element, element by element: its single license
# fields, then the items of its array of licenses, all SPDX expressions.
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

# The tables of an SPDX 3 JSON-LD document `doc`.
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
  structure(
    list(
      elements = elements,
      licenses = tables_spdx3_licenses(graph, ix, which(is_rel & is_license), rel_type, from, id),
      purls = tables_purls(purls$location, purls$id, purls$purl),
      relationships = tables_spdx3_relationships(
        graph, ix, which(is_rel & !is_license), rel_type, from
      ),
      document = tables_spdx3_document(graph, ix, root)
    ),
    index = ix
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

# The license each license relationship at `rels` points to: the text of a
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
