# The raw models of the XML formats: CycloneDX XML converted to the
# CycloneDX JSON model, and a SWID tag read into a small list. read_document()
# detects the format and parses the file; these convert the parsed root.

# Namespaces. CycloneDX XML, SWID and SPDX XML elements are matched by
# namespace as well as name: an element or attribute from another namespace
# must not stand in for a standard one. The CycloneDX and SWID schemas let
# such nodes appear anywhere.

# The namespace map of the document `node` belongs to, as xml_name() and
# xml_attrs() take it, with the XML namespace that xml:lang uses.
xml_ns_map <- function(node) {
  c(unclass(xml2::xml_ns(node)), xml = "http://www.w3.org/XML/1998/namespace")
}

# The children of `node` in a namespace whose prefixes in the map `ns` are
# `prefixes`, or in no namespace when `prefixes` is empty, as a list of nodes
# named by local name. Other children are left out, with everything inside
# them.
xml_kids_in <- function(node, ns, prefixes) {
  # xml_length() is much cheaper than xml_children(), and most elements
  # hold only text.
  if (xml2::xml_length(node) == 0L) {
    return(list())
  }
  kids <- unclass(xml2::xml_children(node))
  qualified <- vapply(kids, xml2::xml_name, character(1), ns = ns)
  if (length(prefixes) == 0L) {
    keep <- !grepl(":", qualified, fixed = TRUE)
    local <- qualified[keep]
  } else if (length(prefixes) == 1L) {
    keep <- startsWith(qualified, paste0(prefixes, ":"))
    local <- substring(qualified[keep], nchar(prefixes) + 2L)
  } else {
    colon <- regexpr(":", qualified, fixed = TRUE)
    keep <- colon > 0L & substr(qualified, 1L, colon - 1L) %in% prefixes
    local <- substring(qualified[keep], colon[keep] + 1L)
  }
  kids <- kids[keep]
  names(kids) <- local
  kids
}

# The CycloneDX XML conversion works on plain lists of nodes rather than on
# xml2 node sets, whose subsetting costs more than the conversion itself in a
# document of tens of thousands of components. `ctx` holds the namespace map
# and the prefixes of the document's CycloneDX namespace.

# The attributes the bundled CycloneDX XSDs (1.4 to 1.7) declare on each
# element, keyed by element name, or by "parent/name" where one name declares
# different attributes under different parents. The schemas also admit any
# other attribute (`xs:anyAttribute namespace="##any"`), so an undeclared
# one could stand in for a field, such as a component's purl; only these are
# read. A test recomputes the table from the XSDs.
cdx_xml_declared_attrs <- list(
  address = "bom-ref",
  annotation = "bom-ref",
  assembly = "ref",
  `assessors/assessor` = "bom-ref",
  attachment = c("content-type", "encoding"),
  `authors/author` = "bom-ref",
  bom = c("serialNumber", "version"),
  citation = "bom-ref",
  claim = "bom-ref",
  component = c("bom-ref", "isExternal", "mime-type", "type"),
  `component/data` = "bom-ref",
  composition = "bom-ref",
  contact = "bom-ref",
  `data/classification` = "flow",
  dataflow = c("description", "name"),
  `dataflow/classification` = "flow",
  dataset = "bom-ref",
  dependency = "ref",
  details = c("bom-ref", "license-identifier"),
  `details/text` = c("content-type", "encoding"),
  `diff/text` = c("content-type", "encoding"),
  energyProviders = "bom-ref",
  environmentVar = "name",
  `event/data` = c("content-type", "encoding"),
  `evidence/author` = "bom-ref",
  `evidence/evidence` = "bom-ref",
  `expression-detailed` = c("acknowledgement", "bom-ref", "expression"),
  externalReference = "type",
  `externalReferences/reference` = "type",
  fingerprint = "alg",
  formula = "bom-ref",
  hash = "alg",
  image = c("content-type", "encoding"),
  individual = "bom-ref",
  `input/data` = c("content-type", "encoding"),
  issue = "type",
  level = "bom-ref",
  license = c("acknowledgement", "bom-ref"),
  `license/text` = c("content-type", "encoding"),
  `licenses/expression` = c("acknowledgement", "bom-ref"),
  manufacture = "bom-ref",
  manufacturer = "bom-ref",
  modelCard = "bom-ref",
  `note/text` = c("content-type", "encoding"),
  occurrence = "bom-ref",
  organization = "bom-ref",
  `output/data` = c("content-type", "encoding"),
  patch = "type",
  patent = "bom-ref",
  patentAssertion = "bom-ref",
  patentFamily = "bom-ref",
  property = "name",
  provider = "bom-ref",
  provides = "ref",
  `requirements/requirement` = "bom-ref",
  reviewer = "bom-ref",
  service = "bom-ref",
  standard = "bom-ref",
  subject = "ref",
  supplier = "bom-ref",
  swid = c("name", "patch", "tagId", "tagVersion", "version"),
  `swid/text` = c("content-type", "encoding"),
  `tasks/task` = "bom-ref",
  tool = "ref",
  trigger = "bom-ref",
  vulnerability = c("bom-ref", "ref"),
  workflow = "bom-ref",
  workspace = "bom-ref"
)

# The elements whose text, and the attributes whose value, the XSDs type as
# xs:token or a type derived from it, whose surrounding whitespace is not
# part of the value. Every other value keeps its whitespace. A test
# recomputes these too.
cdx_xml_token_text <- c("fingerprint", "hash")
cdx_xml_token_attrs <- "mime-type"

# The element names that a table of declared attributes keys by parent.
xml_split_names <- function(table) {
  keys <- names(table)
  unique(sub("^.*/", "", keys[grepl("/", keys, fixed = TRUE)]))
}
cdx_xml_attr_split <- xml_split_names(cdx_xml_declared_attrs)

# The attributes `table` declares on the element `node`.
xml_declared_attrs <- function(node, table, split) {
  name <- xml2::xml_name(node)
  if (name %in% split) {
    table[[paste0(xml2::xml_name(xml2::xml_parent(node)), "/", name)]]
  } else {
    table[[name]]
  }
}

# trimws(), but only where there is whitespace to trim: called on every
# token, trimws() alone would take much of the conversion's time.
cdx_xml_trim <- function(x) {
  space <- c(" ", "\t", "\n", "\r")
  padded <- substr(x, 1L, 1L) %in% space | substring(x, nchar(x)) %in% space
  if (any(padded)) x[padded] <- trimws(x[padded])
  x
}

cdx_xml_kids <- function(node, ctx) {
  xml_kids_in(node, ctx$ns, ctx$prefixes)
}

# The CycloneDX children of each of `nodes`, in order, as one named list.
cdx_xml_grandkids <- function(nodes, ctx) {
  kids <- lapply(unname(nodes), cdx_xml_kids, ctx = ctx)
  if (length(kids) == 0L) list() else do.call(c, kids)
}

# An element's own text: the text inside elements of another namespace is
# not part of it.
xml_own_text <- function(node) {
  if (xml2::xml_length(node) == 0L) {
    return(xml2::xml_text(node))
  }
  contents <- xml2::xml_contents(node)
  keep <- xml2::xml_type(contents) %in% c("text", "cdata", "entity_ref")
  paste(xml2::xml_text(contents[keep]), collapse = "")
}

# The attributes CycloneDX declares on an element, as a named list. They have
# no namespace, so a prefixed attribute is never one of them. CycloneDX JSON
# names the attachment attribute content-type contentType.
cdx_xml_attrs <- function(node, ctx) {
  attrs <- xml2::xml_attrs(node, ctx$ns)
  if (length(attrs) == 0L) {
    return(list())
  }
  attrs <- attrs[names(attrs) %in% xml_declared_attrs(node, cdx_xml_declared_attrs, cdx_xml_attr_split)]
  if (length(attrs) == 0L) {
    return(list())
  }
  token <- names(attrs) %in% cdx_xml_token_attrs
  if (any(token)) attrs[token] <- cdx_xml_trim(attrs[token])
  names(attrs)[names(attrs) == "content-type"] <- "contentType"
  as.list(attrs)
}

# Attributes and child elements together. No CycloneDX type declares an
# attribute and a child of one name, but should a file hold both, the child
# wins.
cdx_xml_merge <- function(attrs, fields) {
  c(attrs[!names(attrs) %in% names(fields)], fields)
}

# An element that is always an object, such as a component: its attributes
# and its children.
cdx_xml_object <- function(node, ctx) {
  cdx_xml_merge(cdx_xml_attrs(node, ctx), cdx_xml_fields(cdx_xml_kids(node, ctx), ctx))
}

# Any other element, named `tag`: a string when it holds only text,
# otherwise its attributes and children. Text beside attributes is kept as
# `content`, the name CycloneDX JSON gives it in hashes and attachments.
cdx_xml_value <- function(node, ctx, tag) {
  kids <- cdx_xml_kids(node, ctx)
  attrs <- cdx_xml_attrs(node, ctx)
  if (length(kids) > 0L) {
    return(cdx_xml_merge(attrs, cdx_xml_fields(kids, ctx)))
  }
  text <- xml_own_text(node)
  if (tag %in% cdx_xml_token_text) text <- cdx_xml_trim(text)
  if (length(attrs) == 0L) {
    return(text)
  }
  if (nzchar(text)) attrs$content <- text
  attrs
}

# Text beside attributes, kept under `key`: a hash's content, which is a
# token (cdx_xml_token_text), or a property's value, kept as written.
cdx_xml_text_item <- function(key, trim = FALSE) {
  function(node, ctx) {
    text <- xml_own_text(node)
    c(cdx_xml_attrs(node, ctx), stats::setNames(list(if (trim) cdx_xml_trim(text) else text), key))
  }
}

# An organizational entity, whose urls and contacts are arrays.
cdx_xml_org <- function(node, ctx) {
  kids <- cdx_xml_kids(node, ctx)
  tags <- names(kids)
  out <- cdx_xml_merge(cdx_xml_attrs(node, ctx), cdx_xml_fields(kids[!tags %in% c("url", "contact")], ctx))
  if (any(tags == "url")) {
    out$url <- unname(lapply(kids[tags == "url"], xml_own_text))
  }
  if (any(tags == "contact")) {
    out$contact <- unname(lapply(kids[tags == "contact"], cdx_xml_object, ctx = ctx))
  }
  out
}

# A license choice: {license: {...}} or {expression, ...}.
cdx_xml_license <- function(node, ctx) {
  if (xml2::xml_name(node) == "license") {
    list(license = cdx_xml_object(node, ctx))
  } else {
    c(list(expression = xml_own_text(node)), cdx_xml_attrs(node, ctx))
  }
}

# One dependency element, walked once: list(entry, nested). `entry` is its
# ref, with the refs of its child dependencies as dependsOn and of its
# provides children as provides. `nested` holds the entries of the
# dependencies inside it that have edges of their own, depth-first: XML
# nests dependencies, which JSON cannot.
cdx_xml_dependency <- function(node, ctx) {
  entry <- cdx_xml_attrs(node, ctx)
  kids <- cdx_xml_kids(node, ctx)
  tags <- names(kids)
  inner <- lapply(unname(kids[tags == "dependency"]), cdx_xml_dependency, ctx = ctx)
  ref_of <- function(attrs) if (is_string(attrs[["ref"]])) attrs[["ref"]] else NA_character_
  depends_on <- vapply(inner, function(d) ref_of(d$entry), character(1))
  provides <- vapply(unname(kids[tags == "provides"]), function(p) ref_of(cdx_xml_attrs(p, ctx)), character(1))
  if (any(!is.na(depends_on))) entry$dependsOn <- as.list(depends_on[!is.na(depends_on)])
  if (any(!is.na(provides))) entry$provides <- as.list(provides[!is.na(provides)])
  nested <- lapply(inner, function(d) {
    own <- if (!is.null(d$entry[["dependsOn"]]) || !is.null(d$entry[["provides"]])) list(d$entry)
    c(own, d$nested)
  })
  list(entry = entry, nested = if (length(nested) == 0L) list() else do.call(c, nested))
}

# The top-level dependencies: one entry per dependency element, then each
# nested dependency's edges, merged into the entry of its ref or added as a
# new entry.
cdx_xml_dependencies <- function(nodes, ctx) {
  deps <- cdx_xml_grandkids(nodes, ctx)
  walked <- lapply(unname(deps[names(deps) == "dependency"]), cdx_xml_dependency, ctx = ctx)
  entries <- lapply(walked, function(d) d$entry)
  lifted <- unlist(lapply(walked, function(d) d$nested), recursive = FALSE)
  ref_of <- function(entry) if (is_string(entry[["ref"]])) entry[["ref"]] else NA_character_
  lifted_refs <- vapply(lifted, ref_of, character(1))
  lifted <- lifted[!is.na(lifted_refs)]
  lifted_refs <- lifted_refs[!is.na(lifted_refs)]
  if (length(lifted) == 0L) {
    return(entries)
  }
  refs <- vapply(entries, ref_of, character(1))
  groups <- split(seq_along(lifted), factor(lifted_refs, levels = unique(lifted_refs)))
  added <- vector("list", length(groups))
  for (k in seq_along(groups)) {
    ref <- names(groups)[k]
    at <- match(ref, refs)
    entry <- if (is.na(at)) list(ref = ref) else entries[[at]]
    for (field in c("dependsOn", "provides")) {
      values <- unique(c(
        unlist(entry[[field]]),
        unlist(lapply(lifted[groups[[k]]], function(e) e[[field]]))
      ))
      if (length(values) > 0L) entry[[field]] <- as.list(values)
    }
    if (is.na(at)) added[[k]] <- entry else entries[[at]] <- entry
  }
  c(entries, added[!vapply(added, is.null, logical(1))])
}

# The items named `names` in the containers `nodes`, gathered from every
# container, each converted by `convert`, as an array.
cdx_xml_items <- function(nodes, names, convert, ctx) {
  kids <- cdx_xml_grandkids(nodes, ctx)
  unname(lapply(kids[names(kids) %in% names], convert, ctx = ctx))
}

# A number from the text of an xs:decimal, as jsonlite parses the number in
# CycloneDX JSON: an integer when it has no fraction. Any other text is kept
# as it is, for the reader to refuse.
cdx_xml_number <- function(text) {
  value <- cdx_xml_trim(text)
  if (grepl("^[+-]?[0-9]+$", value)) {
    return(spdx_integer_value(value))
  }
  if (grepl("^[+-]?([0-9]+[.][0-9]*|[.][0-9]+)$", value)) as.numeric(value) else text
}

# An element with its attributes and children, whose children named in
# `arrays` are containers: each becomes the array of its items named
# `arrays[[tag]]$item`, converted by `arrays[[tag]]$convert`. Every other
# child is converted by cdx_xml_field().
cdx_xml_with_arrays <- function(node, ctx, arrays) {
  kids <- cdx_xml_kids(node, ctx)
  tags <- names(kids)
  fields <- list()
  for (tag in unique(tags)) {
    nodes <- kids[tags == tag]
    a <- arrays[[tag]]
    fields[tag] <- list(
      if (is.null(a)) cdx_xml_field(tag, nodes, ctx) else cdx_xml_items(nodes, a$item, a$convert, ctx)
    )
  }
  cdx_xml_merge(cdx_xml_attrs(node, ctx), fields)
}

# A vulnerability, whose references, ratings, CWEs, advisories and affected
# targets are arrays, as are a target's versions. A rating's score and a CWE
# are numbers.
cdx_xml_vulnerability <- function(node, ctx) {
  rating <- function(node, ctx) {
    out <- cdx_xml_object(node, ctx)
    if (is_string(out[["score"]])) out[["score"]] <- cdx_xml_number(out[["score"]])
    out
  }
  target <- function(node, ctx) {
    cdx_xml_with_arrays(node, ctx, list(versions = list(item = "version", convert = cdx_xml_object)))
  }
  cdx_xml_with_arrays(node, ctx, list(
    references = list(item = "reference", convert = cdx_xml_object),
    ratings = list(item = "rating", convert = rating),
    cwes = list(item = "cwe", convert = function(node, ctx) cdx_xml_number(xml_own_text(node))),
    advisories = list(item = "advisory", convert = cdx_xml_object),
    affects = list(item = "target", convert = target)
  ))
}

# The value of the children named `tag`, given as the named list of nodes
# `nodes`. Containers become arrays of their items, gathered from every
# container of that name; `top` says whether these are children of <bom>,
# the only place dependencies and vulnerabilities get their JSON shape
# (compositions also hold elements named vulnerabilities, of another type).
# Tools are an array of tools in CycloneDX 1.4, and {components, services}
# from 1.5. Another element repeated becomes an array.
cdx_xml_field <- function(tag, nodes, ctx, top = FALSE) {
  if (top && tag == "dependencies") {
    return(cdx_xml_dependencies(nodes, ctx))
  }
  if (top && tag == "vulnerabilities") {
    return(cdx_xml_items(nodes, "vulnerability", cdx_xml_vulnerability, ctx))
  }
  items <- function(names, convert) cdx_xml_items(nodes, names, convert, ctx)
  one_or_many <- function(convert) {
    values <- unname(lapply(nodes, convert, ctx = ctx))
    if (length(values) == 1L) values[[1L]] else values
  }
  switch(tag,
    components = items("component", cdx_xml_object),
    services = items("service", cdx_xml_object),
    hashes = items("hash", cdx_xml_text_item("content", trim = TRUE)),
    licenses = items(c("license", "expression"), cdx_xml_license),
    externalReferences = items("reference", cdx_xml_object),
    properties = items("property", cdx_xml_text_item("value")),
    authors = items("author", cdx_xml_object),
    tools = {
      kids <- cdx_xml_grandkids(nodes, ctx)
      if (any(names(kids) == "tool")) {
        unname(lapply(kids[names(kids) == "tool"], cdx_xml_object, ctx = ctx))
      } else {
        cdx_xml_fields(kids, ctx)
      }
    },
    supplier = , manufacturer = , manufacture = , provider = , organization = one_or_many(cdx_xml_org),
    one_or_many(function(node, ctx) cdx_xml_value(node, ctx, tag))
  )
}

# The children of an element, a named list of nodes, as a named list of
# values by local name.
cdx_xml_fields <- function(kids, ctx, top = FALSE) {
  tags <- names(kids)
  out <- list()
  for (tag in unique(tags)) {
    out[tag] <- list(cdx_xml_field(tag, kids[tags == tag], ctx, top))
  }
  out
}

#' Convert CycloneDX XML to the CycloneDX JSON model
#'
#' Only elements in the document's CycloneDX namespace (the root's) are read,
#' with only the attributes the CycloneDX XSDs declare on them
#' (`cdx_xml_declared_attrs`); elements of any other namespace are left out,
#' with everything inside them, and so is every other attribute. Values keep
#' their whitespace, except those of a token type (`cdx_xml_token_text`,
#' `cdx_xml_token_attrs`).
#'
#' These follow the CycloneDX JSON model exactly: components and services;
#' hashes (`{alg, content}`); licenses (`{license: {...}}` or
#' `{expression}`); externalReferences; properties (`{name, value}`);
#' authors; the top-level dependencies (`{ref, dependsOn, provides}`, with
#' nested dependencies lifted into entries of their own); the top-level
#' vulnerabilities, whose references, ratings, cwes, advisories and affects
#' (`[{ref, versions}]`) are arrays; tools (an array in 1.4,
#' `{components, services}` from 1.5); and organizational entities, whose
#' `url` and `contact` are arrays. Attributes become fields, and text-only
#' elements strings. `bomFormat` and `specVersion`, which XML carries in the
#' namespace, are added, and the `version` attribute, a rating's score and a
#' CWE are numbers.
#'
#' Every other element is converted generically: its attributes and children
#' become a named list, and repeated children an array. So lifecycles,
#' pedigree ancestors, compositions and the like keep their XML nesting
#' (`{lifecycle: {phase}}` where JSON has `[{phase}]`).
#'
#' @param root The `<bom>` element.
#' @return A named list.
#' @noRd
cdx_xml_model <- function(root) {
  ns <- xml_ns_map(root)
  uri <- xml2::xml_find_chr(root, "string(namespace-uri(.))")
  ctx <- list(ns = ns, prefixes = names(ns)[ns == uri])
  doc <- c(
    list(bomFormat = "CycloneDX", specVersion = substring(uri, nchar(cdx_xml_ns) + 1L)),
    cdx_xml_attrs(root, ctx),
    cdx_xml_fields(cdx_xml_kids(root, ctx), ctx, top = TRUE)
  )
  if (is_string(doc[["version"]])) {
    version <- spdx_integer_value(doc[["version"]])
    if (!is.na(version)) doc[["version"]] <- version
  }
  doc
}

# The attributes the bundled SWID XSD declares on each element, keyed as
# cdx_xml_declared_attrs is. Meta, and SoftwareMeta which extends it, also
# admit any other attribute, of any namespace or none
# (`<xs:anyAttribute processContents="lax">`), so an undeclared one such as
# purl would pass the schema there; only these are read. A test recomputes
# the table from the XSD.
swid_declared_attrs <- list(
  Directory = c("key", "location", "name", "root"),
  Entity = c("name", "regid", "role", "thumbprint"),
  Evidence = c("date", "deviceId"),
  File = c("key", "location", "name", "root", "size", "version"),
  Link = c("artifact", "href", "media", "ownership", "rel", "type", "use"),
  Process = c("name", "pid"),
  Resource = "type",
  SoftwareIdentity = c(
    "corpus", "media", "name", "patch", "supplemental", "tagId", "tagVersion",
    "version", "versionScheme"
  ),
  `SoftwareIdentity/Meta` = c(
    "activationStatus", "channelType", "colloquialVersion", "description",
    "edition", "entitlementDataRequired", "entitlementKey", "generator",
    "persistentId", "product", "productFamily", "revision", "summary",
    "unspscCode", "unspscVersion"
  )
)
swid_attr_split <- xml_split_names(swid_declared_attrs)

# The declared attributes whose type derives from xs:token: role is
# xs:NMTOKENS, rel and versionScheme are xs:NMTOKEN, and ownership and use
# restrict xs:NMTOKEN. They are trimmed as CycloneDX tokens are; every other
# value keeps its whitespace. A test recomputes these too.
swid_token_attrs <- c("ownership", "rel", "role", "use", "versionScheme")

# A SWID element's attributes as a named character vector: those the XSD
# declares on it, xml:lang, and sbom's own (from swid_sbom_ns, whose
# prefixes in the map `ns` are `ext`) under keys that start with "sbom:", so
# that they never stand in for a standard attribute. Any other attribute is
# left out. Declared attributes of a token type are trimmed.
swid_attrs <- function(node, ns, ext) {
  attrs <- xml2::xml_attrs(node, ns)
  keys <- names(attrs)
  colon <- regexpr(":", keys, fixed = TRUE)
  prefix <- ifelse(colon > 0L, substr(keys, 1L, colon - 1L), "")
  sbom <- colon > 0L & prefix %in% ext
  keys[sbom] <- paste0("sbom:", substring(keys[sbom], colon[sbom] + 1L))
  declared <- colon < 0L & keys %in% xml_declared_attrs(node, swid_declared_attrs, swid_attr_split)
  token <- declared & keys %in% swid_token_attrs
  if (any(token)) attrs[token] <- cdx_xml_trim(attrs[token])
  keep <- declared | sbom | keys == "xml:lang"
  stats::setNames(unname(attrs[keep]), keys[keep])
}

#' Read a SWID tag into a list
#'
#' Only Entity, Link and Meta elements in the ISO 19770-2:2015 namespace are
#' read. Their standard attributes are those the SWID XSD declares on them
#' (`swid_declared_attrs`), plus `xml:lang`; sbom's own attributes are read
#' from its namespace under keys such as `"sbom:purl"`. Values keep their
#' whitespace, except those of a token type (`swid_token_attrs`).
#'
#' @param root The `<SoftwareIdentity>` element.
#' @return `list(tag, entities, links, meta)`: the SoftwareIdentity
#'   attributes as a named character vector, and one such vector for each
#'   Entity, Link and Meta element.
#' @noRd
swid_model <- function(root) {
  ns <- xml_ns_map(root)
  ext <- names(ns)[ns == swid_sbom_ns]
  kids <- xml_kids_in(root, ns, names(ns)[ns == swid_iso_ns])
  each <- function(tag) unname(lapply(kids[names(kids) == tag], swid_attrs, ns = ns, ext = ext))
  list(
    tag = swid_attrs(root, ns, ext),
    entities = each("Entity"),
    links = each("Link"),
    meta = each("Meta")
  )
}
