# CycloneDX XML writer. Walks the list from `cdx_document()` in order, so the
# element sequence follows the XSD.

xml_text_child <- function(parent, name, value) {
  xml2::xml_add_child(parent, name, enc2utf8(as.character(value)))
}

# An element whose scalar entries are children, except for `attrs`, which
# become XML attributes. Container entries are routed through `special`.
xml_element <- function(parent, name, item, attrs = character(), special = list()) {
  node <- xml2::xml_add_child(parent, name)
  for (a in intersect(attrs, names(item))) {
    xml2::xml_set_attr(node, a, enc2utf8(item[[a]]))
  }
  for (key in setdiff(names(item), attrs)) {
    value <- item[[key]]
    if (key %in% names(special)) {
      special[[key]](node, value)
    } else {
      xml_text_child(node, key, value)
    }
  }
  node
}

xml_each <- function(parent, container, items, fn) {
  node <- xml2::xml_add_child(parent, container)
  for (item in items) fn(node, item)
  invisible(node)
}

xml_org <- function(parent, name, org) {
  node <- xml2::xml_add_child(parent, name)
  xml_text_child(node, "name", org$name)
  for (u in org$url) xml_text_child(node, "url", u)
  invisible(node)
}

xml_license <- function(node, item) {
  if (!is.null(item$expression)) {
    xml_text_child(node, "expression", item$expression)
  } else {
    lic <- xml2::xml_add_child(node, "license")
    xml_text_child(lic, "name", item$license$name)
  }
}

xml_reference <- function(node, ref) {
  r <- xml2::xml_add_child(node, "reference")
  xml2::xml_set_attr(r, "type", ref$type)
  xml_text_child(r, "url", ref$url)
  if (!is.null(ref$comment)) xml_text_child(r, "comment", ref$comment)
}

xml_component <- function(parent, comp, tag = "component") {
  xml_element(parent, tag, comp, attrs = c("type", "bom-ref"), special = list(
    supplier = function(node, v) xml_org(node, "supplier", v),
    hashes = function(node, v) {
      xml_each(node, "hashes", v, function(p, h) {
        n <- xml_text_child(p, "hash", h$content)
        xml2::xml_set_attr(n, "alg", h$alg)
      })
    },
    licenses = function(node, v) xml_each(node, "licenses", v, xml_license),
    externalReferences = function(node, v) {
      xml_each(node, "externalReferences", v, xml_reference)
    },
    properties = function(node, v) xml_properties(node, v),
    components = function(node, v) {
      xml_each(node, "components", v, function(p, c) xml_component(p, c))
    }
  ))
}

xml_properties <- function(node, props) {
  xml_each(node, "properties", props, function(p, prop) {
    n <- xml_text_child(p, "property", prop$value)
    xml2::xml_set_attr(n, "name", enc2utf8(prop$name))
  })
}

xml_metadata <- function(bom, meta) {
  node <- xml2::xml_add_child(bom, "metadata")
  xml_text_child(node, "timestamp", meta$timestamp)
  if (!is.null(meta$tools$components)) {
    tools <- xml2::xml_add_child(node, "tools")
    xml_each(tools, "components", meta$tools$components, xml_component)
  } else {
    xml_each(node, "tools", meta$tools, function(p, t) xml_element(p, "tool", t))
  }
  if (!is.null(meta$authors)) {
    xml_each(node, "authors", meta$authors, function(p, a) {
      xml_element(p, "author", a)
    })
  }
  xml_component(node, meta$component)
  if (!is.null(meta$manufacturer)) {
    xml_element(node, "manufacturer", meta$manufacturer)
  }
  if (!is.null(meta$properties)) xml_properties(node, meta$properties)
  invisible(node)
}

xml_dependency <- function(parent, dep) {
  node <- xml2::xml_add_child(parent, "dependency")
  xml2::xml_set_attr(node, "ref", enc2utf8(dep$ref))
  for (target in dep$dependsOn) {
    child <- xml2::xml_add_child(node, "dependency")
    xml2::xml_set_attr(child, "ref", enc2utf8(target))
  }
  invisible(node)
}

xml_vulnerability <- function(parent, v) {
  xml_source <- function(node, s) xml_element(node, "source", s)
  xml_element(parent, "vulnerability", v, attrs = "bom-ref", special = list(
    source = xml_source,
    references = function(node, refs) {
      xml_each(node, "references", refs, function(p, r) {
        xml_element(p, "reference", r, special = list(source = xml_source))
      })
    },
    ratings = function(node, rs) xml_each(node, "ratings", rs, function(p, r) xml_element(p, "rating", r)),
    advisories = function(node, as) {
      xml_each(node, "advisories", as, function(p, a) xml_element(p, "advisory", a))
    },
    affects = function(node, as) xml_each(node, "affects", as, function(p, a) xml_element(p, "target", a))
  ))
}

cdx_xml <- function(x, version = "1.6") {
  doc <- cdx_document(x, version)
  root <- xml2::xml_new_root("bom")
  xml2::xml_set_attr(root, "xmlns", sprintf("http://cyclonedx.org/schema/bom/%s", version))
  xml2::xml_set_attr(root, "serialNumber", doc$serialNumber)
  xml2::xml_set_attr(root, "version", as.character(doc$version))
  xml_metadata(root, doc$metadata)
  xml_each(root, "components", doc$components, function(p, c) xml_component(p, c))
  xml_each(root, "dependencies", doc$dependencies, xml_dependency)
  if (!is.null(doc$vulnerabilities)) {
    xml_each(root, "vulnerabilities", doc$vulnerabilities, xml_vulnerability)
  }
  out <- as.character(root, options = "format")
  enc2utf8(paste0(sub("\n+$", "", out), "\n"))
}
