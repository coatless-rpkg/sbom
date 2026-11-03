# SPDX XML writer: the SPDX JSON document with its keys as elements under
# <Document>, as R Observatory writes it. A list is the same element repeated,
# and a logical is `true` or `false`. SPDX has no official XML schema.

spdx_xml_scalar <- function(v) {
  if (is.logical(v)) {
    return(if (isTRUE(v)) "true" else "false")
  }
  enc2utf8(as.character(v))
}

# Adds `value` under `parent` as the element `name`.
spdx_xml_add <- function(parent, name, value) {
  if (is.list(value) && is.null(names(value))) {
    for (item in value) spdx_xml_add(parent, name, item)
  } else if (is.list(value)) {
    node <- xml2::xml_add_child(parent, name)
    for (key in names(value)) spdx_xml_add(node, key, value[[key]])
  } else if (length(value) != 1L) {
    for (item in as.list(value)) spdx_xml_add(parent, name, item)
  } else {
    xml2::xml_add_child(parent, name, spdx_xml_scalar(value))
  }
  invisible(parent)
}

spdx_xml <- function(x, version = "2.3") {
  doc <- spdx_document(x, version)
  root <- xml2::xml_new_root("Document")
  for (key in names(doc)) spdx_xml_add(root, key, doc[[key]])
  out <- as.character(root, options = "format")
  enc2utf8(paste0(sub("\n+$", "", out), "\n"))
}
