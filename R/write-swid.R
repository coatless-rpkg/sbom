# SWID tag (ISO/IEC 19770-2:2015) writer. Follows R Observatory's tag, with
# the differences in spec section 6a: the tag creator is the user's
# organization, `tagId` is the root's ref, and the extension attributes are in
# the `sbom` namespace.

swid_iso_ns <- "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
swid_sbom_ns <- "https://cran.r-project.org/package=sbom"
swid_placeholder_regid <- "http://invalid.unavailable"

swid_set <- function(x) {
  length(x) == 1L && !is.na(x) && nzchar(x)
}

# Adds `node` as a child of `parent`, with the named attributes that are set.
swid_node <- function(parent, name, attrs) {
  node <- xml2::xml_add_child(parent, name)
  for (a in names(attrs)) {
    if (swid_set(attrs[[a]])) {
      xml2::xml_set_attr(node, a, enc2utf8(as.character(attrs[[a]])))
    }
  }
  invisible(node)
}

swid_tag <- function(x, version = "2015") {
  comps <- x$components
  root <- comps[comps$ref == x$metadata$root, , drop = FALSE][1, ]
  has_version <- swid_set(root$version)
  scheme <- if (has_version && grepl("^\\d+(\\.\\d+)*$", root$version)) {
    "multipartnumeric"
  } else {
    "unknown"
  }
  doc <- xml2::xml_new_root("SoftwareIdentity")
  xml2::xml_set_attr(doc, "xmlns", swid_iso_ns)
  xml2::xml_set_attr(doc, "xmlns:sbom", swid_sbom_ns)
  xml2::xml_set_attr(doc, "name", enc2utf8(root$name))
  if (has_version) {
    xml2::xml_set_attr(doc, "version", enc2utf8(root$version))
    xml2::xml_set_attr(doc, "versionScheme", scheme)
  }
  xml2::xml_set_attr(doc, "tagId", enc2utf8(root$ref))
  xml2::xml_set_attr(doc, "tagVersion", "1")

  meta <- x$metadata
  authors <- meta$author[!is.na(meta$author)]
  creator <- if (swid_set(meta$organization)) {
    meta$organization
  } else if (length(authors) > 0L) {
    authors[[1]]
  } else {
    "sbom"
  }
  swid_node(doc, "Entity", c(
    name = creator,
    regid = if (swid_set(meta$regid)) meta$regid else swid_placeholder_regid,
    role = "tagCreator"
  ))
  if (swid_set(root$supplier_name)) {
    swid_node(doc, "Entity", c(
      name = root$supplier_name, regid = root$supplier_url, role = "distributor"
    ))
  }
  if (swid_set(root$maintainer)) {
    swid_node(doc, "Entity", c(name = root$maintainer, role = "maintainer"))
  }

  notes <- document_notes(x)
  swid_node(doc, "Meta", c(
    generator = paste("sbom", meta$tool_version), product = root$name,
    description = if (length(notes) > 0L) paste(notes, collapse = " "),
    `sbom:purl` = root$purl, `sbom:license` = root$license_as_written
  ))

  # A link needs its href; without one the link is left out.
  link <- function(attrs) if (swid_set(attrs[["href"]])) swid_node(doc, "Link", attrs)
  link(c(rel = "describedby", href = root$homepage))
  link(c(
    rel = "installationmedia", href = root$download_location,
    artifact = root$package_file_name, type = "application/gzip"
  ))
  link(c(rel = "related", href = root$vcs_url))
  deps <- comps[!comps$is_root, , drop = FALSE]
  deps <- deps[order(deps$ref, method = "radix"), , drop = FALSE]
  for (i in seq_len(nrow(deps))) {
    d <- deps[i, ]
    link(c(
      rel = "requires", href = paste0("swid:", d$ref),
      use = if (identical(d$scope, "optional")) "optional" else "required",
      `sbom:name` = d$name, `sbom:version` = d$version,
      `sbom:versionIs` = if (identical(d$version_is, "minimum")) "minimum",
      `sbom:purl` = d$purl,
      `sbom:partOf` = if (identical(d$ecosystem, "base-r")) "R"
    ))
  }
  out <- as.character(doc, options = "format")
  enc2utf8(paste0(sub("\n+$", "", out), "\n"))
}
