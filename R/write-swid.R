# SWID tag (ISO/IEC 19770-2:2015) writer. Follows R Observatory's tag, with
# the differences in spec section 6a: the tag creator is the user's
# organization, `tagId` is the regid's authority followed by the root's ref,
# and the extension attributes are in the `sbom` namespace. As in R
# Observatory, `tagVersion` is the date of the timestamp.

swid_iso_ns <- "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
swid_sbom_ns <- "https://cran.r-project.org/package=sbom"
swid_placeholder_regid <- "http://invalid.unavailable"

swid_set <- function(x) {
  length(x) == 1L && !is.na(x) && nzchar(x)
}

# The regid without leading or trailing white space, or NA when there is
# none. The builders store it trimmed (check_regid()), but an SBOM read or
# made otherwise may carry it padded.
swid_regid <- function(regid) {
  regid <- if (length(regid) == 1L) trimws(as.character(regid)) else NA_character_
  if (swid_set(regid)) regid else NA_character_
}

# The regid without its scheme or trailing "/": "https://example.org" gives
# "example.org". NA when there is no regid.
swid_authority <- function(regid) {
  if (!swid_set(regid)) {
    return(NA_character_)
  }
  out <- sub("/+$", "", sub("^[A-Za-z][A-Za-z0-9+.-]*://", "", regid))
  if (nzchar(out)) out else NA_character_
}

# A component's tag id: "<authority>/<ref>", or the ref alone without a regid
# (which the regid-missing issue reports).
swid_tag_id <- function(ref, authority) {
  if (is.na(authority)) ref else paste0(authority, "/", ref)
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

# The notes of a tag. A SWID tag has no place for advisories, so the
# sentences that say they are listed (R Observatory's two and the note on
# where the data came from) are taken out wherever they are, a whole note or
# inside one into which a read document joined its notes. When the SBOM
# lists advisories (`listed`), or the notes already said that a tag has no
# place for them, that sentence is given once, where the first sentence
# taken out was, or at the end. The advisory issues of `issues`, which speak
# of what the file lists, are left out too when advisories are listed.
swid_advisory_notes <- function(notes, issues, listed) {
  if (listed) {
    notes <- notes[!notes %in% issues$message[startsWith(as.character(issues$code), "advisories-")]]
  }
  said <- any(grepl(advisory_notes$swid, notes, fixed = TRUE))
  pattern <- paste(unlist(advisory_sentences[c("listed", "bioc", "provenance", "swid")]), collapse = "|")
  notes_without(notes, pattern, with = if (listed || said) advisory_notes$swid)
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
  meta <- x$metadata
  regid <- swid_regid(meta$regid)
  authority <- swid_authority(regid)
  xml2::xml_set_attr(doc, "tagId", enc2utf8(swid_tag_id(root$ref, authority)))
  # The UTC date as YYYYMMDD, so the version grows with each new tag.
  xml2::xml_set_attr(
    doc, "tagVersion", format(as.POSIXct(meta$timestamp), "%Y%m%d", tz = "UTC")
  )

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
    regid = if (!is.na(regid)) regid else swid_placeholder_regid,
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

  # The tag describes only the root, so its overrides' provenance goes here.
  notes <- swid_advisory_notes(
    c(document_notes(x, swid = TRUE), spdx_asserted_sentences(root)), x$issues,
    identical(advisories_status(x), "listed")
  )
  swid_node(doc, "Meta", c(
    generator = if (swid_set(meta$tool_version)) paste("sbom", meta$tool_version) else "sbom",
    product = root$name,
    description = if (length(notes) > 0L) paste(notes, collapse = " "),
    `sbom:purl` = root$purl, `sbom:license` = root$license_as_written,
    `sbom:systemRequirements` = root$system_requirements
  ))

  # A link needs its href; without one the link is left out.
  link <- function(attrs) if (swid_set(attrs[["href"]])) swid_node(doc, "Link", attrs)
  link(c(rel = "describedby", href = root$homepage))
  link(c(
    rel = "installationmedia", href = root$download_location,
    artifact = root$package_file_name, type = "application/gzip"
  ))
  link(c(rel = "related", href = root$vcs_url))
  # App files are not dependencies, so they get no link.
  deps <- comps[!comps$is_root & comps$type != "file" & !is_embedded_ref(comps$ref), , drop = FALSE]
  deps <- deps[order(deps$ref, method = "radix"), , drop = FALSE]
  for (i in seq_len(nrow(deps))) {
    d <- deps[i, ]
    link(c(
      rel = "requires", href = paste0("swid:", swid_tag_id(d$ref, authority)),
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
