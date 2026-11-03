# SPDX tag-value writer, following R Observatory's tag order and `## ...`
# section comments. Free-text fields are wrapped in <text>...</text>, which
# cannot be escaped, so a literal </text> inside one is removed.

tv_text <- function(s) {
  # Removing a closer can join its neighbours into a new one, so repeat.
  while (grepl("</text>", s, fixed = TRUE)) {
    s <- gsub("</text>", "", s, fixed = TRUE)
  }
  paste0("<text>", s, "</text>")
}

# One `Tag: value` line, or nothing when the value is missing. Tag-value cannot
# hold a newline in a plain tag, so it becomes a space.
tv_line <- function(tag, value, wrap = FALSE) {
  if (is.null(value) || length(value) != 1L || is.na(value)) {
    return(character())
  }
  value <- if (wrap) tv_text(value) else gsub("[[:space:]]*[\r\n]+[[:space:]]*", " ", value)
  paste0(tag, ": ", value)
}

tv_package_tags <- c(
  name = "PackageName", SPDXID = "SPDXID", versionInfo = "PackageVersion",
  packageFileName = "PackageFileName", supplier = "PackageSupplier",
  originator = "PackageOriginator", downloadLocation = "PackageDownloadLocation"
)

tv_package <- function(p) {
  lines <- c("", "## Package Information")
  for (key in names(tv_package_tags)) {
    lines <- c(lines, tv_line(tv_package_tags[[key]], p[[key]]))
  }
  lines <- c(lines, tv_line("FilesAnalyzed", if (!is.null(p$filesAnalyzed)) {
    if (isTRUE(p$filesAnalyzed)) "true" else "false"
  }))
  for (cs in p$checksums) {
    lines <- c(lines, tv_line("PackageChecksum", paste0(cs$algorithm, ": ", cs$checksumValue)))
  }
  lines <- c(
    lines,
    tv_line("PackageHomePage", p$homepage),
    tv_line("PackageSourceInfo", p$sourceInfo, wrap = TRUE),
    tv_line("PackageLicenseConcluded", p$licenseConcluded),
    tv_line("PackageLicenseDeclared", p$licenseDeclared),
    tv_line("PackageLicenseComments", p$licenseComments, wrap = TRUE),
    tv_line("PackageCopyrightText", p$copyrightText),
    tv_line("PackageComment", p$comment, wrap = TRUE)
  )
  for (ref in p$externalRefs) {
    lines <- c(
      lines,
      tv_line("ExternalRef", paste(ref$referenceCategory, ref$referenceType, ref$referenceLocator)),
      tv_line("ExternalRefComment", ref$comment, wrap = TRUE)
    )
  }
  c(lines, tv_line("PrimaryPackagePurpose", p$primaryPackagePurpose))
}

spdx_tv <- function(x, version = "2.3") {
  doc <- spdx_document(x, version)
  lines <- c(
    tv_line("SPDXVersion", doc$spdxVersion),
    tv_line("DataLicense", doc$dataLicense),
    tv_line("SPDXID", doc$SPDXID),
    tv_line("DocumentName", doc$name),
    tv_line("DocumentNamespace", doc$documentNamespace),
    tv_line("DocumentComment", doc$comment, wrap = TRUE),
    "",
    "## Creation Information"
  )
  for (creator in doc$creationInfo$creators) {
    lines <- c(lines, tv_line("Creator", creator))
  }
  lines <- c(
    lines,
    tv_line("Created", doc$creationInfo$created),
    tv_line("CreatorComment", doc$creationInfo$comment, wrap = TRUE)
  )
  for (p in doc$packages) lines <- c(lines, tv_package(p))
  lines <- c(lines, "", "## Relationships")
  for (r in doc$relationships) {
    lines <- c(
      lines,
      tv_line("Relationship", paste(r$spdxElementId, r$relationshipType, r$relatedSpdxElement)),
      tv_line("RelationshipComment", r$comment, wrap = TRUE)
    )
  }
  enc2utf8(paste0(paste(lines, collapse = "\n"), "\n"))
}
