# SPDX tag-value writer, following R Observatory's tag order and `## ...`
# section comments. Free-text fields are wrapped in <text>...</text>, which
# cannot be escaped, so a literal </text> inside one is removed.
#
# The document is gathered as entries, a tag and a value each, and written as
# lines in one pass at the end: a regular expression run once a line, or
# lines appended one package at a time, took most of a minute for a large
# SBOM.

# `s` wrapped in `<text>` tags for tag-value, with any `</text>` inside
# removed so the value cannot close early.
tv_text <- function(s) {
  by_encoding(s, function(s) {
    # Removing a closer can join its neighbors into a new one, so repeat.
    while (any(hit <- !is.na(s) & grepl("</text>", s, fixed = TRUE))) {
      s[hit] <- gsub("</text>", "", s[hit], fixed = TRUE)
    }
    paste0("<text>", s, "</text>")
  })
}

# The lines of entries: `tag: value`, the value wrapped in <text> where
# `wrap` is TRUE, and the value alone, as a line of its own, where the tag
# is NA. Tag-value cannot hold a newline in a plain tag, so it becomes a
# space. A plain value that starts with <text>, after any white space, would
# open a text block that runs to the next closer, swallowing the lines
# between, so it is wrapped too.
tv_lines <- function(tag, value, wrap) {
  wrap <- wrap | (!is.na(tag) & grepl("^[[:space:]]*<text>", value, useBytes = TRUE))
  plain <- !is.na(tag) & !wrap
  value[plain] <- by_encoding(value[plain], function(v) gsub("[[:space:]]*[\r\n]+[[:space:]]*", " ", v))
  value[wrap] <- tv_text(value[wrap])
  ifelse(is.na(tag), value, paste0(tag, ": ", value))
}

# Whether a value makes a line: a single value that is not missing.
tv_has <- function(value) {
  !is.null(value) && length(value) == 1L && !is.na(value)
}

# Entries from parallel tags, values (a list, with NULL or NA for none) and
# wrap flags, as list(tag, value, wrap), leaving out those without a value.
# A tag of NA is a line of its own.
tv_entries <- function(tag, value, wrap = rep(FALSE, length(tag))) {
  keep <- vapply(value, tv_has, NA)
  list(tag = tag[keep], value = as.character(unlist(value[keep])), wrap = wrap[keep])
}

# The entries of several lists of entries, in order.
tv_join <- function(parts) {
  list(
    tag = unlist(lapply(parts, `[[`, "tag")),
    value = unlist(lapply(parts, `[[`, "value")),
    wrap = unlist(lapply(parts, `[[`, "wrap"))
  )
}

tv_package_tags <- c(
  name = "PackageName", SPDXID = "SPDXID", versionInfo = "PackageVersion",
  packageFileName = "PackageFileName", supplier = "PackageSupplier",
  originator = "PackageOriginator", downloadLocation = "PackageDownloadLocation"
)

# The tag-value entries of the SPDX package list element `p` at spec
# `version`, with its checksums and external references as lines.
tv_package_entries <- function(p, version = "2.3") {
  checksums <- lapply(p$checksums, function(cs) paste0(cs$algorithm, ": ", cs$checksumValue))
  refs <- do.call(c, lapply(p$externalRefs, function(ref) {
    category <- ref$referenceCategory
    # SPDX 2.2 spells it PACKAGE_MANAGER in JSON, YAML and XML, which its
    # schema requires, but PACKAGE-MANAGER in tag-value.
    if (version == "2.2" && identical(category, "PACKAGE_MANAGER")) {
      category <- "PACKAGE-MANAGER"
    }
    list(paste(category, ref$referenceType, ref$referenceLocator), ref$comment)
  }))
  n_refs <- length(p$externalRefs)
  tv_entries(
    tag = c(
      NA, NA, unname(tv_package_tags), "FilesAnalyzed",
      rep("PackageChecksum", length(checksums)),
      "PackageHomePage", "PackageSourceInfo", "PackageLicenseConcluded",
      "PackageLicenseDeclared", "PackageLicenseComments", "PackageCopyrightText",
      "PackageSummary", "PackageComment", rep(c("ExternalRef", "ExternalRefComment"), n_refs),
      "PrimaryPackagePurpose"
    ),
    value = c(
      list("", "## Package Information"),
      lapply(names(tv_package_tags), function(key) p[[key]]),
      list(if (!is.null(p$filesAnalyzed)) {
        if (isTRUE(p$filesAnalyzed)) "true" else "false"
      }),
      checksums,
      list(
        p$homepage, p$sourceInfo, p$licenseConcluded, p$licenseDeclared,
        p$licenseComments, p$copyrightText, p$summary, p$comment
      ),
      if (n_refs > 0L) refs,
      list(p$primaryPackagePurpose)
    ),
    wrap = c(
      rep(FALSE, 10L + length(checksums)),
      FALSE, TRUE, FALSE, FALSE, TRUE, FALSE, TRUE, TRUE,
      rep(c(FALSE, TRUE), n_refs),
      FALSE
    )
  )
}

# The SPDX tag-value text of `x` at spec `version`: header, packages,
# extracted licenses and relationships, ending in a newline.
spdx_tv <- function(x, version = "2.3") {
  doc <- spdx_document(x, version)
  creators <- doc$creationInfo$creators
  head <- tv_entries(
    tag = c(
      "SPDXVersion", "DataLicense", "SPDXID", "DocumentName", "DocumentNamespace",
      "DocumentComment", NA, NA, rep("Creator", length(creators)), "Created",
      "CreatorComment"
    ),
    value = c(
      list(
        doc$spdxVersion, doc$dataLicense, doc$SPDXID, doc$name, doc$documentNamespace,
        doc$comment, "", "## Creation Information"
      ),
      creators,
      list(doc$creationInfo$created, doc$creationInfo$comment)
    ),
    wrap = c(rep(FALSE, 5L), TRUE, FALSE, FALSE, rep(FALSE, length(creators)), FALSE, TRUE)
  )
  packages <- lapply(doc$packages, tv_package_entries, version = version)
  extracted <- doc$hasExtractedLicensingInfos
  licenses <- lapply(seq_along(extracted), function(k) {
    tv_entries(
      tag = c(NA, "LicenseID", "ExtractedText", "LicenseName"),
      value = list(
        if (k > 1L) "", extracted[[k]]$licenseId, extracted[[k]]$extractedText,
        extracted[[k]]$name
      ),
      wrap = c(FALSE, FALSE, TRUE, FALSE)
    )
  })
  relationships <- doc$relationships
  stated <- vapply(relationships, function(r) {
    paste(r$spdxElementId, r$relationshipType, r$relatedSpdxElement)
  }, "")
  comments <- lapply(relationships, function(r) r$comment)
  related <- tv_entries(
    tag = rep(c("Relationship", "RelationshipComment"), length(relationships)),
    value = c(rbind(as.list(stated), comments)),
    wrap = rep(c(FALSE, TRUE), length(relationships))
  )
  entries <- tv_join(c(
    list(head),
    packages,
    if (length(extracted) > 0L) list(tv_entries(c(NA, NA), list("", "## License Information"))),
    licenses,
    list(tv_entries(c(NA, NA), list("", "## Relationships")), related)
  ))
  lines <- tv_lines(entries$tag, entries$value, entries$wrap)
  enc2utf8(paste0(paste(lines, collapse = "\n"), "\n"))
}
