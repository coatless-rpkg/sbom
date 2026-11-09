# The supported formats as a named list: each one's name, writer, file
# extension, versions, default version and media type.
format_registry <- function() {
  cdx_versions <- c("1.4", "1.5", "1.6", "1.7")
  list(
    `cyclonedx-json` = list(
      name = "CycloneDX JSON", writer = cdx_json, extension = ".cdx.json",
      versions = cdx_versions, default_version = "1.6",
      media_type = "application/vnd.cyclonedx+json", all = TRUE
    ),
    `cyclonedx-xml` = list(
      name = "CycloneDX XML", writer = cdx_xml, extension = ".cdx.xml",
      versions = cdx_versions, default_version = "1.6",
      media_type = "application/vnd.cyclonedx+xml", all = TRUE
    ),
    `spdx-json` = list(
      name = "SPDX JSON", writer = spdx_json,
      extension = ".spdx.json", versions = c("2.2", "2.3"),
      default_version = "2.3", media_type = "application/spdx+json",
      all = TRUE
    ),
    `spdx-yaml` = list(
      name = "SPDX YAML", writer = spdx_yaml,
      extension = ".spdx.yaml", versions = c("2.2", "2.3"),
      default_version = "2.3", media_type = "application/spdx+yaml",
      all = TRUE
    ),
    `spdx-xml` = list(
      name = "SPDX XML", writer = spdx_xml,
      extension = ".spdx.xml", versions = c("2.2", "2.3"),
      default_version = "2.3", media_type = "application/spdx+xml",
      all = TRUE
    ),
    `spdx-tv` = list(
      name = "SPDX tag-value", writer = spdx_tv,
      extension = ".spdx", versions = c("2.2", "2.3"),
      default_version = "2.3", media_type = "text/spdx",
      all = TRUE
    ),
    `spdx3-jsonld` = list(
      name = "SPDX 3 JSON-LD", writer = spdx3_jsonld,
      extension = ".spdx3.jsonld", versions = "3.0.1",
      default_version = "3.0.1", media_type = "application/spdx+json",
      all = TRUE
    ),
    swid = list(
      name = "SWID tag", writer = swid_tag, extension = ".swidtag",
      versions = "2015", default_version = "2015",
      media_type = "application/swid+xml", all = TRUE
    ),
    csv = list(
      name = "CSV inventory", writer = csv_file, extension = ".csv",
      versions = character(), default_version = NA_character_,
      media_type = "text/csv", all = FALSE
    )
  )
}

#' List the SBOM formats this package can write
#'
#' @return A data frame with one row per format and columns `format`
#'   (the value to pass to [write_sbom()]), `name`, `extension`, `versions`
#'   (comma-separated), `default_version` and `media_type`.
#' @export
#' @examples
#' sbom_formats()
sbom_formats <- function() {
  reg <- format_registry()
  data.frame(
    format = names(reg),
    name = vapply(reg, function(r) r$name, character(1)),
    extension = vapply(reg, function(r) r$extension, character(1)),
    versions = vapply(reg, function(r) paste(r$versions, collapse = ", "), character(1)),
    default_version = vapply(reg, function(r) as.character(r$default_version), character(1)),
    media_type = vapply(reg, function(r) r$media_type, character(1)),
    row.names = NULL,
    stringsAsFactors = FALSE
  )
}
