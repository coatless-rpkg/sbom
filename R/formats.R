format_registry <- function() {
  cdx_versions <- c("1.4", "1.5", "1.6", "1.7")
  list(
    `cyclonedx-json` = list(
      name = "CycloneDX JSON", writer = cdx_json, extension = ".cdx.json",
      versions = cdx_versions, default_version = "1.6",
      media_type = "application/vnd.cyclonedx+json"
    ),
    `cyclonedx-xml` = list(
      name = "CycloneDX XML", writer = cdx_xml, extension = ".cdx.xml",
      versions = cdx_versions, default_version = "1.6",
      media_type = "application/vnd.cyclonedx+xml"
    ),
    `spdx-json` = list(
      name = "SPDX JSON", writer = function(x, version) spdx_json(x),
      extension = ".spdx.json", versions = "2.3", default_version = "2.3",
      media_type = "application/spdx+json"
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
    default_version = vapply(reg, function(r) r$default_version, character(1)),
    media_type = vapply(reg, function(r) r$media_type, character(1)),
    row.names = NULL,
    stringsAsFactors = FALSE
  )
}
