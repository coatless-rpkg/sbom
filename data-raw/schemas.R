# Downloads the CycloneDX and SPDX schemas bundled under inst/schemas/.
# Run from the package root. This is the only place that touches the network.
cdx_tag <- "1.7.2"
cdx_base <- sprintf("https://raw.githubusercontent.com/CycloneDX/specification/%s/schema/", cdx_tag)

cdx_files <- c(
  sprintf("bom-1.%d.schema.json", 4:7),
  sprintf("bom-1.%d.xsd", 4:7),
  "spdx.schema.json", "spdx.xsd", "jsf-0.82.schema.json", "cryptography-defs.schema.json"
)

dir.create("inst/schemas/cyclonedx", recursive = TRUE, showWarnings = FALSE)
dir.create("inst/schemas/spdx", recursive = TRUE, showWarnings = FALSE)

fetch <- function(url, dest) {
  status <- utils::download.file(url, dest, mode = "wb", quiet = TRUE)
  if (status != 0) stop("Download failed: ", url)
}

rows <- list()
for (f in cdx_files) {
  dest <- file.path("inst/schemas/cyclonedx", f)
  url <- paste0(cdx_base, f)
  fetch(url, dest)
  modified <- FALSE
  if (grepl("\\.xsd$", f) && grepl("^bom-", f)) {
    x <- readLines(dest, encoding = "UTF-8", warn = FALSE)
    imports <- grep("<xs:import", x, value = TRUE)
    if (length(imports) != 1L || !grepl("http://cyclonedx.org/schema/spdx", imports)) {
      stop("Unexpected imports in ", f, ": ", paste(imports, collapse = " | "))
    }
    y <- sub('schemaLocation="http://cyclonedx.org/schema/spdx"', 'schemaLocation="spdx.xsd"', x, fixed = TRUE)
    modified <- !identical(x, y)
    writeLines(y, dest, useBytes = TRUE)
  }
  rows[[length(rows) + 1L]] <- data.frame(
    file = file.path("cyclonedx", f), source_url = url, tag = cdx_tag,
    sha256 = cli::hash_file_sha256(dest), modified = modified
  )
}

spdx_schemas <- list(
  list(version = "2.3", tag = "v2.3"),
  list(version = "2.2", tag = "v2.2.2")
)
for (s in spdx_schemas) {
  file <- sprintf("spdx/spdx-%s.schema.json", s$version)
  dest <- file.path("inst/schemas", file)
  url <- sprintf("https://raw.githubusercontent.com/spdx/spdx-spec/%s/schemas/spdx-schema.json", s$tag)
  fetch(url, dest)
  rows[[length(rows) + 1L]] <- data.frame(
    file = file, source_url = url, tag = s$tag,
    sha256 = cli::hash_file_sha256(dest), modified = FALSE
  )
}

# SPDX 3 publishes its JSON schema on spdx.org, generated from the
# spdx/spdx-3-model repository; it is one self-contained file.
spdx3_version <- "3.0.1"
spdx3_file <- sprintf("spdx/spdx-%s.schema.json", spdx3_version)
spdx3_url <- sprintf("https://spdx.org/schema/%s/spdx-json-schema.json", spdx3_version)
spdx3_dest <- file.path("inst/schemas", spdx3_file)
fetch(spdx3_url, spdx3_dest)
rows[[length(rows) + 1L]] <- data.frame(
  file = spdx3_file, source_url = spdx3_url, tag = spdx3_version,
  sha256 = cli::hash_file_sha256(spdx3_dest), modified = FALSE
)

# SWID tags (ISO/IEC 19770-2:2015). The ISO schema imports the XML Signature
# and XML namespace schemas by URL; those imports are rewritten to the local
# copies, so validation needs no network. There must stay exactly one import
# per namespace, or libxml2 warns that it is skipping one.
dir.create("inst/schemas/swid", recursive = TRUE, showWarnings = FALSE)
swid_files <- list(
  list(
    file = "swid-2015.xsd",
    url = "https://standards.iso.org/iso/19770/-2/2015-current/schema.xsd",
    tag = "2015-current"
  ),
  list(
    file = "xmldsig-core-schema.xsd",
    url = "https://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd", tag = ""
  ),
  list(file = "xml.xsd", url = "https://www.w3.org/2001/xml.xsd", tag = "")
)
for (s in swid_files) {
  file <- file.path("swid", s$file)
  dest <- file.path("inst/schemas", file)
  fetch(s$url, dest)
  modified <- FALSE
  if (s$file == "swid-2015.xsd") {
    # Work on bytes, so the file's CRLF line endings and notice are kept.
    x <- rawToChar(readBin(dest, "raw", file.size(dest)))
    Encoding(x) <- "UTF-8"
    y <- x
    for (loc in c(
      "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd",
      "http://www.w3.org/2001/xml.xsd"
    )) {
      if (lengths(regmatches(y, gregexpr(loc, y, fixed = TRUE))) != 1L) {
        stop("Expected exactly one import of ", loc, " in ", s$file)
      }
      y <- sub(loc, basename(loc), y, fixed = TRUE)
    }
    imports <- regmatches(y, gregexpr("namespace=\"[^\"]*\"\\s+schemaLocation=\"[^\"]*\"", y))[[1]]
    namespaces <- sub("^namespace=\"([^\"]*)\".*$", "\\1", imports)
    if (length(imports) != 2L || anyDuplicated(namespaces)) {
      stop("Expected exactly one import per namespace in ", s$file)
    }
    if (!grepl("for the purpose of implementing the", y, fixed = TRUE)) {
      stop("The ISO copyright notice is missing from ", s$file)
    }
    modified <- !identical(x, y)
    writeBin(charToRaw(y), dest)
  }
  rows[[length(rows) + 1L]] <- data.frame(
    file = file, source_url = s$url, tag = s$tag,
    sha256 = cli::hash_file_sha256(dest), modified = modified
  )
}

manifest <- do.call(rbind, rows)
utils::write.csv(manifest, "inst/schemas/MANIFEST.csv", row.names = FALSE, quote = FALSE)
