# Downloads the CycloneDX and SPDX schemas bundled under inst/schemas/.
# Run from the package root. This is the only place that touches the network.
cdx_tag <- "1.7.2"
cdx_base <- sprintf("https://raw.githubusercontent.com/CycloneDX/specification/%s/schema/", cdx_tag)
spdx_tag <- "v2.3"
spdx_base <- sprintf("https://raw.githubusercontent.com/spdx/spdx-spec/%s/schemas/", spdx_tag)

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

dest <- "inst/schemas/spdx/spdx-2.3.schema.json"
url <- paste0(spdx_base, "spdx-schema.json")
fetch(url, dest)
rows[[length(rows) + 1L]] <- data.frame(
  file = "spdx/spdx-2.3.schema.json", source_url = url, tag = spdx_tag,
  sha256 = cli::hash_file_sha256(dest), modified = FALSE
)

manifest <- do.call(rbind, rows)
utils::write.csv(manifest, "inst/schemas/MANIFEST.csv", row.names = FALSE, quote = FALSE)
