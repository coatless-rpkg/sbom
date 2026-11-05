# Precomputes inst/extdata/licenses.{csv,dcf}: SPDX expressions from R's own license analysis,
# for every License value on CRAN and Bioconductor. Needs network; run from the package root.
#
# The rule is R Observatory's (_obs_sbom_spdx): an expression is kept only when every alternative maps
# to SPDX, no alternative is `file LICENSE` alone, and no `+ file LICENSE` is attached to a license
# that is not a template (extensible in R's license db).

analyze <- utils::getFromNamespace("analyze_license", "tools")
license_db <- utils::getFromNamespace("R_license_db", "tools")()

bioc <- "https://bioconductor.org/packages/release/"
views <- c(
  paste0(bioc, "bioc/VIEWS"),
  paste0(bioc, "data/annotation/VIEWS"),
  paste0(bioc, "data/experiment/VIEWS"),
  paste0(bioc, "workflows/VIEWS")
)

normalize <- function(x) gsub("\\s+", " ", trimws(x))

specs <- c(
  tools::CRAN_package_db()$License,
  unlist(lapply(views, function(u) {
    con <- url(u)
    on.exit(close(con))
    read.dcf(con, fields = "License")[, "License"]
  })),
  "GPL-2 | GPL-3"
)
specs <- normalize(specs[!is.na(specs)])
specs <- sort(unique(specs[nzchar(specs)]), method = "radix")

spdx_for <- function(spec) {
  a <- analyze(spec)
  if (!is.character(a$spdx) || length(a$spdx) != 1L || is.na(a$spdx) || !nzchar(a$spdx)) {
    return(NA_character_)
  }
  ext <- a$extensions
  for (k in seq_along(a$components)) {
    comp <- a$components[k]
    if (grepl("^file +LICEN[CS]E$", comp)) return(NA_character_)
    if (grepl("[+] *file +LICEN[CS]E", comp)) {
      i <- if (is.data.frame(ext)) match(comp, ext$components) else NA_integer_
      if (is.na(i) || !isTRUE(ext$extensible[i])) return(NA_character_)
    }
    for (e in a$expansions[[k]]) {
      label <- trimws(sub("[+] *file +LICEN[CS]E.*$", "", e))
      j <- match(label, license_db[, "Labels"])
      if (is.na(j) || is.na(license_db[j, "SPDX"])) return(NA_character_)
    }
  }
  a$spdx
}

tbl <- data.frame(
  spec = specs,
  spdx = vapply(specs, spdx_for, character(1), USE.NAMES = FALSE)
)
# SPDX ids that the SPDX License List has deprecated, mapped to their replacements. R's own
# license database still returns the old id. Applied to every id in every expression.
spdx_remap <- c("BSD-2-Clause-FreeBSD" = "BSD-2-Clause-Views")
for (old in names(spdx_remap)) {
  pattern <- paste0("(?<![A-Za-z0-9.-])", gsub(".", "[.]", old, fixed = TRUE), "(?![A-Za-z0-9.+-])")
  tbl$spdx <- gsub(pattern, spdx_remap[[old]], tbl$spdx, perl = TRUE)
}
utils::write.csv(tbl, "inst/extdata/licenses.csv", row.names = FALSE, na = "", fileEncoding = "UTF-8")

writeLines(c(
  paste("Built-with:", as.character(getRversion())),
  paste("Date:", format(Sys.Date())),
  paste("Sources: tools::CRAN_package_db(); Bioconductor release VIEWS (bioc, annotation, experiment, workflows); R itself"),
  paste("Rows:", nrow(tbl))
), "inst/extdata/licenses.dcf", useBytes = TRUE)
