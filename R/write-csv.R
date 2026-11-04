# CSV component inventory: a spreadsheet view for compliance reviewers, not an
# SBOM standard. Built by hand so the bytes never pass through the native locale.

csv_columns <- function() {
  c(
    "ref", "name", "version", "version_is", "type", "ecosystem", "scope", "purl",
    "supplier", "maintainer", "license", "license_as_written", "published",
    "homepage", "vcs_url", "download_location", "doi", "sha256", "evidence",
    "asserted", "issues", "parent"
  )
}

csv_quote <- function(x) {
  x <- as.character(x)
  out <- paste0("\"", gsub("\"", "\"\"", x, fixed = TRUE), "\"")
  out[is.na(x)] <- "\"\""
  out
}

# Spreadsheets evaluate a cell that starts with = + - @ tab or CR, quoted or
# not, so such a value gets a leading apostrophe (OWASP), in every column:
# names, versions and dates come from third-party DESCRIPTION text too. Real
# values never start that way, so they are unchanged.
csv_neutralise <- function(x) {
  x <- as.character(x)
  risky <- !is.na(x) & grepl("^[=+@\t\r-]", x, useBytes = TRUE)
  x[risky] <- paste0("'", x[risky])
  x
}

csv_sha256 <- function(hashes) {
  vapply(hashes, function(h) {
    hit <- if (is.data.frame(h) && nrow(h) > 0L) h$content[h$alg %in% "SHA-256"] else character()
    if (length(hit) > 0L) hit[1] else NA_character_
  }, character(1))
}

csv_asserted <- function(asserted) {
  vapply(asserted, function(a) {
    if (!is.data.frame(a) || nrow(a) == 0L) {
      return(NA_character_)
    }
    paste0(a$field, "=", a$value, " (", a$asserted_by, ": ", a$reason, ")", collapse = "; ")
  }, character(1))
}

csv_inventory <- function(x, version = NA) {
  comps <- x$components
  comps <- comps[order(!(comps$is_root %in% TRUE), comps$ref, method = "radix"), , drop = FALSE]
  msgs <- split(x$issues$message, factor(x$issues$ref, levels = unique(comps$ref)))
  issues <- vapply(
    comps$ref,
    function(r) if (length(msgs[[r]]) > 0L) paste(msgs[[r]], collapse = " ") else NA_character_,
    character(1)
  )
  cols <- list(
    ref = comps$ref, name = comps$name, version = comps$version,
    version_is = comps$version_is, type = comps$type, ecosystem = comps$ecosystem,
    scope = comps$scope, purl = comps$purl, supplier = comps$supplier_name,
    maintainer = comps$maintainer, license = comps$license_spdx,
    license_as_written = comps$license_as_written, published = comps$published,
    homepage = comps$homepage, vcs_url = comps$vcs_url,
    download_location = comps$download_location, doi = comps$doi,
    sha256 = csv_sha256(comps$hashes), evidence = comps$evidence,
    asserted = csv_asserted(comps$asserted), issues = issues,
    parent = comps$parent_ref
  )
  stopifnot(identical(names(cols), csv_columns()))
  cols <- lapply(cols, csv_neutralise)
  lines <- do.call(paste, c(lapply(cols, csv_quote), sep = ","))
  enc2utf8(paste0(paste(c(paste(csv_quote(csv_columns()), collapse = ","), lines), collapse = "\n"), "\n"))
}

# What write_sbom() writes: the inventory after a UTF-8 byte-order mark, so
# that spreadsheets read it as UTF-8, as readr::write_excel_csv() does.
csv_file <- function(x, version = NA) {
  paste0("\ufeff", csv_inventory(x, version))
}
