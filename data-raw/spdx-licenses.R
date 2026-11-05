# Precomputes inst/extdata/spdx-licenses.{csv,dcf}: the identifiers of the SPDX License List, for the
# license-expression checker. Needs network; run from the package root.
#
# Only the identifiers and their deprecation flag are kept. Update `version` to move to a newer list.

version <- "3.29.0"
base <- paste0("https://raw.githubusercontent.com/spdx/license-list-data/v", version, "/json/")
urls <- paste0(base, c("licenses.json", "exceptions.json"))

licenses <- jsonlite::fromJSON(urls[1])
exceptions <- jsonlite::fromJSON(urls[2])
stopifnot(
  identical(licenses$licenseListVersion, version),
  identical(exceptions$licenseListVersion, version)
)

out <- rbind(
  data.frame(
    id = licenses$licenses$licenseId,
    kind = "license",
    deprecated = licenses$licenses$isDeprecatedLicenseId
  ),
  data.frame(
    id = exceptions$exceptions$licenseExceptionId,
    kind = "exception",
    deprecated = exceptions$exceptions$isDeprecatedLicenseId
  )
)
out <- out[order(out$id, method = "radix"), ]
stopifnot(!anyDuplicated(out$id), !anyNA(out$deprecated))

# Write by hand so that `deprecated` is TRUE/FALSE and the line endings are "\n".
lines <- c("id,kind,deprecated", paste(out$id, out$kind, ifelse(out$deprecated, "TRUE", "FALSE"), sep = ","))
con <- file("inst/extdata/spdx-licenses.csv", "wb")
writeLines(lines, con, sep = "\n", useBytes = TRUE)
close(con)

dcf <- c(
  paste("Version:", version),
  paste("Source:", paste(urls, collapse = " ")),
  paste("Date:", as.character(Sys.Date()))
)
con <- file("inst/extdata/spdx-licenses.dcf", "wb")
writeLines(dcf, con, sep = "\n", useBytes = TRUE)
close(con)
