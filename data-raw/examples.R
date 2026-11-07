# Makes inst/extdata/examples/osv-all.zip, the OSV advisory export that
# sbom_example("osv-all.zip") returns. A dev-time script: utils::zip() runs an
# external zip program (Info-ZIP zip), which users need not have, so the zip it
# makes is committed and the package only reads it. Run it from the package
# root:
#
#   Rscript data-raw/examples.R
#
# The zip holds one record, EXAMPLE-2026-1.json, at its top level, as OSV's
# CRAN export holds them: a made-up advisory against holeypkg, the made-up CRAN
# package of the "study" example, fixed in 1.0.1. The other examples are plain
# text files, written by hand.

record <- c(
  '{"id": "EXAMPLE-2026-1", "summary": "A made-up advisory for sbom\'s examples",',
  ' "published": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",',
  ' "affected": [{"package": {"ecosystem": "CRAN", "name": "holeypkg"},',
  '   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}'
)
dir <- tempfile("osv-")
dir.create(dir)
json <- file.path(dir, "EXAMPLE-2026-1.json")
writeLines(record, json, useBytes = TRUE)
zip <- normalizePath(file.path("inst", "extdata", "examples", "osv-all.zip"), mustWork = FALSE)
unlink(zip)
status <- utils::zip(zip, json, flags = "-j -X -q")
if (status != 0L) stop("zip failed with status ", status)
unlink(dir, recursive = TRUE)
cat("Wrote", zip, "\n")
