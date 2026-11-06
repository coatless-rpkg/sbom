# Makes the zip fixtures in this folder. A dev-time script: utils::zip() runs
# an external zip program (Info-ZIP zip), which test machines need not have,
# so the zips it makes are committed and the tests only read them. Run it from
# the package root:
#
#   Rscript tests/testthat/fixtures/osv/make-zips.R
#
# It makes:
#
# * all.zip: every record in records/, each at the top level of the zip as
#   <id>.json, as OSV's CRAN export holds them.
# * evil-names.zip: the entries ../x.json and a/b.json, names that would
#   leave or nest inside the folder an unzip wrote to.
# * not-json.zip: one entry, README.txt, which is not an OSV record file.
# * bad-json.zip: one entry, RSEC-9000-90.json, whose text is not JSON.
# * no-id.zip: one entry, RSEC-9000-91.json, a JSON object without an id.
# * bad-id.zip: one entry, RSEC-9000-94.json, whose id holds a slash and a
#   space, which no OSV id holds.
# * odd.zip: records that are valid JSON but odd. a.json and b.json share the
#   id RSEC-9000-92; a.json's summary holds a control character (BEL), its
#   modified time has an offset, its interval opens at an object rather than
#   a version, and its list of versions holds an object and a null where
#   strings are expected. c.json (RSEC-9000-93) has a string for `upstream`
#   and an array for `published`, and no `affected`.
# * not-cran.zip: PYSEC-2099-1.json, a record of a PyPI package, and
#   RSEC-9000-95.json, a record without `affected`: no CRAN record.
# * affected-object.zip: RSEC-9000-96.json, whose `affected` is an object,
#   not an array.
# * empty-affected.zip: RSEC-9000-97.json, whose affected entry is {}.
# * no-package.zip: RSEC-9000-98.json, whose affected entry has ranges but no
#   `package`.
#
# Every file is given the same modification time and zip is run with -X (no
# extra attributes), so that a run on another machine makes the same entries.

out <- normalizePath("tests/testthat/fixtures/osv", mustWork = TRUE)
stamp <- as.POSIXct("2026-01-01 00:00:00", tz = "UTC")
Sys.setenv(TZ = "UTC")

# Zips `files`, relative to `dir`, into out/<name>, replacing it.
make_zip <- function(name, dir, files) {
  zipfile <- file.path(out, name)
  unlink(zipfile)
  Sys.setFileTime(file.path(dir, files), stamp)
  old <- setwd(dir)
  on.exit(setwd(old), add = TRUE)
  status <- utils::zip(zipfile, files, flags = "-X -q")
  stopifnot(identical(as.integer(status), 0L), file.exists(zipfile))
  print(utils::unzip(zipfile, list = TRUE, unzip = "internal")[c("Name", "Length")])
}

# A new empty folder holding `entries`, a named list of path = text.
stage <- function(entries) {
  dir <- tempfile("osv-fixture-")
  for (path in names(entries)) {
    target <- file.path(dir, path)
    dir.create(dirname(target), recursive = TRUE, showWarnings = FALSE)
    writeLines(entries[[path]], target, useBytes = TRUE)
  }
  dir
}

records <- file.path(out, "records")
make_zip("all.zip", records, sort(list.files(records, pattern = "\\.json$"), method = "radix"))

# zip runs in work/, and x.json is beside it, so that zip stores the name
# ../x.json as given.
evil <- stage(list(x.json = "{}", `work/a/b.json` = "{}"))
make_zip("evil-names.zip", file.path(evil, "work"), c("../x.json", "a/b.json"))

not_json <- stage(list(README.txt = "Not an OSV record."))
make_zip("not-json.zip", not_json, "README.txt")

bad_json <- stage(list(`RSEC-9000-90.json` = '{"id": "RSEC-9000-90", "summary": '))
make_zip("bad-json.zip", bad_json, "RSEC-9000-90.json")

no_id <- stage(list(`RSEC-9000-91.json` = '{"summary": "A record without an id", "affected": []}'))
make_zip("no-id.zip", no_id, "RSEC-9000-91.json")

bad_id <- stage(list(`RSEC-9000-94.json` = '{"id": "../RSEC 9000", "summary": "An id that is not an OSV id"}'))
make_zip("bad-id.zip", bad_id, "RSEC-9000-94.json")

odd <- stage(list(
  a.json = paste0(
    '{"id": "RSEC-9000-92", "summary": "First\\u0007record", "modified": "2099-08-01T00:00:00+01:00", ',
    '"affected": [{"package": {"name": "oddpkg", "ecosystem": "CRAN"}, ',
    '"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": {"at": "1.0"}}, {"fixed": "2.0"}]}], ',
    '"versions": ["1.1", {"v": "1.2"}, null]}]}'
  ),
  b.json = '{"id": "RSEC-9000-92", "summary": "Second record"}',
  c.json = '{"id": "RSEC-9000-93", "upstream": "CVE-2099-0093", "published": ["2099-01-01"]}'
))
make_zip("odd.zip", odd, c("a.json", "b.json", "c.json"))

range_from_0 <- '"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]'
not_cran <- stage(list(
  `PYSEC-2099-1.json` = paste0(
    '{"id": "PYSEC-2099-1", "modified": "2099-01-01T00:00:00Z", ',
    '"affected": [{"package": {"ecosystem": "PyPI", "name": "fakepkg"}, ', range_from_0, "}]}"
  ),
  `RSEC-9000-95.json` = '{"id": "RSEC-9000-95", "summary": "A record without affected packages"}'
))
make_zip("not-cran.zip", not_cran, c("PYSEC-2099-1.json", "RSEC-9000-95.json"))

affected_object <- stage(list(`RSEC-9000-96.json` = paste0(
  '{"id": "RSEC-9000-96", "affected": {"package": {"ecosystem": "CRAN", "name": "fakepkg"}, ', range_from_0, "}}"
)))
make_zip("affected-object.zip", affected_object, "RSEC-9000-96.json")

empty_affected <- stage(list(`RSEC-9000-97.json` = '{"id": "RSEC-9000-97", "affected": [{}]}'))
make_zip("empty-affected.zip", empty_affected, "RSEC-9000-97.json")

no_package <- stage(list(`RSEC-9000-98.json` = paste0('{"id": "RSEC-9000-98", "affected": [{', range_from_0, "}]}")))
make_zip("no-package.zip", no_package, "RSEC-9000-98.json")

unlink(
  c(evil, not_json, bad_json, no_id, bad_id, odd, not_cran, affected_object, empty_affected, no_package),
  recursive = TRUE
)
