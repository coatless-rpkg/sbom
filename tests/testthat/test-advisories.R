osv_fixture <- function(...) test_path("fixtures", "osv", ...)

osv_url <- "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip"

# The sentence of the sbom_advisories_error that `expr` raises. The printed
# message holds the same words.
advisories_error <- function(expr) {
  cnd <- tryCatch(expr, sbom_advisories_error = identity)
  expect_s3_class(cnd, "sbom_advisories_error")
  if (!inherits(cnd, "sbom_advisories_error")) {
    return(NA_character_)
  }
  expect_identical(trimws(gsub("[[:space:]]+", " ", conditionMessage(cnd))), cnd$sentence)
  cnd$sentence
}

# The sentence of the error that reading the zip at `path` raises.
zip_error <- function(path) {
  advisories_error(osv_read_zip(path, basename(path)))
}

# A CRAN package component, its ref the package URL of `name` and `version`.
cran_component <- function(name, version, version_is = "exact", ecosystem = "cran", purl = NULL) {
  if (is.null(purl)) {
    purl <- paste0("pkg:cran/", name, if (!is.na(version)) paste0("@", version))
  }
  component_row(
    ref = purl, name = name, version = version,
    version_is = if (!is.na(version)) version_is, type = "library",
    ecosystem = ecosystem, purl = purl
  )
}

# A copy of the zip at `path`, in a new temporary folder, whose entry name
# `from` is replaced by the bytes `to`, as long, in its local header and its
# central directory. A name is not part of the data a CRC covers.
zip_renamed <- function(path, from, to, env = parent.frame()) {
  bytes <- readBin(path, "raw", n = file.size(path))
  from <- charToRaw(from)
  stopifnot(length(to) == length(from))
  starts <- seq_len(length(bytes) - length(from) + 1L)
  at <- starts[vapply(starts, function(i) identical(bytes[i + seq_along(from) - 1L], from), logical(1))]
  expect_length(at, 2L)
  for (i in at) {
    bytes[i + seq_along(from) - 1L] <- to
  }
  out <- file.path(withr::local_tempdir(.local_envir = env), basename(path))
  writeBin(bytes, out)
  out
}

# Runs the rest of the calling code with a UTF-8 LC_CTYPE. Skips when the
# platform has none.
local_utf8_ctype <- function(env = parent.frame()) {
  for (locale in c("en_US.UTF-8", "C.UTF-8", "en_GB.UTF-8")) {
    suppressWarnings(withr::local_locale(c(LC_CTYPE = locale), .local_envir = env))
    if (isTRUE(l10n_info()[["UTF-8"]])) {
      return(invisible())
    }
  }
  testthat::skip("This platform has no UTF-8 locale.")
}

# OSV's tables for one record, RSEC-9000-99, whose `affected` array is the
# JSON text given, parsed as osv_read_zip() parses a record.
osv_tables <- function(affected) {
  doc <- json_parse_strict(paste0('{"id": "RSEC-9000-99", "affected": ', affected, "}"))
  records <- osv_records(list(doc))
  list(records = records, affected = osv_affected(list(doc), records$id), newest_modified = NA_character_)
}

# The `affected` array of one entry for evpkg with one ECOSYSTEM range, whose
# events are the JSON text given.
evpkg_range <- function(events) {
  paste0('[{"package": {"name": "evpkg", "ecosystem": "CRAN"}, "ranges": [{"type": "ECOSYSTEM", "events": ', events, "}]}]")
}

# What matching each version of evpkg with `osv` gives: "unparsed", "none",
# "open" (no fix), "closed" (matched, with no fixed version) or the fixed
# version.
evpkg_grid <- function(osv, versions = c("0.5", "1.0", "1.2", "1.5", "1.7", "2.0", "2.1", "2.3", "2.5")) {
  comps <- do.call(rbind, lapply(versions, function(v) cran_component("evpkg", v)))
  m <- osv_match(comps, osv)
  affects <- do.call(rbind, c(list(data.frame(ref = character(), fixed = character(), no_fix = logical())),
                              lapply(m$advisories$affects, `[`, c("ref", "fixed", "no_fix"))))
  out <- vapply(comps$ref, function(ref) {
    hit <- affects[affects$ref == ref, , drop = FALSE]
    if (ref %in% m$unparsed) {
      "unparsed"
    } else if (nrow(hit) == 0L) {
      "none"
    } else if (hit$no_fix) {
      "open"
    } else if (is.na(hit$fixed)) {
      "closed"
    } else {
      hit$fixed
    }
  }, "", USE.NAMES = FALSE)
  names(out) <- versions
  out
}

# The interval columns of the range rows of `osv`.
range_rows <- function(osv) {
  aff <- osv$affected[osv$affected$kind == "range", c("introduced", "fixed", "last_affected")]
  rownames(aff) <- NULL
  aff
}

intervals <- function(introduced, fixed = NA_character_, last_affected = NA_character_) {
  data.frame(introduced = introduced, fixed = fixed, last_affected = last_affected, stringsAsFactors = FALSE)
}

# Calls url() as the sbom namespace sees it with the file:// URL of a local
# file, which reaches no network whether url() is mocked or not, and checks
# that the mock recorded it in `calls$urls`.
expect_url_mocked <- function(calls) {
  local <- withr::local_tempfile()
  write_text("", local)
  target <- paste0("file://", local)
  con <- tryCatch(get("url", envir = environment(osv_lookup_real))(target), error = function(e) NULL)
  if (inherits(con, "connection")) close(con)
  expect_identical(utils::tail(calls$urls, 1L), target)
}

# Calls utils::download.file(), as osv_download() calls it, with the file://
# URL of a local file, which reaches no network whether it is mocked or not,
# and checks that the mock recorded it in `calls$urls`.
expect_download_mocked <- function(calls) {
  local <- withr::local_tempfile()
  write_text("", local)
  target <- paste0("file://", local)
  try(suppressWarnings(utils::download.file(target, withr::local_tempfile(), mode = "wb", quiet = TRUE)), silent = TRUE)
  expect_identical(utils::tail(calls$urls, 1L), target)
}

test_that("osv_read_zip() reads every record of an OSV export", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  expect_named(osv, c("records", "affected", "newest_modified"))
  rec <- osv$records
  expect_named(rec, c("id", "summary", "published", "modified", "withdrawn", "source_url", "upstream"))
  expect_identical(rec$id, paste0("RSEC-9000-", 1:8))
  expect_identical(rec$summary[c(1, 8)], c("Synthetic flaw in fakepkg", NA))
  expect_identical(rec$published[[1]], "2099-01-02T03:04:05Z")
  expect_identical(rec$modified[[3]], "2099-06-30T12:00:00.5Z")
  expect_identical(
    rec$source_url,
    c("https://example.org/r-advisory-database/vulns/fakepkg/RSEC-9000-1.yaml", rep(NA, 7))
  )
  expect_identical(
    rec$upstream,
    c(list("CVE-2099-0001", character(), c("CVE-2099-0003", "GHSA-xxxx-yyyy-zzzz")), rep(list(character()), 5))
  )
})

test_that("osv_read_zip() gives one row per interval and per listed version", {
  aff <- osv_read_zip(osv_fixture("all.zip"), "all.zip")$affected
  expected <- data.frame(
    id = paste0("RSEC-9000-", c(1, 1, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8)),
    package = c(rep("fakepkg", 4), "openpkg", "lastpkg", "listpkg", "listpkg", "fakepkg", "fakepkg",
                "twopkg", "twopkg", "badpkg"),
    ecosystem = c(rep("CRAN", 9), "Bioconductor", rep("CRAN", 3)),
    kind = c("range", "listed", "listed", "listed", "range", "range", "listed", "listed", rep("range", 5)),
    introduced = c("0.1.0", NA, NA, NA, "0", "1.0", NA, NA, "0", "0", "1.0", "2.0", "not-a-version"),
    fixed = c("1.1.0", NA, NA, NA, NA, NA, NA, NA, NA, NA, "1.5", "2.3", NA),
    last_affected = c(NA, NA, NA, NA, NA, "1.2-3", NA, NA, NA, NA, NA, NA, NA),
    version = c(NA, "0.1.0", "0.1.1", "1.0.0", NA, NA, "2.0.1", "2.0-2", NA, NA, NA, NA, NA),
    stringsAsFactors = FALSE
  )
  expect_identical(aff, expected)
  # twopkg's GIT range is not read.
  expect_identical(sum(aff$package == "twopkg"), 2L)
  expect_identical(sum(aff$package == "fakepkg" & aff$kind == "listed"), 3L)
})

test_that("newest_modified is the latest modified time, as written", {
  # RSEC-9000-7's 12:00:00Z sorts after RSEC-9000-3's 12:00:00.5Z as text,
  # but is half a second earlier.
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  expect_identical(osv$newest_modified, "2099-06-30T12:00:00.5Z")
})

test_that("a withdrawn record is kept and marked", {
  rec <- osv_read_zip(osv_fixture("all.zip"), "all.zip")$records
  expect_identical(rec$withdrawn[rec$id == "RSEC-9000-5"], "2099-03-01T00:00:00Z")
  expect_true(all(is.na(rec$withdrawn[rec$id != "RSEC-9000-5"])))
})

test_that("a damaged or hostile zip is an advisories error that names the reason", {
  dir <- withr::local_tempdir()
  truncated <- file.path(dir, "all.zip")
  writeBin(readBin(osv_fixture("all.zip"), "raw", n = 100L), truncated)
  expect_identical(zip_error(truncated), "The OSV advisory file all.zip is damaged: it is not a zip file.")

  text <- file.path(withr::local_tempdir(), "all.zip")
  write_text("This is not a zip file.\n", text)
  expect_identical(zip_error(text), "The OSV advisory file all.zip is damaged: it is not a zip file.")

  expect_identical(
    zip_error(osv_fixture("evil-names.zip")),
    "The OSV advisory file evil-names.zip is damaged: it holds an entry that is not an OSV record file."
  )
  expect_identical(
    zip_error(osv_fixture("not-json.zip")),
    "The OSV advisory file not-json.zip is damaged: it holds an entry, README.txt, that is not an OSV record file."
  )
  expect_identical(
    zip_error(osv_fixture("bad-json.zip")),
    "The OSV advisory file bad-json.zip is damaged: the record RSEC-9000-90.json is not valid JSON."
  )
  expect_identical(
    zip_error(osv_fixture("no-id.zip")),
    "The OSV advisory file no-id.zip is damaged: the record RSEC-9000-91.json has no id."
  )
  # An id that is not made of the characters OSV ids use is no id.
  expect_identical(
    zip_error(osv_fixture("bad-id.zip")),
    "The OSV advisory file bad-id.zip is damaged: the record RSEC-9000-94.json has no id."
  )
})

test_that("a record sbom cannot read as an OSV record, or a zip without a CRAN record, is damaged", {
  expect_identical(
    zip_error(osv_fixture("not-cran.zip")),
    "The OSV advisory file not-cran.zip is damaged: it holds no CRAN records."
  )
  expect_identical(
    zip_error(osv_fixture("affected-object.zip")),
    "The OSV advisory file affected-object.zip is damaged: the record RSEC-9000-96.json is not an OSV record."
  )
  expect_identical(
    zip_error(osv_fixture("empty-affected.zip")),
    "The OSV advisory file empty-affected.zip is damaged: the record RSEC-9000-97.json is not an OSV record."
  )
  expect_identical(
    zip_error(osv_fixture("no-package.zip")),
    "The OSV advisory file no-package.zip is damaged: the record RSEC-9000-98.json is not an OSV record."
  )
})

test_that("a record is an OSV record when each affected entry names its package and ecosystem", {
  ok <- function(txt) osv_record_ok(json_parse_strict(txt))
  package <- '{"package": {"name": "a", "ecosystem": "CRAN"}}'
  for (good in c('{"id": "A-1"}', '{"id": "A-1", "affected": []}', paste0('{"affected": [', package, "]}"))) {
    expect_true(ok(good), label = good)
  }
  for (bad in c(
    '{"affected": null}', '{"affected": "not a list"}', '{"affected": 1}', paste0('{"affected": ', package, "}"),
    paste0('{"affected": [', package, ', "not an object"]}'), '{"affected": [{}]}', '{"affected": [[]]}',
    '{"affected": [{"package": "a"}]}', '{"affected": [{"package": {"name": "a"}}]}',
    '{"affected": [{"package": {"ecosystem": "CRAN"}}]}',
    '{"affected": [{"package": {"name": 5, "ecosystem": "CRAN"}}]}',
    '{"affected": [{"package": {"name": "", "ecosystem": "CRAN"}}]}',
    '{"affected": [{"package": {"name": ["a"], "ecosystem": "CRAN"}}]}',
    '{"affected": [{"package": {"name": "a", "ecosystem": null}}]}'
  )) {
    expect_false(ok(bad), label = bad)
  }
})

test_that("an entry name that is not ASCII is refused in a UTF-8 and in the C locale", {
  # é in UTF-8, and é in Latin-1, which is not valid UTF-8.
  utf8 <- zip_renamed(osv_fixture("no-id.zip"), "RSEC-9000-91.json",
                      c(charToRaw("RSEC-9000-"), as.raw(c(0xc3, 0xa9)), charToRaw(".json")))
  latin1 <- zip_renamed(osv_fixture("no-id.zip"), "RSEC-9000-91.json",
                        c(charToRaw("RSEC-9000-"), as.raw(0xe9), charToRaw("1.json")))
  sentence <- "The OSV advisory file no-id.zip is damaged: it holds an entry that is not an OSV record file."
  local({
    local_utf8_ctype()
    expect_identical(zip_error(utf8), sentence)
    expect_identical(zip_error(latin1), sentence)
  })
  local({
    local_c_ctype()
    expect_identical(zip_error(utf8), sentence)
    expect_identical(zip_error(latin1), sentence)
  })
})

test_that("an entry whose compressed data is damaged is not a valid record", {
  bytes <- readBin(osv_fixture("all.zip"), "raw", n = file.size(osv_fixture("all.zip")))
  # The first entry's data starts after its 30-byte local header, its name
  # and its extra field.
  le16 <- function(at) as.integer(bytes[at]) + 256L * as.integer(bytes[at + 1L])
  start <- 30L + le16(27L) + le16(29L) + 1L
  bytes[start + 0:19] <- as.raw(0xff)
  path <- file.path(withr::local_tempdir(), "all.zip")
  writeBin(bytes, path)
  expect_identical(
    zip_error(path),
    "The OSV advisory file all.zip is damaged: the record RSEC-9000-1.json is not valid JSON."
  )
})

test_that("a zip over the size or entry cap is refused", {
  withr::local_options(sbom.osv_max_mb = 0.0001)
  expect_identical(
    zip_error(osv_fixture("all.zip")),
    "The OSV advisory file all.zip is damaged: it unpacks to more than 0.0001 MB."
  )
  withr::local_options(sbom.osv_max_mb = NULL, sbom.osv_max_entries = 7)
  expect_identical(
    zip_error(osv_fixture("all.zip")),
    "The OSV advisory file all.zip is damaged: it holds more than 7 entries."
  )
  expect_identical(osv_max_mb(), 50)
  # unz() finds each entry by reading the zip's directory from its start, so
  # reading takes time in the square of the entry count.
  withr::local_options(sbom.osv_max_entries = NULL)
  expect_identical(osv_max_entries(), 2000)
})

test_that("reading a zip writes no file", {
  before <- list.files(tempdir(), recursive = TRUE, all.files = TRUE)
  fixtures <- list.files(osv_fixture(), recursive = TRUE, all.files = TRUE)
  osv_read_zip(osv_fixture("all.zip"), "all.zip")
  expect_identical(list.files(tempdir(), recursive = TRUE, all.files = TRUE), before)
  expect_identical(list.files(osv_fixture(), recursive = TRUE, all.files = TRUE), fixtures)
})

test_that("odd records are read without failing, the first of two with one id kept", {
  osv <- osv_read_zip(osv_fixture("odd.zip"), "odd.zip")
  rec <- osv$records
  expect_identical(rec$id, c("RSEC-9000-92", "RSEC-9000-93"))
  # a.json comes before b.json, and its control character is kept as a space.
  expect_identical(rec$summary, c("First record", NA))
  expect_identical(rec$upstream, list(character(), character()))
  expect_identical(rec$published, c(NA_character_, NA_character_))
  # A time with an offset is not one OSV writes, so none is the newest.
  expect_identical(osv$newest_modified, NA_character_)
  expect_identical(
    osv$affected,
    data.frame(
      id = "RSEC-9000-92", package = "oddpkg", ecosystem = "CRAN", kind = c("range", "listed"),
      introduced = c("", NA), fixed = c("2.0", NA), last_affected = NA_character_,
      version = c(NA, "1.1"), stringsAsFactors = FALSE
    )
  )
  # The interval opens at an object, kept as a bound with no version, so no
  # version can be compared with the range, but a listed version still
  # matches.
  m <- osv_match(rbind(cran_component("oddpkg", "1.1"), cran_component("oddpkg", "1.5")), osv)
  expect_identical(m$advisories$id, "RSEC-9000-92")
  expect_identical(m$advisories$affects[[1]]$ref, "pkg:cran/oddpkg@1.1")
  expect_identical(m$unparsed, c("pkg:cran/oddpkg@1.1", "pkg:cran/oddpkg@1.5"))
})

test_that("osv_fetch() reads a local file and names a missing one", {
  got <- osv_fetch(osv_source(osv_fixture("all.zip")))
  expect_named(got, c("records", "affected", "newest_modified", "fetched"))
  expect_identical(nrow(got$records), 8L)
  expect_s3_class(got$fetched, "POSIXct")
  expect_true(is.na(got$fetched))
  expect_identical(osv_source(osv_fixture("all.zip"))$label, "all.zip")

  missing <- file.path(withr::local_tempdir(), "missing.zip")
  expect_identical(
    advisories_error(osv_fetch(osv_source(missing))),
    paste0("The OSV advisory file ", missing, " does not exist.")
  )
})

test_that("osv_fetch() downloads OSV's export to a temporary file it removes", {
  seen <- new.env()
  local_mocked_bindings(osv_download = function(url, dest, timeout = 300) {
    seen$url <- url
    seen$dest <- dest
    seen$timeout <- timeout
    file.copy(osv_fixture("all.zip"), dest)
    TRUE
  })
  expect_identical(osv_source(TRUE), list(kind = "url", location = osv_url, label = osv_url))
  got <- osv_fetch(osv_source(TRUE), timeout = 12)
  expect_identical(seen$url, osv_url)
  expect_identical(seen$timeout, 12)
  expect_false(file.exists(seen$dest))
  expect_identical(nrow(got$records), 8L)
  expect_s3_class(got$fetched, "POSIXct")
  expect_identical(attr(got$fetched, "tzone"), "UTC")
  expect_false(is.na(got$fetched))
})

test_that("a failed or damaged download is an advisories error", {
  expect_identical(
    advisories_error(osv_fetch(osv_source(TRUE))),
    paste0("OSV's advisory data could not be downloaded from ", osv_url, " (not run in tests).")
  )
  local_mocked_bindings(osv_download = function(url, dest, ...) structure(FALSE, reason = "HTTP status 404"))
  expect_identical(
    advisories_error(osv_fetch(osv_source(TRUE))),
    paste0("OSV's advisory data could not be downloaded from ", osv_url, " (HTTP status 404).")
  )
  local_mocked_bindings(osv_download = function(url, dest, ...) {
    write_text("Not a zip file.\n", dest)
    TRUE
  })
  expect_identical(
    advisories_error(osv_fetch(osv_source(TRUE))),
    paste0("The OSV advisory file ", osv_url, " is damaged: it is not a zip file.")
  )
})

test_that("osv_match() matches exact CRAN versions against intervals and listed versions", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  comps <- rbind(
    cran_component("fakepkg", "1.0.0"),
    cran_component("fakepkg", "1.1.0"),
    cran_component("fakepkg", "0.1.1"),
    cran_component("openpkg", "99.0"),
    cran_component("lastpkg", "1.2.3"),
    cran_component("lastpkg", "1.2.4"),
    cran_component("listpkg", "2.0.2"),
    cran_component("twopkg", "1.2"),
    cran_component("twopkg", "1.7"),
    cran_component("twopkg", "2.1"),
    cran_component("fakepkg", "1.0.0", ecosystem = "bioconductor",
                   purl = "pkg:cran/fakepkg@1.0.0?repository_url=https://bioconductor.org/packages/3.20/bioc"),
    cran_component("fakepkg", "abc1234", ecosystem = "github", purl = "pkg:github/someone/fakepkg@abc1234"),
    cran_component("fakepkg", "0.5", version_is = "minimum"),
    cran_component("openpkg", NA),
    cran_component("badpkg", "1.0"),
    cran_component("fakepkg", "abc123")
  )
  m <- osv_match(comps, osv)
  expect_named(m, c("advisories", "no_exact", "unparsed", "not_cran"))
  adv <- m$advisories
  expect_named(adv, c("id", "summary", "published", "source_url", "upstream", "ratings", "affects"))
  # The withdrawn RSEC-9000-5 and the Bioconductor RSEC-9000-6 never match.
  expect_identical(adv$id, paste0("RSEC-9000-", c(1, 2, 3, 4, 7)))
  affects <- function(ref, version, fixed, no_fix) {
    data.frame(ref = ref, version = version, fixed = fixed, no_fix = no_fix, stringsAsFactors = FALSE)
  }
  expect_identical(adv$affects, list(
    affects(c("pkg:cran/fakepkg@0.1.1", "pkg:cran/fakepkg@1.0.0"), c("0.1.1", "1.0.0"), "1.1.0", FALSE),
    affects("pkg:cran/openpkg@99.0", "99.0", NA_character_, TRUE),
    affects("pkg:cran/lastpkg@1.2.3", "1.2.3", NA_character_, FALSE),
    affects("pkg:cran/listpkg@2.0.2", "2.0.2", NA_character_, FALSE),
    affects(c("pkg:cran/twopkg@1.2", "pkg:cran/twopkg@2.1"), c("1.2", "2.1"), c("1.5", "2.3"), FALSE)
  ))
  expect_identical(adv$summary[[1]], "Synthetic flaw in fakepkg")
  expect_identical(adv$published, c("2099-01-02", "2099-02-01", "2099-03-01", "2099-04-01", "2099-06-01"))
  expect_identical(adv$source_url, c("https://example.org/r-advisory-database/vulns/fakepkg/RSEC-9000-1.yaml", rep(NA, 4)))
  expect_identical(adv$upstream[[1]], "CVE-2099-0001")
  expect_identical(adv$ratings, vector("list", 5L))
  expect_identical(m$no_exact, c("pkg:cran/fakepkg@0.5", "pkg:cran/openpkg"))
  expect_identical(m$unparsed, c("pkg:cran/badpkg@1.0", "pkg:cran/fakepkg@abc123"))
})

test_that("candidates are the components with a CRAN package URL and a version, whatever their ecosystem", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  bioc <- "?repository_url=https://bioconductor.org/packages/3.20/bioc"
  comps <- rbind(
    # A version with no version_is counts as exact.
    cran_component("fakepkg", "1.0.0", version_is = NA, ecosystem = "unknown"),
    cran_component("openpkg", "2.0", ecosystem = "local"),
    cran_component("listpkg", "2.0.1", version_is = "minimum", ecosystem = "unknown"),
    cran_component("lastpkg", NA, ecosystem = "unknown"),
    # A CRAN package URL that names Bioconductor is neither compared nor named.
    cran_component("twopkg", "1.2", ecosystem = "repository", purl = paste0("pkg:cran/twopkg@1.2", bioc)),
    cran_component("twopkg", NA, ecosystem = "repository",
                   purl = "pkg:cran/twopkg?repository_url=https://www.bioconductor.org")
  )
  m <- osv_match(comps, osv)
  expect_identical(m$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"))
  expect_identical(m$advisories$affects[[1]]$ref, "pkg:cran/fakepkg@1.0.0")
  expect_identical(m$no_exact, c("pkg:cran/lastpkg", "pkg:cran/listpkg@2.0.1"))
  expect_identical(m$not_cran, character())

  # R packages without a CRAN package URL are named in not_cran; the root,
  # embedded copies, and components that are not R packages are not.
  others <- rbind(
    component_row(ref = "unknown/fakepkg", name = "fakepkg", version = "1.0.0", type = "library",
                  ecosystem = "unknown"),
    component_row(ref = "pkg:github/someone/openpkg@abc", name = "openpkg", version = "2.0", version_is = "exact",
                  type = "library", ecosystem = "github", purl = "pkg:github/someone/openpkg@abc"),
    component_row(ref = "local/rootpkg", name = "rootpkg", type = "library", ecosystem = "local", is_root = TRUE),
    component_row(ref = "local/rootpkg#embedded/fakepkg", name = "fakepkg", type = "library", ecosystem = "unknown"),
    component_row(ref = "R", name = "R", type = "platform", ecosystem = "r"),
    component_row(ref = "system/libxml2", name = "libxml2", type = "library", ecosystem = "system")
  )
  m <- osv_match(others, osv)
  expect_identical(nrow(m$advisories), 0L)
  expect_identical(m$no_exact, character())
  expect_identical(m$not_cran, c("pkg:github/someone/openpkg@abc", "unknown/fakepkg"))
})

test_that("a package from another CRAN-like repository is matched too", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  comp <- cran_component("twopkg", "2.1", ecosystem = "repository",
                         purl = "pkg:cran/twopkg@2.1?repository_url=https://example.org/drat")
  m <- osv_match(comp, osv)
  expect_identical(m$advisories$id, "RSEC-9000-7")
  expect_identical(m$advisories$affects[[1]]$fixed, "2.3")
})

test_that("osv_match() gives empty tables when nothing matches", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  m <- osv_match(cran_component("otherpkg", "1.0"), osv)
  expect_identical(nrow(m$advisories), 0L)
  expect_named(m$advisories, c("id", "summary", "published", "source_url", "upstream", "ratings", "affects"))
  expect_identical(m$no_exact, character())
  expect_identical(m$unparsed, character())
})

test_that("osv_match() gives empty tables when there is no candidate", {
  osv <- osv_read_zip(osv_fixture("all.zip"), "all.zip")
  empty <- osv_match(cran_component("otherpkg", "1.0"), osv)$advisories
  expect_identical(
    vapply(empty, typeof, ""),
    c(id = "character", summary = "character", published = "character", source_url = "character",
      upstream = "list", ratings = "list", affects = "list")
  )
  github <- cran_component("fakepkg", "abc1234", ecosystem = "github", purl = "pkg:github/someone/fakepkg@abc1234")
  minimum <- cran_component("fakepkg", "0.5", version_is = "minimum")
  for (comps in list(github, github[0, ], minimum)) {
    m <- osv_match(comps, osv)
    expect_named(m, c("advisories", "no_exact", "unparsed", "not_cran"))
    expect_identical(m$advisories, empty)
    expect_identical(m$unparsed, character())
  }
  expect_identical(osv_match(github, osv)$no_exact, character())
  expect_identical(osv_match(minimum, osv)$no_exact, "pkg:cran/fakepkg@0.5")
})

test_that("a range's events are taken in version order, as OSV evaluates them", {
  # A second introduced inside an interval changes nothing.
  osv <- osv_tables(evpkg_range('[{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.3"}]'))
  expect_identical(range_rows(osv), intervals("1.0", "2.3"))
  expect_identical(
    evpkg_grid(osv),
    c(`0.5` = "none", `1.0` = "2.3", `1.2` = "2.3", `1.5` = "2.3", `1.7` = "2.3", `2.0` = "2.3",
      `2.1` = "2.3", `2.3` = "none", `2.5` = "none")
  )
  # A fix written before its introduced still closes the interval.
  osv <- osv_tables(evpkg_range('[{"fixed": "1.5"}, {"introduced": "1.0"}]'))
  expect_identical(range_rows(osv), intervals("1.0", "1.5"))
  expect_identical(evpkg_grid(osv)[c("0.5", "1.0", "1.2", "1.5", "2.5")],
                   c(`0.5` = "none", `1.0` = "1.5", `1.2` = "1.5", `1.5` = "none", `2.5` = "none"))
  # The inverted pair: the fix comes first, so the interval from 1.5 is open.
  osv <- osv_tables(evpkg_range('[{"introduced": "1.5"}, {"fixed": "1.2"}]'))
  expect_identical(range_rows(osv), intervals("1.5"))
  expect_identical(
    evpkg_grid(osv),
    c(`0.5` = "none", `1.0` = "none", `1.2` = "none", `1.5` = "open", `1.7` = "open", `2.0` = "open",
      `2.1` = "open", `2.3` = "open", `2.5` = "open")
  )
  # Two intervals written in reverse.
  osv <- osv_tables(evpkg_range('[{"introduced": "2.0"}, {"fixed": "2.3"}, {"introduced": "1.0"}, {"fixed": "1.5"}]'))
  expect_identical(range_rows(osv), intervals(c("1.0", "2.0"), c("1.5", "2.3")))
  expect_identical(
    evpkg_grid(osv),
    c(`0.5` = "none", `1.0` = "1.5", `1.2` = "1.5", `1.5` = "none", `1.7` = "none", `2.0` = "2.3",
      `2.1` = "2.3", `2.3` = "none", `2.5` = "none")
  )
  # The lower of two fixes closes the interval.
  osv <- osv_tables(evpkg_range('[{"introduced": "1.0"}, {"fixed": "2.0"}, {"fixed": "1.5"}]'))
  expect_identical(range_rows(osv), intervals("1.0", "1.5"))
  expect_identical(evpkg_grid(osv)[c("1.2", "1.5", "1.7", "2.0")],
                   c(`1.2` = "1.5", `1.5` = "none", `1.7` = "none", `2.0` = "none"))
  # Introduced "0" comes first wherever it is written.
  osv <- osv_tables(evpkg_range('[{"fixed": "1.0"}, {"introduced": "0"}]'))
  expect_identical(range_rows(osv), intervals("0", "1.0"))
  expect_identical(evpkg_grid(osv)[c("0.5", "1.0")], c(`0.5` = "1.0", `1.0` = "none"))
  # At one version, introduced comes before fixed or last_affected.
  osv <- osv_tables(evpkg_range('[{"fixed": "1.5"}, {"introduced": "1.5"}]'))
  expect_true(all(evpkg_grid(osv) == "none"))
  osv <- osv_tables(evpkg_range('[{"last_affected": "1.5"}, {"introduced": "1.5"}]'))
  expect_identical(evpkg_grid(osv)[c("1.2", "1.5", "1.7")], c(`1.2` = "none", `1.5` = "closed", `1.7` = "none"))
})

test_that("a range with a bound that is not a version sends every version of its package to unparsed", {
  unparsed <- rep("unparsed", 9L)
  names(unparsed) <- c("0.5", "1.0", "1.2", "1.5", "1.7", "2.0", "2.1", "2.3", "2.5")
  for (events in c(
    '[{"introduced": "1.0"}, {"fixed": ""}]',
    '[{"introduced": "1.0"}, {"fixed": {"x": "1.5"}}]',
    '[{"introduced": "1.0"}, {"fixed": 1.5}]',
    '[{"introduced": "1.0"}, {"last_affected": ""}]',
    '[{"introduced": "1.0"}, {"fixed": "not-a-version"}]',
    '[{"fixed": "not-a-version"}, {"introduced": "1.0"}]',
    '[{"introduced": "not-a-version"}, {"fixed": "1.5"}]'
  )) {
    expect_identical(evpkg_grid(osv_tables(evpkg_range(events))), unparsed, label = events)
  }
  # Such a range keeps its events as written; an empty or non-text bound is
  # kept as an empty string, and a fix with nothing open as a row without an
  # introduced.
  expect_identical(range_rows(osv_tables(evpkg_range('[{"introduced": "1.0"}, {"fixed": {"x": "1.5"}}]'))),
                   intervals("1.0", ""))
  expect_identical(range_rows(osv_tables(evpkg_range('[{"fixed": "not-a-version"}, {"introduced": "1.0"}]'))),
                   intervals(c(NA, "1.0"), c("not-a-version", NA)))
  # Another advisory on the same package is still compared, and a listed
  # version still matches.
  osv <- osv_tables(paste0(
    '[{"package": {"name": "evpkg", "ecosystem": "CRAN"}, "versions": ["1.2"], ',
    '"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": ""}]}]}]'
  ))
  m <- osv_match(rbind(cran_component("evpkg", "1.2"), cran_component("evpkg", "1.7")), osv)
  expect_identical(m$advisories$affects[[1]]$ref, "pkg:cran/evpkg@1.2")
  expect_identical(m$unparsed, c("pkg:cran/evpkg@1.2", "pkg:cran/evpkg@1.7"))
})

test_that("overlapping intervals give no fix when any is open, and otherwise the largest fix", {
  two <- function(first, second) {
    osv_tables(paste0(
      '[{"package": {"name": "evpkg", "ecosystem": "CRAN"}, "ranges": [{"type": "ECOSYSTEM", "events": ', first, "}]}, ",
      '{"package": {"name": "evpkg", "ecosystem": "CRAN"}, "ranges": [{"type": "ECOSYSTEM", "events": ', second, "}]}]"
    ))
  }
  osv <- two('[{"introduced": "2.0"}, {"fixed": "2.3"}]', '[{"introduced": "1.0"}]')
  expect_identical(evpkg_grid(osv)[c("0.5", "1.5", "2.1", "2.5")],
                   c(`0.5` = "none", `1.5` = "open", `2.1` = "open", `2.5` = "open"))
  osv <- two('[{"introduced": "2.0"}, {"fixed": "2.3"}]', '[{"introduced": "1.0"}, {"fixed": "3.0"}]')
  expect_identical(evpkg_grid(osv)[c("0.5", "1.5", "2.1", "2.5")],
                   c(`0.5` = "none", `1.5` = "3.0", `2.1` = "3.0", `2.5` = "3.0"))
  osv <- two('[{"introduced": "1.0"}, {"fixed": "3.0"}]', '[{"introduced": "2.0"}, {"fixed": "2.3"}]')
  expect_identical(evpkg_grid(osv)[["2.1"]], "3.0")
})

test_that("cvss_base_score() follows the CVSS 3 formula and its round-up", {
  expect_identical(cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), 8.8)
  expect_identical(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
  expect_identical(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), 6.4)
  expect_identical(cvss_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"), 0)
  expect_identical(cvss_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), NA_real_)
  expect_identical(cvss_base_score("garbage"), NA_real_)
  expect_identical(cvss_base_score(NA_character_), NA_real_)
  # A missing metric or an unknown value gives no score.
  expect_identical(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"), NA_real_)
  expect_identical(cvss_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), NA_real_)
  # A metric given twice makes the vector invalid.
  expect_identical(cvss_base_score("CVSS:3.1/AV:N/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), NA_real_)
  expect_identical(cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/E:H"), NA_real_)
  expect_identical(cvss_base_score(character()), numeric())
  expect_identical(
    cvss_base_score(c("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "garbage")),
    c(9.8, NA)
  )
})

test_that("cvss_severity() follows the CVSS 3 thresholds", {
  expect_identical(
    cvss_severity(c(0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10, NA)),
    c("none", "low", "low", "medium", "medium", "high", "high", "critical", "critical", NA)
  )
})

test_that("cvss_method() names each vector's CVSS version", {
  expect_identical(
    cvss_method(c(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P",
      "garbage", NA
    )),
    c("CVSSv31", "CVSSv3", "CVSSv4", "CVSSv2", "other", "other")
  )
  expect_identical(cvss_method(character()), character())
  expect_identical(cvss_severity(numeric()), character())
})

test_that("the suite never reaches OSV", {
  expect_false(isTRUE(osv_download(osv_url, withr::local_tempfile(fileext = ".zip"))))
  expect_null(osv_lookup("CVE-2099-0001"))
  expect_true(is.function(osv_download_real))
  expect_true(is.function(osv_lookup_real))
})

test_that("osv_lookup() sends no request for an id that is not an OSV id", {
  calls <- new.env()
  calls$urls <- character()
  local_mocked_bindings(
    url = function(description, ...) {
      calls$urls <- c(calls$urls, description)
      stop("offline")
    },
    .package = "base"
  )
  expect_url_mocked(calls)
  calls$urls <- character()
  for (id in list("../etc", "..", "a..b", ".x", "1abc", "CVE-2099-0001 fakepkg", "", NA_character_,
                  c("CVE-2099-0001", "CVE-2099-0002"))) {
    expect_null(osv_lookup_real(id))
  }
  expect_identical(calls$urls, character())
  # The mock fails at the connection.
  expect_false(osv_lookup_real("CVE-2099-0001"))
  expect_false(osv_lookup_real("GHSA-xxxx-yyyy-zzzz"))
  expect_identical(
    calls$urls,
    c("https://api.osv.dev/v1/vulns/CVE-2099-0001", "https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz")
  )
  expect_identical(
    osv_id_ok(c("RSEC-2023-0", "CVE-2018-1000086", "GHSA-xxxx-yyyy-zzzz", "a.b:c_d", "..", "a..b", ".x", "1abc", "", NA)),
    c(TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE)
  )
})

test_that("osv_lookup() gives the record OSV sends, and NULL for anything else", {
  calls <- new.env()
  calls$urls <- character()
  respond <- function(text) {
    function(description, ...) {
      calls$urls <- c(calls$urls, description)
      rawConnection(charToRaw(text))
    }
  }
  record <- '{"id": "CVE-2099-0001", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}'
  local_mocked_bindings(url = respond(record), .package = "base")
  expect_url_mocked(calls)
  got <- osv_lookup_real("CVE-2099-0001")
  expect_identical(got$id, "CVE-2099-0001")
  expect_identical(got$severity[[1]]$score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  withr::with_options(list(sbom.osv_max_mb = 0.00001), expect_null(osv_lookup_real("CVE-2099-0001")))

  for (text in c("{not json", '["CVE-2099-0001"]', '{"id": "a", "id": "b"}', '{"id": "a"} // note')) {
    local_mocked_bindings(url = respond(text), .package = "base")
    expect_url_mocked(calls)
    expect_null(osv_lookup_real("CVE-2099-0001"))
  }
})

test_that("osv_lookup() gives FALSE when no answer came, and NULL for an HTTP error", {
  calls <- new.env()
  calls$urls <- character()
  fail <- function(warning) {
    function(description, ...) {
      calls$urls <- c(calls$urls, description)
      warning(sprintf(warning, description))
      stop("cannot open the connection to '", description, "'")
    }
  }
  local_mocked_bindings(url = fail("cannot open URL '%s': HTTP status was '404 Not Found'"), .package = "base")
  suppressWarnings(expect_url_mocked(calls))
  expect_null(osv_lookup_real("CVE-2099-0001"))
  for (warning in c("URL '%s': Timeout of 30 seconds was reached", "URL '%s': status was 'Couldn't resolve host name'")) {
    local_mocked_bindings(url = fail(warning), .package = "base")
    suppressWarnings(expect_url_mocked(calls))
    got <- osv_lookup_real("CVE-2099-0001")
    expect_false(got, label = warning)
    expect_identical(attr(got, "reason"), "the connection failed", label = warning)
  }
  # A read that stalls after the connection opened fails at the connection too.
  local_mocked_bindings(
    url = function(description, ...) {
      calls$urls <- c(calls$urls, description)
      rawConnection(raw(0))
    },
    .package = "base"
  )
  expect_url_mocked(calls)
  local_mocked_bindings(read_capped = function(con, cap) stop("Timeout was reached"))
  expect_false(osv_lookup_real("CVE-2099-0001"))
})

test_that("osv_download() gives TRUE, or FALSE with a fixed reason", {
  dest <- withr::local_tempfile(fileext = ".zip")
  timeout <- getOption("timeout")
  calls <- new.env()
  calls$urls <- character()
  record <- function(url) calls$urls <- c(calls$urls, url)
  local_mocked_bindings(
    download.file = function(url, destfile, ...) {
      record(url)
      calls$timeout <- getOption("timeout")
      calls$args <- list(...)[c("mode", "quiet")]
      writeBin(as.raw(1:3), destfile)
      0L
    },
    .package = "utils"
  )
  expect_download_mocked(calls)
  expect_true(osv_download_real(osv_url, dest))
  expect_identical(utils::tail(calls$urls, 1L), osv_url)
  expect_identical(calls$timeout, 300)
  expect_identical(calls$args, list(mode = "wb", quiet = TRUE))
  expect_identical(getOption("timeout"), timeout)

  local_mocked_bindings(
    download.file = function(url, destfile, ...) {
      record(url)
      warning("cannot open URL '", url, "': HTTP status was '404 Not Found'")
      stop("cannot open URL '", url, "'")
    },
    .package = "utils"
  )
  expect_download_mocked(calls)
  got <- osv_download_real(osv_url, dest)
  expect_false(got)
  expect_identical(attr(got, "reason"), "HTTP status 404")

  local_mocked_bindings(
    download.file = function(url, destfile, ...) {
      record(url)
      stop("Could not resolve host: /home/user/secret")
    },
    .package = "utils"
  )
  expect_download_mocked(calls)
  expect_identical(attr(osv_download_real(osv_url, dest), "reason"), "the connection failed")
})
