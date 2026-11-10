ts <- as.POSIXct("2026-01-01", tz = "UTC")

# Repository metadata as pak::meta_list() gives it, with jsonlite 2.0.0 and
# no cli 3.6.5, which the analysis example's lockfile pins.
fake_metadata <- function() {
  data.frame(
    package = c("jsonlite", "jsonlite", "cli"),
    version = c("2.0.0", "2.0.0", "3.6.6"),
    platform = c("source", "aarch64-apple-darwin23", "source"),
    sha256 = c(strrep("a", 64), strrep("b", 64), strrep("c", 64)),
    md5sum = c(strrep("1", 32), strrep("2", 32), strrep("3", 32)),
    target = c("src/contrib/jsonlite_2.0.0.tar.gz", "bin/macosx/jsonlite_2.0.0.tgz",
      "src/contrib/cli_3.6.6.tar.gz"),
    mirror = "https://cloud.r-project.org",
    stringsAsFactors = FALSE
  )
}

analysis_lock <- function() file.path(sbom_example("analysis"), "renv.lock")

test_that("checksums = TRUE records each source tarball's SHA-256, MD5 and download location", {
  local_mocked_bindings(repo_metadata = function(call) fake_metadata())
  x <- sbom_renv(analysis_lock(), system = FALSE, timestamp = ts, checksums = TRUE)
  comps <- sbom_components(x)
  json <- comps[comps$name == "jsonlite", ]
  hashes <- json$hashes[[1]]
  expect_equal(hashes$alg, c("SHA-256", "MD5"))
  expect_equal(hashes$content, c(strrep("a", 64), strrep("1", 32)))
  expect_equal(unique(hashes$of), "source tarball")
  expect_equal(json$package_file_name, "jsonlite_2.0.0.tar.gz")
  expect_equal(json$download_location, "https://cloud.r-project.org/src/contrib/jsonlite_2.0.0.tar.gz")
  expect_true(any(x$metadata$inputs$kind == "checksums" &
    x$metadata$inputs$path == "https://cloud.r-project.org"))
  expect_true(any(startsWith(
    x$metadata$notes, "Checksums of source packages come from the repository metadata that pak read."
  )))
})

test_that("a package whose version the metadata lacks is named in one issue", {
  local_mocked_bindings(repo_metadata = function(call) fake_metadata())
  x <- sbom_renv(analysis_lock(), system = FALSE, timestamp = ts, checksums = TRUE)
  comps <- sbom_components(x)
  expect_equal(nrow(comps$hashes[[which(comps$name == "cli")]]), 0L)
  issues <- sbom_issues(x)
  missing <- issues[issues$code == "checksums-not-found", ]
  expect_equal(nrow(missing), 1L)
  expect_equal(missing$ref, x$metadata$root)
  expect_match(missing$message, "cli 3.6.5", fixed = TRUE)
})

test_that("checksums = FALSE, the default, reads no metadata", {
  local_mocked_bindings(repo_metadata = function(call) stop("read metadata"))
  x <- sbom_renv(analysis_lock(), system = FALSE, timestamp = ts)
  expect_false("checksums" %in% x$metadata$inputs$kind)
  expect_true(all(vapply(sbom_components(x)$hashes, nrow, 0L) == 0L))
})

test_that("checksums need pak, a usable answer from it, and TRUE or FALSE", {
  local_mocked_bindings(pak_function = function(name) NULL)
  expect_error(sbom_renv(analysis_lock(), system = FALSE, checksums = TRUE), "pak")
  local_mocked_bindings(pak_function = function(name) function() stop("no connection"))
  expect_error(sbom_renv(analysis_lock(), system = FALSE, checksums = TRUE),
    "could not read the repository metadata")
  expect_error(sbom_renv(analysis_lock(), system = FALSE, checksums = "yes"), "`checksums` must be")
  expect_error(sbom(sbom_example("analysis", copy = TRUE), checksums = NA), "`checksums` must be")
})

test_that("sbom() looks checksums up once, for a folder or for several paths", {
  calls <- new.env()
  calls$n <- 0L
  local_mocked_bindings(repo_metadata = function(call) {
    calls$n <- calls$n + 1L
    fake_metadata()
  })
  x <- sbom(sbom_example("analysis", copy = TRUE), system = FALSE, timestamp = ts, checksums = TRUE)
  expect_equal(calls$n, 1L)
  expect_equal(nrow(sbom_components(x)$hashes[[which(sbom_components(x)$name == "jsonlite")]]), 2L)
  calls$n <- 0L
  y <- sbom(c(sbom_example("analysis", copy = TRUE), sbom_example("study", copy = TRUE)),
    name = "suite", system = FALSE, timestamp = ts, checksums = TRUE)
  expect_equal(calls$n, 1L)
  expect_equal(sum(sbom_issues(y)$code == "checksums-not-found"), 1L)
})

test_that("checksums are written in every format and the documents stay valid", {
  local_mocked_bindings(repo_metadata = function(call) fake_metadata())
  x <- sbom_renv(analysis_lock(), system = FALSE, timestamp = ts, checksums = TRUE)
  spdx <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(x, spdx)
  doc <- jsonlite::fromJSON(spdx, simplifyVector = FALSE)
  pkg <- Filter(function(p) identical(p$name, "jsonlite"), doc$packages)[[1]]
  expect_setequal(vapply(pkg$checksums, function(c) c$algorithm, ""), c("SHA256", "MD5"))
  expect_equal(pkg$downloadLocation, "https://cloud.r-project.org/src/contrib/jsonlite_2.0.0.tar.gz")
  for (ext in c(".spdx.json", ".cdx.json", ".spdx3.jsonld")) {
    f <- withr::local_tempfile(fileext = ext)
    write_sbom(x, f)
    expect_false(identical(validate_sbom(f, profile = "none")$status, "fail"), info = ext)
    back <- sbom_components(read_sbom(f))
    expect_true(any(vapply(back$hashes[back$name == "jsonlite"], function(h) "SHA-256" %in% h$alg, NA)),
      info = ext)
  }
})
