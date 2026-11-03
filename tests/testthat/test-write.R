test_that("format comes from the extension", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, file.path(dir, "a.cdx.xml"))
  expect_match(readLines(file.path(dir, "a.cdx.xml"), n = 2)[2], "cyclonedx.org/schema/bom/1.6")
  expect_error(write_sbom(x, file.path(dir, "a.txt")), "\\.cdx\\.json")
  expect_error(write_sbom(x, file.path(dir, "a.spdx.json"), version = "1.6"), "version")
})

test_that("format = 'all' writes every format with R Observatory's names", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, dir, format = "all")
  expect_setequal(list.files(dir), c("srcpkg-0.1.0.cdx.json", "srcpkg-0.1.0.cdx.xml", "srcpkg-0.1.0.spdx.json", "srcpkg-0.1.0.spdx.yaml", "srcpkg-0.1.0.spdx.xml", "srcpkg-0.1.0.spdx", "srcpkg-0.1.0.spdx3.jsonld", "srcpkg-0.1.0.swidtag"))
})

test_that("format = 'all' creates a missing directory and sanitizes the stem", {
  x <- sbom_installed(lib = local_fake_lib(list()))
  dir <- file.path(withr::local_tempdir(), "new", "out")
  write_sbom(x, dir, format = "all", version = "1.5")
  expect_true(all(startsWith(list.files(dir), "R-library.")))
  expect_match(readLines(file.path(dir, "R-library.cdx.json"), n = 3)[2], "1.5", fixed = TRUE)
})

test_that("bad input is rejected", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  expect_error(write_sbom(list(), file.path(dir, "a.cdx.json")), "sbom")
  expect_error(write_sbom(x, file.path(dir, "a.cdx.json"), version = "9.9"), "1.6")
  expect_error(write_sbom(x, file.path(dir, "a.json"), format = "nope"), "cyclonedx-json")
})

test_that("sbom_formats() lists the registry", {
  f <- sbom_formats()
  expect_equal(f$format, c("cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml", "spdx-tv", "spdx3-jsonld", "swid"))
  expect_equal(f$extension, c(".cdx.json", ".cdx.xml", ".spdx.json", ".spdx.yaml", ".spdx.xml", ".spdx", ".spdx3.jsonld", ".swidtag"))
  expect_equal(f$versions, c(rep("1.4, 1.5, 1.6, 1.7", 2), rep("2.2, 2.3", 4), "3.0.1", "2015"))
  expect_equal(f$default_version, c("1.6", "1.6", "2.3", "2.3", "2.3", "2.3", "3.0.1", "2015"))
})

test_that("output is byte-identical across runs with SOURCE_DATE_EPOCH", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  d1 <- withr::local_tempdir(); d2 <- withr::local_tempdir()
  write_sbom(sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib()), d1, format = "all")
  write_sbom(sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib()), d2, format = "all")
  for (f in list.files(d1)) {
    expect_identical(readBin(file.path(d1, f), "raw", 1e6), readBin(file.path(d2, f), "raw", 1e6), label = f)
    raw <- readBin(file.path(d1, f), "raw", 1e6)
    expect_false(as.raw(13) %in% raw)
    expect_equal(raw[length(raw)], as.raw(10))
  }
  cdx <- paste(readLines(file.path(d1, "srcpkg-0.1.0.cdx.json")), collapse = "")
  expect_match(cdx, "2023-11-14T22:13:20Z")
  expect_match(cdx, "The timestamp comes from the SOURCE_DATE_EPOCH environment variable.", fixed = TRUE)
})

test_that("a latin1 maintainer is written as UTF-8", {
  pkg <- local_latin1_pkg()
  x <- sbom_package(pkg, lib = local_fake_lib(list()))
  tf <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(x, tf)
  txt <- readLines(tf, encoding = "UTF-8")
  expect_true(any(grepl("Gábor Csárdi", txt, fixed = TRUE)))
})

test_that("latin1 maintainers are written as UTF-8 bytes in a C locale", {
  local_c_ctype()
  for (declare in c(TRUE, FALSE)) {
    x <- sbom_package(local_latin1_pkg(declare = declare), lib = local_fake_lib(list()))
    for (ext in c(".cdx.json", ".cdx.xml", ".spdx.json")) {
      tf <- withr::local_tempfile(fileext = ext)
      write_sbom(x, tf)
      raw <- readBin(tf, "raw", 1e6)
      expect_length(grepRaw(charToRaw("Gábor Csárdi"), raw, fixed = TRUE), 1L)
    }
  }
})

test_that("a failing writer leaves existing files untouched and writes nothing", {
  reg <- format_registry()
  reg[["spdx-json"]]$writer <- function(x, version) stop("boom")
  local_mocked_bindings(format_registry = function() reg)
  x <- fixture_sbom(); dir <- withr::local_tempdir()

  f <- file.path(dir, "a.spdx.json")
  writeBin(charToRaw("keep\n"), f)
  expect_error(write_sbom(x, f), "boom")
  expect_identical(readBin(f, "raw", 100), charToRaw("keep\n"))

  out <- file.path(dir, "out")
  expect_error(write_sbom(x, out, format = "all"), "boom")
  expect_false(dir.exists(out))

  dir.create(out)
  expect_error(write_sbom(x, out, format = "all"), "boom")
  expect_length(list.files(out), 0L)
})

test_that("version applies to every format that lists it", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, dir, format = "all", version = "2.2")
  expect_match(paste(readLines(file.path(dir, "srcpkg-0.1.0.spdx.json")), collapse = ""), "SPDX-2.2")
  expect_match(readLines(file.path(dir, "srcpkg-0.1.0.cdx.xml"), n = 2)[2], "bom/1.6")
  expect_error(write_sbom(x, file.path(dir, "a.spdx.json"), version = "1.6"), "2.2")
  expect_error(write_sbom(x, dir, format = "all", version = "9.9"), "version")
})
