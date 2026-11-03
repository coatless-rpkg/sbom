test_that("format comes from the extension", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, file.path(dir, "a.cdx.xml"))
  expect_match(readLines(file.path(dir, "a.cdx.xml"), n = 2)[2], "cyclonedx.org/schema/bom/1.6")
  expect_error(write_sbom(x, file.path(dir, "a.txt")), "\\.cdx\\.json")
  expect_error(write_sbom(x, file.path(dir, "a.spdx.json"), version = "1.6"), "version")
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

test_that("format = 'all' writes the eight files of the dplyr set", {
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, dir, format = "all")
  expect_setequal(list.files(dir), paste0("srcpkg-0.1.0", c(".cdx.json", ".cdx.xml", ".spdx.json",
    ".spdx.yaml", ".spdx.xml", ".spdx", ".spdx3.jsonld", ".swidtag")))
})

test_that("every format is byte-identical across runs, also in a C locale", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  test_env <- environment()
  d1 <- withr::local_tempdir(); d2 <- withr::local_tempdir()
  run <- function(d) {
    x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(env = test_env))
    write_sbom(x, d, format = "all"); write_sbom(x, file.path(d, "inv.csv"))
  }
  run(d1)
  local({ local_c_ctype(); run(d2) })
  expect_length(list.files(d1), 9L)
  for (f in list.files(d1)) {
    a <- readBin(file.path(d1, f), "raw", 1e7)
    expect_identical(a, readBin(file.path(d2, f), "raw", 1e7), label = f)
    expect_false(as.raw(13) %in% a); expect_equal(a[length(a)], as.raw(10))
  }
  cdx <- paste(readLines(file.path(d1, "srcpkg-0.1.0.cdx.json")), collapse = "")
  expect_match(cdx, "2023-11-14T22:13:20Z")
  expect_match(cdx, "The timestamp comes from the SOURCE_DATE_EPOCH environment variable.", fixed = TRUE)
})

test_that("a library SBOM, and an SBOM with overrides and a latin1 maintainer, validate in every format", {
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  local_c_ctype()
  ov <- data.frame(component = "localpkg", field = "license_spdx", value = "Apache-2.0",
                   asserted_by = "Legal", reason = "Reviewed")
  latin <- local_latin1_pkg()
  sboms <- list(library = sbom_installed(lib = fixture_lib()),
                asserted = sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov),
                latin1 = sbom_package(latin, lib = local_fake_lib(list())))
  checks <- list(c("cyclonedx-json", "1.6"), c("cyclonedx-xml", "1.6"), c("spdx-json", "2.3"), c("spdx-json", "2.2"),
                 c("spdx-yaml", "2.3"), c("spdx-xml", "2.3"), c("spdx-tv", "2.3"), c("spdx3-jsonld", "3.0.1"),
                 c("swid", "2015"))
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  partial <- c("spdx-xml", "spdx-tv", "spdx3-jsonld")
  for (nm in names(sboms)) for (ck in checks) {
    tf <- withr::local_tempfile(fileext = ext[[ck[1]]])
    write_sbom(sboms[[nm]], tf, format = ck[1], version = ck[2])
    expect_identical(schema_validate(tf, ck[1], ck[2])$status,
                     if (ck[1] %in% partial) "partial" else "pass", label = paste(nm, ck[1], ck[2]))
    if (nm == "latin1") expect_true(any(grepl("G\u00e1bor Cs\u00e1rdi", readLines(tf, encoding = "UTF-8"), fixed = TRUE)), label = ck[1])
    # SWID describes only the root, so it carries no asserted component.
    if (nm == "asserted" && ck[1] != "swid") expect_true(any(grepl(if (startsWith(ck[1], "cyclonedx")) "asserted by Legal" else "Asserted by Legal",
                                         readLines(tf, encoding = "UTF-8"))), label = ck[1])
  }
  acsv <- withr::local_tempfile(fileext = ".csv")
  write_sbom(sboms$asserted, acsv, format = "csv")
  inv <- utils::read.csv(acsv, stringsAsFactors = FALSE, fileEncoding = "UTF-8-BOM")
  expect_identical(inv$asserted[inv$name == "localpkg"], "license_spdx=Apache-2.0 (Legal: Reviewed)")
  csv <- withr::local_tempfile(fileext = ".csv")
  write_sbom(sboms$latin1, csv, format = "csv")
  expect_length(grepRaw(charToRaw("G\u00e1bor Cs\u00e1rdi"), readBin(csv, "raw", 1e6), fixed = TRUE), 1L)
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
