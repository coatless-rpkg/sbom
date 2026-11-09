test_that("the CSV inventory has one quoted row per component", {
  x <- fixture_sbom()
  txt <- csv_inventory(x)
  expect_match(txt, '^"ref","name","version","version_is","type","ecosystem","scope","purl","supplier",')
  df <- utils::read.csv(text = txt, colClasses = "character", na.strings = "", encoding = "UTF-8")
  expect_equal(nrow(df), nrow(sbom_components(x)))
  expect_equal(df$ref[1], "local/srcpkg")
  expect_equal(names(df)[ncol(df)], "parent")
  expect_equal(df$license[df$ref == "pkg:cran/cranpkg@1.2.0"], "GPL-2.0-only OR GPL-3.0-only")
  expect_match(df$issues[df$name == "localpkg"], "local source")
})

test_that("commas, quotes and non-ASCII survive", {
  local_c_ctype()
  x <- fixture_sbom()
  x$components$maintainer[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- 'Gábor, "the" Csárdi'
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", encoding = "UTF-8")
  expect_equal(df$maintainer[df$ref == "pkg:cran/cranpkg@1.2.0"], 'Gábor, "the" Csárdi')
})

test_that("format = 'all' leaves the inventory out, and .csv writes it", {
  skip_on_cran()
  x <- fixture_sbom(); dir <- withr::local_tempdir()
  write_sbom(x, dir, format = "all")
  expect_false(any(grepl("\\.csv$", list.files(dir))))
  write_sbom(x, file.path(dir, "inventory.csv"))
  expect_true(file.exists(file.path(dir, "inventory.csv")))
  expect_error(write_sbom(x, file.path(dir, "i.csv"), version = "1.6"), "version")
})

test_that("every field is quoted, empty ones included, and lines end in LF", {
  txt <- csv_inventory(fixture_sbom())
  lines <- strsplit(txt, "\n", fixed = TRUE)[[1]]
  expect_true(endsWith(txt, "\n"))
  expect_false(grepl("\r", txt, fixed = TRUE))
  expect_true(all(startsWith(lines, "\"") & endsWith(lines, "\"")))
  df <- utils::read.csv(text = txt, colClasses = "character", na.strings = NULL)
  expect_identical(df$purl[1], "")
  expect_identical(df$supplier[1], "")
})

test_that("the sha256 and asserted columns are filled from the component tables", {
  x <- fixture_sbom()
  i <- which(x$components$ref == "pkg:cran/cranpkg@1.2.0")
  x$components$hashes[[i]] <- data.frame(
    alg = c("SHA-1", "SHA-256"), content = c("aa", "bb"), of = "package",
    stringsAsFactors = FALSE
  )
  x$components$asserted[[i]] <- data.frame(
    field = c("license", "homepage"), value = c("MIT", "https://e.org"),
    asserted_by = "me", reason = "checked", stringsAsFactors = FALSE
  )
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = "")
  expect_equal(df$sha256[df$ref == "pkg:cran/cranpkg@1.2.0"], "bb")
  expect_equal(
    df$asserted[df$ref == "pkg:cran/cranpkg@1.2.0"],
    "license=MIT (me: checked); homepage=https://e.org (me: checked)"
  )
})

test_that("free-text cells that a spreadsheet would evaluate get a leading apostrophe", {
  skip_on_cran()
  payloads <- c("=cmd|' /C calc'!A0", "+1", "-2+3", "@SUM(A1)", "\tx")
  for (p in payloads) {
    x <- fixture_sbom()
    x$components$maintainer[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- p
    df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
    expect_identical(df$maintainer[df$ref == "pkg:cran/cranpkg@1.2.0"], paste0("'", p))
  }
  x <- fixture_sbom()
  x$components$maintainer[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- "Grace Hopper"
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
  expect_identical(df$maintainer[df$ref == "pkg:cran/cranpkg@1.2.0"], "Grace Hopper")
})

test_that("a value a spreadsheet would evaluate gets a leading apostrophe in any column", {
  skip_on_cran()
  fields <- c(
    ref = "ref", name = "name", version = "version", version_is = "version_is",
    type = "type", ecosystem = "ecosystem", scope = "scope", purl = "purl",
    supplier = "supplier_name", maintainer = "maintainer", license = "license_spdx",
    license_as_written = "license_as_written", published = "published",
    homepage = "homepage", vcs_url = "vcs_url",
    download_location = "download_location", doi = "doi", evidence = "evidence"
  )
  for (col in names(fields)) {
    for (p in c("=1+1", "-1")) {
      x <- fixture_sbom()
      x$components[[fields[[col]]]][x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- p
      df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
      expect_true(paste0("'", p) %in% df[[col]], label = paste(col, p))
      expect_false(p %in% df[[col]], label = paste(col, p))
    }
  }
  x <- fixture_sbom()
  i <- which(x$components$ref == "pkg:cran/cranpkg@1.2.0")
  x$components$hashes[[i]] <- data.frame(alg = "SHA-256", content = "=1+1", of = "package")
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
  expect_identical(df$sha256[df$ref == "pkg:cran/cranpkg@1.2.0"], "'=1+1")
})

test_that("a real version is left as it is", {
  x <- fixture_sbom()
  x$components$version[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- "1.0-2"
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
  expect_identical(df$version[df$ref == "pkg:cran/cranpkg@1.2.0"], "1.0-2")
})

test_that("a package name and publication date from DESCRIPTION are neutralized", {
  src <- withr::local_tempdir()
  write_text(paste0(
    "Package: =2+5\nVersion: 1.0\nLicense: MIT\nMaintainer: A <a@b.c>\n",
    "Date/Publication: =1+1\n"
  ), file.path(src, "DESCRIPTION"))
  x <- sbom_package(src, lib = local_fake_lib(list()))
  df <- utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
  expect_identical(df$name[1], "'=2+5")
  expect_identical(df$published[1], "'=1+1")
})

test_that("a leading carriage return is neutralized in the written text", {
  x <- fixture_sbom()
  x$components$maintainer[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- "\rx"
  expect_match(csv_inventory(x), "\"'\rx\"", fixed = TRUE)
})

test_that("a written CSV starts with a UTF-8 byte-order mark; the inventory text has none", {
  local_c_ctype()
  x <- fixture_sbom()
  x$components$maintainer[x$components$ref == "pkg:cran/cranpkg@1.2.0"] <- "G\u00e1bor Cs\u00e1rdi"
  txt <- csv_inventory(x)
  expect_false(startsWith(txt, "\ufeff"))
  tf <- withr::local_tempfile(fileext = ".csv")
  write_sbom(x, tf)
  raw <- readBin(tf, "raw", 1e6)
  expect_identical(raw[1:3], as.raw(c(0xef, 0xbb, 0xbf)))
  expect_identical(raw[-(1:3)], charToRaw(txt))
  expect_length(grepRaw(charToRaw("G\u00e1bor Cs\u00e1rdi"), raw, fixed = TRUE), 1L)
})

test_that("read.csv() with fileEncoding = 'UTF-8-BOM' reads a written CSV", {
  x <- fixture_sbom()
  tf <- withr::local_tempfile(fileext = ".csv")
  write_sbom(x, tf)
  df <- utils::read.csv(tf, colClasses = "character", na.strings = NULL, fileEncoding = "UTF-8-BOM")
  expect_identical(names(df)[1], "ref")
  expect_identical(
    df,
    utils::read.csv(text = csv_inventory(x), colClasses = "character", na.strings = NULL)
  )
  expect_identical(nrow(df), nrow(sbom_components(x)))
})

test_that("the version error says the CSV inventory takes no version", {
  x <- fixture_sbom()
  tf <- withr::local_tempfile(fileext = ".csv")
  err <- expect_error(write_sbom(x, tf, version = "1.6"), "is not a version of any format")
  expect_match(conditionMessage(err), "CSV inventory (takes no version)", fixed = TRUE)
  expect_false(grepl("()", conditionMessage(err), fixed = TRUE))
})
