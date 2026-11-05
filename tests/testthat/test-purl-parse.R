test_that("valid purls are split into their parts", {
  res <- purl_parse("pkg:cran/dplyr@1.2.1")
  expect_named(res, c("purl", "valid", "problem", "type", "namespace", "name",
                      "version", "qualifiers", "subpath"))
  expect_true(res$valid)
  expect_true(is.na(res$problem))
  expect_identical(res$type, "cran")
  expect_identical(res$name, "dplyr")
  expect_identical(res$version, "1.2.1")
  expect_true(is.na(res$namespace))
  expect_true(is.na(res$subpath))

  res <- purl_parse("pkg:github/tidyverse/dplyr@abc123")
  expect_true(res$valid)
  expect_identical(res$namespace, "tidyverse")

  res <- purl_parse("pkg:npm/%40angular/core@1.0.0")
  expect_true(res$valid)
  expect_identical(res$namespace, "@angular")
  expect_identical(res$name, "core")

  res <- purl_parse("pkg:maven/org.apache/commons@1.0?type=jar#sub/path")
  expect_true(res$valid)
  expect_identical(res$qualifiers, "type=jar")
  expect_identical(res$subpath, "sub/path")

  res <- purl_parse("pkg:cran/x?repository_url=https://bioconductor.org/packages/3.20/bioc")
  expect_true(res$valid)
  expect_identical(res$qualifiers, "repository_url=https://bioconductor.org/packages/3.20/bioc")
})

test_that("invalid purls have a problem", {
  bad <- c("cran/dplyr", "pkg:/dplyr", "pkg:1abc/x", "pkg:cran/", "pkg:cran/@1.0",
           "pkg:cran/dpl%zzr", "pkg:cran/x?a=1&a=2", "pkg:cran/x?=1", "pkg:cran/x@")
  res <- purl_parse(bad)
  expect_identical(res$purl, bad)
  expect_false(any(res$valid))
  expect_false(anyNA(res$problem))
  expect_true(all(nzchar(res$problem)))
  expect_match(res$problem[res$purl == "pkg:cran/"], "no name")
})

test_that("every purl that purl() builds parses", {
  built <- c(
    purl(c("dplyr", "x"), c("1.2.1", NA)),
    purl("srcpkg", "abc123", source = "github", namespace = "example"),
    purl("x", "1.0", repository_url = "https://bioconductor.org/packages/3.20/bioc")
  )
  res <- purl_parse(built)
  expect_true(all(res$valid))
  expect_identical(res$name, c("dplyr", "x", "srcpkg", "x"))
})

test_that("purl_parse() is vectorised and handles NA and empty input", {
  expect_identical(nrow(purl_parse(character(0))), 0L)
  res <- purl_parse(c("pkg:cran/a", NA))
  expect_identical(res$valid, c(TRUE, FALSE))
  expect_false(is.na(res$problem[2]))
})

test_that("hostile input is invalid, never an error", {
  res <- purl_parse(c("pkg:cran/a%00b", "pkg:cran/a%00", "pkg:cran/x\xff", NA))
  expect_false(any(res$valid))
  expect_identical(res$problem[1:2], rep("it encodes a NUL character", 2))
  expect_identical(res$problem[3], "it is not valid UTF-8 text")
  expect_identical(res$problem[4], "it is missing")
  expect_false(purl_parse("pkg:cran/a%c3")$valid)
})

test_that("an unencoded @ in the namespace gets a clear problem", {
  res <- purl_parse(c("pkg:npm/@angular/core", "pkg:npm/foo/@angular/core", "pkg:github/a/b@1/2"))
  expect_false(any(res$valid))
  expect_match(res$problem, "@ in its namespace or name that is not percent-encoded", fixed = TRUE)
  expect_match(purl_parse("pkg:cran/@1.0")$problem, "no name")
})

test_that("the subpath is split off before the qualifiers", {
  res <- purl_parse("pkg:cran/x#a/b?c=d")
  expect_true(res$valid)
  expect_identical(res$subpath, "a/b?c=d")
  expect_true(is.na(res$qualifiers))
  res <- purl_parse("pkg:cran/x?a=b#c")
  expect_identical(res$qualifiers, "a=b")
  expect_identical(res$subpath, "c")
})
