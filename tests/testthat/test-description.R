test_that("parse_dep_field() splits a dependency field as written", {
  d <- parse_dep_field("cli (>= 3.6.2), generics,\n    glue (>= 1.3.2)", "Imports")
  expect_equal(d$name, c("cli", "generics", "glue"))
  expect_equal(d$constraint, c(">= 3.6.2", NA, ">= 1.3.2"))
  expect_equal(d$spec, c("cli (>= 3.6.2)", "generics", "glue (>= 1.3.2)"))
  expect_equal(unique(d$field), "Imports")
  expect_equal(nrow(parse_dep_field(NA, "Suggests")), 0L)
  expect_equal(nrow(parse_dep_field("", "Suggests")), 0L)
})

test_that("parse_dep_field() normalises whitespace and drops empty entries", {
  d <- parse_dep_field("a (>=\n   1.0),\n", "Depends")
  expect_equal(d$spec, "a (>= 1.0)")
  expect_equal(d$constraint, ">= 1.0")
})

test_that("parse_maintainer() keeps the name alone, as R Observatory does", {
  expect_equal(parse_maintainer("Hadley Wickham <hadley@posit.co>"),
               c(name = "Hadley Wickham", email = "hadley@posit.co"))
  expect_equal(parse_maintainer("\"R Core\" <r@r-project.org>")[["name"]], "R Core")
  expect_equal(parse_maintainer(NA_character_), c(name = NA_character_, email = NA_character_))
})

test_that("parse_authors() reads Authors@R without running other code", {
  a <- parse_authors('c(person("Ada", "Lovelace", email = "ada@example.org", role = c("aut", "cre"),
    comment = c(ORCID = "0000-0002-1825-0097")), person("Org", role = "cph"))')
  expect_equal(a$name, c("Ada Lovelace", "Org"))
  expect_equal(a$roles, c("aut, cre", "cph"))
  expect_equal(a$orcid, c("0000-0002-1825-0097", NA))
  withr::local_envvar(SBOM_TEST_RAN = NA)
  expect_null(parse_authors('{Sys.setenv(SBOM_TEST_RAN = "yes"); person("A", "B")}'))
  expect_equal(Sys.getenv("SBOM_TEST_RAN"), "")
})

test_that("parse_authors() returns NULL for non-person results and syntax errors", {
  expect_null(parse_authors("1 + 1"))
  expect_null(parse_authors("person("))
  expect_null(parse_authors(NA_character_))
})

test_that("read_description() reads a directory, a DESCRIPTION file and a tarball", {
  dir <- test_path("fixtures/pkgs/srcpkg")
  tmp <- withr::local_tempdir()
  tarball <- file.path(tmp, "srcpkg_0.1.0.tar.gz")
  withr::with_dir(test_path("fixtures/pkgs"), utils::tar(tarball, "srcpkg", compression = "gzip"))
  for (p in c(dir, file.path(dir, "DESCRIPTION"), tarball)) {
    expect_equal(read_description(p)[["Package"]], "srcpkg")
  }
})

test_that("read_description() errors on a missing path and tolerates missing fields", {
  expect_error(read_description(file.path(tempdir(), "nope")), "does not exist")
  empty <- withr::local_tempdir()
  expect_error(read_description(empty), "DESCRIPTION")
  writeLines(c("Package: bare", "Version: 1"), file.path(empty, "DESCRIPTION"))
  d <- read_description(empty)
  expect_false("License" %in% names(d))
})

test_that("read_description() converts a latin1 DESCRIPTION to UTF-8", {
  d <- read_description(local_latin1_pkg())
  expect_equal(d[["Maintainer"]], "Gábor Csárdi <g@example.org>")
  expect_true(validUTF8(d[["Maintainer"]]))
})

test_that("desc_maintainer() falls back to the cre in Authors@R", {
  d <- read_description(test_path("fixtures/pkgs/srcpkg"))
  expect_equal(desc_maintainer(d)[["name"]], "Ada Lovelace")
  expect_equal(desc_maintainer(c(Package = "x")), c(name = NA_character_, email = NA_character_))
  expect_equal(desc_maintainer(c(Maintainer = "A B <a@b.c>"))[["name"]], "A B")
})

test_that("parse_authors() treats an unnamed comment as no ORCID", {
  a <- parse_authors('person("A", "B", comment = "note", role = "cre")')
  expect_equal(a$name, "A B")
  expect_equal(a$orcid, NA_character_)
})

test_that("read_description() tolerates an unsupported Encoding", {
  dir <- withr::local_tempdir()
  lines <- c("Package: odd", "Version: 1.0", "Encoding: bogus",
             "Maintainer: Gábor <g@example.org>", "Title: Café")
  con <- file(file.path(dir, "DESCRIPTION"), "wb")
  writeLines(c(lines[1:3], lines[4]), con, useBytes = TRUE)
  writeLines(iconv(lines[5], from = "UTF-8", to = "latin1"), con, useBytes = TRUE)
  close(con)
  d <- read_description(dir)
  expect_equal(d[["Maintainer"]], "Gábor <g@example.org>")
  expect_equal(d[["Title"]], "Café")
  expect_true(all(validUTF8(d)))
})

test_that("an undeclared encoding is UTF-8 when valid, otherwise latin1", {
  d <- read_description(local_latin1_pkg(declare = FALSE))
  expect_equal(d[["Maintainer"]], "Gábor Csárdi <g@example.org>")
  expect_true(all(validUTF8(d)))
  utf8 <- write_description_bytes(withr::local_tempdir(), c(
    "Package: u", "Version: 1", "Maintainer: Gábor Csárdi <g@example.org>", "Title: Café"
  ))
  d <- read_description(utf8)
  expect_equal(d[["Maintainer"]], "Gábor Csárdi <g@example.org>")
  expect_equal(Encoding(d[["Title"]]), "UTF-8")
})

test_that("DESCRIPTION text is decoded by its bytes, not by the locale", {
  local_c_ctype()
  utf8 <- write_description_bytes(withr::local_tempdir(), c(
    "Package: u", "Version: 1", "Encoding: UTF-8", "Maintainer: Gábor Csárdi <g@example.org>"
  ))
  bogus <- write_description_bytes(withr::local_tempdir(), c(
    "Package: odd", "Version: 1", "Encoding: bogus", "Maintainer: Gábor Csárdi <g@example.org>"
  ), "latin1")
  paths <- list(
    utf8 = utf8, latin1 = local_latin1_pkg(), undeclared = local_latin1_pkg(declare = FALSE),
    bogus = bogus
  )
  for (kind in names(paths)) {
    d <- read_description(paths[[kind]])
    expect_equal(d[["Maintainer"]], "Gábor Csárdi <g@example.org>", label = kind)
    expect_true(all(validUTF8(d)), label = kind)
    expect_equal(
      desc_maintainer(d), c(name = "Gábor Csárdi", email = "g@example.org"),
      label = kind
    )
  }
})

test_that("parse_authors() keeps non-ASCII names under a C locale", {
  local_c_ctype()
  a <- parse_authors('person("Gábor", "Csárdi", role = c("aut", "cre"))')
  expect_equal(a$name, "Gábor Csárdi")
  expect_true(validUTF8(a$name))
  expect_equal(Encoding(a$name), "UTF-8")
})
