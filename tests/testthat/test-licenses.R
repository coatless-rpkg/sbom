test_that("license_spdx() follows R's license database and R Observatory's rule", {
  expect_equal(license_spdx("MIT + file LICENSE"), "MIT")
  expect_equal(license_spdx("GPL-2 | GPL-3"), "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(license_spdx("GPL (>= 2)"), "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(license_spdx("BSD_3_clause + file LICENSE"), "BSD-3-Clause")
  expect_equal(license_spdx("Apache License (== 2.0)"), "Apache-2.0")
  expect_true(is.na(license_spdx("file LICENSE")))
  expect_true(is.na(license_spdx("GPL-3 | file LICENSE")))
  # R's license db marks GPL-2 as not extensible (a file may add terms) but GPL-3 as extensible.
  expect_true(is.na(license_spdx("GPL-2 + file LICENSE")))
  expect_equal(license_spdx("GPL-3 + file LICENSE"), "GPL-3.0-only")
  # The other licenses R's db marks extensible keep their expression too.
  expect_equal(license_spdx("LGPL-3 + file LICENSE"), "LGPL-3.0-only")
  expect_equal(license_spdx("AGPL-3 + file LICENSE"), "AGPL-3.0-only")
  expect_equal(license_spdx("CC BY-SA 4.0 + file LICENSE"), "CC-BY-SA-4.0")
  expect_true(is.na(license_spdx("Apache License (== 2.0) + file LICENSE")))
  expect_true(is.na(license_spdx("GPL-3 | Unlimited")))
  expect_true(is.na(license_spdx("Unlimited")))
  expect_true(is.na(license_spdx("Some Custom License v9")))
  expect_equal(license_spdx("  MIT +   file LICENSE "), "MIT")
  expect_equal(license_spdx(c("MIT + file LICENSE", NA)), c("MIT", NA))
})

test_that("license_comment() uses R Observatory's wording", {
  expect_equal(license_comment("MIT + file LICENSE"), "Declared in DESCRIPTION as MIT + file LICENSE.")
  expect_equal(license_comment("file LICENSE"),
    "Declared in DESCRIPTION as file LICENSE, which has no SPDX expression in R's license database.")
  expect_equal(license_comment("Apache License (== 2.0) | file LICENSE"),
    "Declared in DESCRIPTION as Apache License (== 2.0) | file LICENSE, which has no SPDX expression in R's license database.")
  expect_equal(license_comment("Some Custom License v9"),
    "Declared in DESCRIPTION as Some Custom License v9, which sbom's license table does not cover.")
  expect_true(is.na(license_comment(NA)))
})

test_that("license_lookup() reports whether a spec is in the table", {
  r <- license_lookup(c("MIT + file LICENSE", "Unlimited", "Some Custom License v9", NA))
  expect_equal(r$known, c(TRUE, TRUE, FALSE, FALSE))
  expect_equal(r$spdx, c("MIT", NA, NA, NA))
})

test_that("the shipped table agrees with R's own analysis", {
  skip_on_cran()
  # R's license database changes between R versions, so compare only with the
  # R version that built the table (data-raw/licenses.R records it).
  built <- read.dcf(system.file("extdata", "licenses.dcf", package = "sbom"), fields = "Built-with")[1, 1]
  same_minor <- identical(
    as.character(getRversion()[, 1:2]), as.character(numeric_version(built)[, 1:2])
  )
  skip_if_not(same_minor, paste0("the license table was built with R ", built))
  analyze <- utils::getFromNamespace("analyze_license", "tools")
  tbl <- license_table()
  plain <- tbl[!grepl("file LICEN[CS]E", tbl$spec), ]
  for (i in seq_len(nrow(plain))) {
    r <- analyze(plain$spec[i])$spdx
    # The table replaces SPDX ids that the License List has deprecated (data-raw/licenses.R).
    if (is.character(r) && identical(r, "BSD-2-Clause-FreeBSD")) r <- "BSD-2-Clause-Views"
    has_r <- is.character(r) && length(r) == 1L && !is.na(r) && nzchar(r)
    if (!is.na(plain$spdx[i])) {
      expect_identical(plain$spdx[i], r, label = plain$spec[i])
    }
    if (!has_r) {
      expect_true(is.na(plain$spdx[i]), label = plain$spec[i])
    }
  }
})

test_that("R's FreeBSD license maps to the current SPDX id, not the deprecated one", {
  expect_equal(license_spdx("FreeBSD"), "BSD-2-Clause-Views")
})
