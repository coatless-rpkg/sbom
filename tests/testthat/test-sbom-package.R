test_that("the is a package-level cache environment", {
  expect_true(is.environment(the))
  expect_identical(parent.env(the), emptyenv())
})

test_that("Imports state the cli version that has hash_raw_sha1()", {
  imports <- parse_dep_field(utils::packageDescription("sbom")$Imports, "Imports")
  expect_equal(imports$constraint[imports$name == "cli"], ">= 3.6.0")
})

test_that("the Description names every format written, software names quoted", {
  d <- gsub("\\s+", " ", utils::packageDescription("sbom")$Description)
  for (s in c("'CycloneDX' 1.4 to 1.7", "'SPDX' 2.2 and 2.3", "'SPDX' 3.0.1", "'SWID' tags", "CSV inventory")) {
    expect_match(d, s, fixed = TRUE)
  }
})
