test_that("the is a package-level cache environment", {
  expect_true(is.environment(the))
  expect_identical(parent.env(the), emptyenv())
})

test_that("Imports require a cli version that has hash_raw_sha1()", {
  imports <- parse_dep_field(utils::packageDescription("sbom")$Imports, "Imports")
  floor <- sub("^>=\\s*", "", imports$constraint[imports$name == "cli"])
  expect_true(package_version(floor) >= "3.6.0")
})

test_that("the Description names every format written, software names quoted", {
  d <- gsub("\\s+", " ", utils::packageDescription("sbom")$Description)
  for (s in c(
    "'CycloneDX' 1.4 to 1.7", "Software Package Data Exchange ('SPDX') 2.2, 2.3 and 3.0.1",
    "Software Identification ('SWID') tags", "comma-separated values (CSV) inventory"
  )) {
    expect_match(d, s, fixed = TRUE)
  }
})
