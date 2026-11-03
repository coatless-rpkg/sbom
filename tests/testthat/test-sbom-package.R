test_that("the is a package-level cache environment", {
  expect_true(is.environment(the))
  expect_identical(parent.env(the), emptyenv())
})

test_that("Imports state the cli version that has hash_raw_sha1()", {
  imports <- parse_dep_field(utils::packageDescription("sbom")$Imports, "Imports")
  expect_equal(imports$constraint[imports$name == "cli"], ">= 3.6.0")
})
