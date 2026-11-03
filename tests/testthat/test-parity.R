parity_sbom <- function() {
  lib <- test_path("fixtures/lib-dplyr-1.2.1")
  sbom_package(file.path(lib, "dplyr"), dependencies = c("Depends", "Imports", "LinkingTo"), lib = lib,
               author = "Parity", organization = "Parity")
}

test_that("CycloneDX output matches R Observatory's dplyr 1.2.1 sample", {
  ours <- jsonlite::fromJSON(cdx_json(parity_sbom()), simplifyVector = FALSE)
  theirs <- normalize_cdx(jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.cdx.json")))
  # The normalizers must leave something to compare.
  expect_gte(length(theirs$components), 15)
  expect_gte(length(theirs$dependencies), 10)
  expect_equal(normalize_cdx(ours), theirs)
})

test_that("SPDX output matches R Observatory's dplyr 1.2.1 sample", {
  ours <- jsonlite::fromJSON(spdx_json(parity_sbom()), simplifyVector = FALSE)
  theirs <- normalize_spdx(jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx.json")))
  expect_gte(length(theirs$packages), 20)
  expect_gte(length(theirs$relationships), 50)
  expect_equal(normalize_spdx(ours), theirs)
})

test_that("parity holds when the locale's native encoding is not UTF-8", {
  local_c_ctype()
  x <- parity_sbom()
  ours <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  theirs <- jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.cdx.json"))
  expect_equal(normalize_cdx(ours), normalize_cdx(theirs))
  ours <- jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE)
  theirs <- jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx.json"))
  expect_equal(normalize_spdx(ours), normalize_spdx(theirs))
})
