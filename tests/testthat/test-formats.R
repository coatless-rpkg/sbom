test_that("sbom_formats() lists nine outputs", {
  f <- sbom_formats()
  expect_equal(f$format, c("cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml",
                           "spdx-tv", "spdx3-jsonld", "swid", "csv"))
  expect_equal(f$extension, c(".cdx.json", ".cdx.xml", ".spdx.json", ".spdx.yaml", ".spdx.xml",
                              ".spdx", ".spdx3.jsonld", ".swidtag", ".csv"))
  expect_equal(f$versions, c(rep("1.4, 1.5, 1.6, 1.7", 2), rep("2.2, 2.3", 4), "3.0.1", "2015", ""))
  expect_equal(f$default_version, c("1.6", "1.6", "2.3", "2.3", "2.3", "2.3", "3.0.1", "2015", NA_character_))
  expect_equal(f$versions[f$format == "spdx-tv"], "2.2, 2.3")
})
