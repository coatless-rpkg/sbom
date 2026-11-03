fx <- function(f) test_path("fixtures/r-observatory", f)

test_that("R Observatory's samples pass their schemas", {
  skip_if_not_installed("jsonvalidate")
  expect_equal(schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.6")$status, "pass")
  expect_equal(schema_validate(fx("dplyr-1.2.1.spdx.json"), "spdx-json")$status, "pass")
  expect_equal(schema_validate(fx("dplyr-1.2.1.cdx.xml"), "cyclonedx-xml", "1.6")$status, "pass")
})

test_that("a broken document fails with a location", {
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$type <- "not-a-type"
  tf <- withr::local_tempfile(fileext = ".json")
  jsonlite::write_json(doc, tf, auto_unbox = TRUE)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_true(any(grepl("/components/0/type", res$findings$location)))
})

test_that("a broken XML document fails with findings", {
  doc <- xml2::read_xml(fx("dplyr-1.2.1.cdx.xml"))
  node <- xml2::xml_find_first(doc, "//*[local-name()='component']")
  xml2::xml_set_attr(node, "type", "not-a-type")
  tf <- withr::local_tempfile(fileext = ".xml")
  xml2::write_xml(doc, tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_equal(res$status, "fail")
  expect_named(res$findings, c("location", "message"))
  expect_match(res$findings$message[[1]], "not-a-type")
})

test_that("validation does not depend on the working directory", {
  skip_if_not_installed("jsonvalidate")
  path <- normalizePath(fx("dplyr-1.2.1.cdx.json"))
  xml_path <- normalizePath(fx("dplyr-1.2.1.cdx.xml"))
  withr::local_dir(tempdir())
  the$schemas <- NULL
  expect_equal(schema_validate(path, "cyclonedx-json", "1.6")$status, "pass")
  expect_equal(schema_validate(xml_path, "cyclonedx-xml", "1.6")$status, "pass")
})

test_that("schemas referenced by a sibling file are enforced", {
  skip_if_not_installed("jsonvalidate")
  # The license id enum lives in spdx.schema.json, reached through a $ref.
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$licenses <- list(list(license = list(id = "Not-An-SPDX-Id")))
  tf <- withr::local_tempfile(fileext = ".json")
  jsonlite::write_json(doc, tf, auto_unbox = TRUE)
  withr::local_dir(tempdir())
  the$schemas <- NULL
  expect_equal(schema_validate(tf, "cyclonedx-json", "1.6")$status, "fail")
})

test_that("every supported CycloneDX version has its schema files", {
  for (v in c("1.4", "1.5", "1.6", "1.7")) {
    expect_true(file.exists(schema_file("cyclonedx-json", v)))
    expect_true(file.exists(schema_file("cyclonedx-xml", v)))
  }
  expect_true(file.exists(schema_file("spdx-json", NULL)))
})

test_that("without jsonvalidate the JSON check is skipped, never passed", {
  local_mocked_bindings(has_jsonvalidate = function() FALSE)
  res <- schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.6")
  expect_equal(res$status, "skipped")
  expect_equal(res$findings$message, "jsonvalidate is not installed, so the JSON schema was not checked.")
})

test_that("compiled schemas are cached", {
  skip_if_not_installed("jsonvalidate")
  the$schemas <- NULL
  a <- compiled_json_schema("spdx-json", "2.3")
  expect_identical(compiled_json_schema("spdx-json", "2.3"), a)
  expect_named(the$schemas, "spdx-json/2.3")
})

test_that("unsupported versions and formats are errors", {
  expect_error(schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.3"), "not supported")
  expect_error(schema_validate(fx("dplyr-1.2.1.spdx.json"), "spdx-json", "2.1"), "not supported")
  expect_error(schema_validate(fx("dplyr-1.2.1.cdx.json"), "yaml"), "format")
})

test_that("bundled schema files match the manifest", {
  m <- utils::read.csv(system.file("schemas", "MANIFEST.csv", package = "sbom"), colClasses = "character")
  expect_gt(nrow(m), 0)
  for (i in seq_len(nrow(m))) {
    f <- system.file("schemas", m$file[i], package = "sbom")
    expect_equal(cli::hash_file_sha256(f), m$sha256[i], label = m$file[i])
  }
})

test_that("a file that is not valid JSON fails with a finding", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".json")
  writeLines("{not json", tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(nrow(res$findings), 1L)
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "^The file is not valid JSON: .*\\.$")
})

test_that("a file that is not well-formed XML fails with a finding", {
  tf <- withr::local_tempfile(fileext = ".xml")
  writeLines("<bom><unclosed>", tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(nrow(res$findings), 1L)
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "^The file is not well-formed XML: ")
})
