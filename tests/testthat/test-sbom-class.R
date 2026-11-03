test_that("new_sbom() requires every component column", {
  x <- minimal_sbom()
  expect_s3_class(x, "sbom")
  expect_named(sbom_components(x), component_columns())
  bad <- sbom_components(x)[, -1]
  expect_error(new_sbom(x$metadata, bad, x$relationships, x$issues), "ref")
})

test_that("new_sbom() checks relationships, issues and metadata", {
  x <- minimal_sbom()
  expect_error(
    new_sbom(x$metadata, x$components, x$relationships[, -1], x$issues), "from"
  )
  expect_error(
    new_sbom(x$metadata, x$components, x$relationships, x$issues[, -5]), "message"
  )
  expect_error(
    new_sbom(x$metadata[-1], x$components, x$relationships, x$issues), "root"
  )
})

test_that("empty frames have the object-model types", {
  e <- empty_components()
  expect_equal(nrow(e), 0L)
  expect_named(e, component_columns())
  expect_type(e$is_root, "logical")
  expect_type(e$hashes, "list")
  expect_type(e$deps, "list")
  expect_type(e$asserted, "list")
  expect_type(e$ref, "character")
  expect_named(empty_relationships(), c("from", "to", "field", "spec", "evidence"))
  expect_named(empty_issues(), c("ref", "field", "severity", "code", "message"))
  one <- minimal_sbom()$components[1, ]
  expect_equal(nrow(rbind(e, one)), 1L)
})

test_that("minimal_sbom() fills metadata", {
  x <- minimal_sbom()
  expect_named(x$metadata, c("root", "timestamp", "author", "organization",
    "tool_version", "notes", "inputs"))
  expect_equal(sum(x$components$is_root), 1L)
})

test_that("accessors return the tables", {
  x <- minimal_sbom()
  expect_equal(nrow(sbom_dependencies(x)), 1L)
  expect_equal(nrow(sbom_issues(x)), 0L)
  expect_identical(sbom_components(x), x$components)
  expect_error(sbom_components(list()), "sbom")
})

test_that("resolve_timestamp() honours SOURCE_DATE_EPOCH", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  expect_equal(format(resolve_timestamp(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"), "2023-11-14T22:13:20Z")
  withr::local_envvar(SOURCE_DATE_EPOCH = "soon")
  expect_error(resolve_timestamp(), "SOURCE_DATE_EPOCH")
})

test_that("resolve_timestamp() falls back to the argument, then the clock", {
  withr::local_envvar(SOURCE_DATE_EPOCH = NA)
  ts <- resolve_timestamp(as.POSIXct("2026-01-02 03:04:05", tz = "UTC"))
  expect_equal(format(ts, "%Y-%m-%dT%H:%M:%SZ"), "2026-01-02T03:04:05Z")
  expect_equal(attr(ts, "tzone"), "UTC")
  expect_s3_class(resolve_timestamp(), "POSIXct")
  # R before 4.3 needs an origin for numbers.
  expect_equal(format(resolve_timestamp(1700000000), "%Y-%m-%dT%H:%M:%SZ"), "2023-11-14T22:13:20Z")
  expect_equal(attr(resolve_timestamp(1700000000L), "tzone"), "UTC")
})

test_that("document_notes() appends issue sentences once each", {
  x <- minimal_sbom()
  x$metadata$notes <- "A note."
  x$issues <- add_issue(x$issues, "pkg:cran/b@2.0", "license", "license-no-spdx", "B has no SPDX licence.")
  x$issues <- add_issue(x$issues, "pkg:cran/b@2.0", "license", "license-no-spdx", "B has no SPDX licence.")
  expect_equal(document_notes(x), c("A note.", "B has no SPDX licence."))
})

test_that("print.sbom() summarises", {
  expect_snapshot(print(minimal_sbom()))
})

test_that("print.sbom() handles issues and a root without a version", {
  x <- minimal_sbom()
  x$components$version[1] <- NA
  x$issues <- add_issue(x$issues, "R", "x", "c", "Something.")
  expect_snapshot(print(x))
})
