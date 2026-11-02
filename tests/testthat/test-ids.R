test_that("uuid5() matches the RFC 4122 reference value", {
  expect_equal(uuid5("https://example.com"), "4fd35a71-71ef-5a55-a9d9-aa75c889a6d0")
})

test_that("uuid5() rejects a malformed namespace and non-scalar names", {
  expect_error(uuid5("x", namespace = "not-a-uuid"), "namespace")
  expect_error(uuid5(c("a", "b")), "name")
})

test_that("sbom_uuid() depends on content, not on time", {
  a <- fixture_sbom()
  b <- fixture_sbom()
  b$metadata$timestamp <- b$metadata$timestamp + 3600
  expect_equal(sbom_uuid(a), sbom_uuid(b))
  b$components$version[b$components$name == "cranpkg"] <- "9.9.9"
  expect_false(identical(sbom_uuid(a), sbom_uuid(b)))
})

test_that("sbom_uuid() ignores row order and inputs, but not issues", {
  a <- minimal_sbom()
  b <- a
  b$components <- b$components[3:1, ]
  b$metadata$inputs <- data.frame(kind = "library", path = "/somewhere/else")
  expect_equal(sbom_uuid(a), sbom_uuid(b))
  b$issues <- add_issue(b$issues, "R", "x", "test", "A new issue.", severity = "info")
  expect_false(identical(sbom_uuid(a), sbom_uuid(b)))
})

test_that("spdx_namespace() honors the sbom.namespace option", {
  withr::local_options(sbom.namespace = "https://example.org/sboms")
  expect_match(spdx_namespace(fixture_sbom()), "^https://example.org/sboms/srcpkg-0.1.0-[0-9a-f-]{36}$")
})

test_that("spdx_namespace() omits an NA version and encodes the name", {
  x <- minimal_sbom()
  x$components$version[1] <- NA_character_
  x$components$name[1] <- "a b"
  expect_match(spdx_namespace(x), "^https://spdx.org/spdxdocs/a%20b-[0-9a-f-]{36}$")
})

test_that("format_timestamp() is UTC whatever the session time zone", {
  withr::local_timezone("America/New_York")
  t <- as.POSIXct("2026-11-04 12:00:00", tz = "UTC")
  expect_equal(format_timestamp(t), "2026-11-04T12:00:00Z")
})
