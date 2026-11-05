test_that("the SPDX document follows R Observatory's layout and passes its schema", {
  skip_if_not_installed("jsonvalidate")
  x <- fixture_sbom()
  d <- spdx_document(x)
  expect_equal(d$documentNamespace, spdx_namespace(x))
  expect_equal(d$relationships[[1]],
               list(spdxElementId = "SPDXRef-DOCUMENT", relationshipType = "DESCRIBES",
                    relatedSpdxElement = "SPDXRef-local-srcpkg"))
  cran <- Find(function(p) p$SPDXID == "SPDXRef-cran-cranpkg", d$packages)
  expect_equal(cran$supplier, "Organization: CRAN")
  expect_equal(cran$originator, "Person: Grace Hopper")
  expect_equal(cran$downloadLocation, "NOASSERTION")
  expect_equal(cran$licenseDeclared, "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(cran$comment, "Maintainer Grace Hopper. Published 2026-01-02.")
  utils_pkg <- Find(function(p) p$SPDXID == "SPDXRef-R-utils", d$packages)
  expect_equal(utils_pkg$downloadLocation, "NONE")
  local <- Find(function(p) p$SPDXID == "SPDXRef-local-localpkg", d$packages)
  expect_equal(local$licenseDeclared, "NOASSERTION")
  sug <- Filter(function(r) r$relationshipType == "OPTIONAL_DEPENDENCY_OF", d$relationships)
  expect_equal(sug[[1]]$spdxElementId, "SPDXRef-cran-suggestpkg")
  # Its own dependencies were not read, so no other relationship starts there.
  from_sug <- Filter(function(r) r$spdxElementId == "SPDXRef-cran-suggestpkg", d$relationships)
  expect_equal(vapply(from_sug, `[[`, "", "relationshipType"), "OPTIONAL_DEPENDENCY_OF")
  tf <- withr::local_tempfile(fileext = ".spdx.json")
  writeLines(spdx_json(x), tf, sep = "")
  expect_equal(schema_validate(tf, "spdx-json")$status, "pass")
})

test_that("R, base packages and omitted fields follow the sample", {
  d <- spdx_document(fixture_sbom())
  r <- Find(function(p) p$SPDXID == "SPDXRef-R", d$packages)
  expect_null(r$supplier)
  expect_equal(r$primaryPackagePurpose, "APPLICATION")
  u <- Find(function(p) p$SPDXID == "SPDXRef-R-utils", d$packages)
  expect_null(u$versionInfo)
  expect_null(u$supplier)
  expect_equal(u$licenseComments, "Part of R, under R's own license.")
  contains <- Filter(function(r) r$relationshipType == "CONTAINS" && r$spdxElementId == "SPDXRef-R", d$relationships)
  expect_true(all(vapply(contains, function(r) r$comment == "Part of R", logical(1))))
  expect_true(all(vapply(contains, function(r) r$spdxElementId == "SPDXRef-R", logical(1))))
  ids <- vapply(d$packages, function(p) p$SPDXID, "")
  expect_equal(anyDuplicated(ids), 0L)
  expect_true(is.null(names(d$packages)) && is.null(names(d$creationInfo$creators)))
})

test_that("colliding SPDXIDs are made unique with the version", {
  comps <- data.frame(
    name = c("a b", "a-b", "x"), version = c("1.0", "2.0", "1"),
    ecosystem = c("cran", "cran", "local")
  )
  ids <- spdx_ids(comps)
  expect_equal(ids, c("SPDXRef-cran-a-b-1.0", "SPDXRef-cran-a-b-2.0", "SPDXRef-local-x"))
  expect_equal(anyDuplicated(ids), 0L)
})

test_that("SPDX 2.2 drops 2.3-only fields and passes the 2.2 schema", {
  skip_if_not_installed("jsonvalidate")
  x <- fixture_sbom()
  d <- spdx_document(x, "2.2")
  expect_equal(d$spdxVersion, "SPDX-2.2")
  expect_false(any(vapply(d$packages, function(p) "primaryPackagePurpose" %in% names(p), TRUE)))
  cran <- Find(function(p) p$SPDXID == "SPDXRef-cran-cranpkg", d$packages)
  expect_equal(cran$externalRefs[[1]]$referenceCategory, "PACKAGE_MANAGER")
  tf <- withr::local_tempfile(fileext = ".spdx.json")
  writeLines(spdx_json(x, "2.2"), tf, sep = "")
  expect_equal(schema_validate(tf, "spdx-json", "2.2")$status, "pass")
  expect_error(spdx_document(x, "2.1"), "2.2")
})

test_that("SPDX 2.2 leaves out the checksums of algorithms it does not list", {
  x <- minimal_sbom()
  x$components$hashes[[1]] <- data.frame(
    alg = c("SHA-256", "SHA3-256"), content = c(strrep("a", 64), strrep("b", 64)), of = NA_character_
  )
  algorithms <- function(version) {
    package <- Find(function(p) p$name == "a", spdx_document(x, version)$packages)
    vapply(package$checksums, `[[`, "", "algorithm")
  }
  expect_identical(algorithms("2.3"), c("SHA256", "SHA3-256"))
  expect_identical(algorithms("2.2"), "SHA256")
})

test_that("each LicenseRef a package uses is defined once, in hasExtractedLicensingInfos", {
  x <- minimal_sbom()
  x$components$license_spdx <- c(
    "MIT OR LicenseRef-Zeta", "(LicenseRef-Alpha.1 AND LicenseRef-Zeta) OR DocumentRef-x:LicenseRef-Other",
    NA_character_
  )
  d <- spdx_document(x)
  text <- "The text of this license is not included in this SBOM."
  expect_identical(d$hasExtractedLicensingInfos, list(
    list(licenseId = "LicenseRef-Alpha.1", extractedText = text, name = "Alpha.1"),
    list(licenseId = "LicenseRef-Zeta", extractedText = text, name = "Zeta")
  ))
  # After the packages, before the relationships, in 2.2 as in 2.3.
  expect_identical(names(d)[(length(d) - 2L):length(d)], c("packages", "hasExtractedLicensingInfos", "relationships"))
  expect_identical(spdx_document(x, "2.2")$hasExtractedLicensingInfos, d$hasExtractedLicensingInfos)
  # Without a LicenseRef, the document has no such field.
  expect_false("hasExtractedLicensingInfos" %in% names(spdx_document(fixture_sbom())))
  skip_if_not_installed("jsonvalidate")
  for (version in c("2.2", "2.3")) {
    tf <- withr::local_tempfile(fileext = ".spdx.json")
    write_text(spdx_json(x, version), tf)
    expect_equal(schema_validate(tf, "spdx-json", version)$status, "pass", label = version)
  }
})

test_that("R and base packages carry a supplier only when an override asserts it", {
  ov <- data.frame(
    component = c("R", "methods"), field = "supplier_name", value = "The R Foundation",
    asserted_by = "Test", reason = "Fixture"
  )
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
  # A supplier that is set but not asserted stays out, as R Observatory has it.
  x$components$supplier_name[x$components$ref == "R/utils"] <- "Someone"
  supplier <- function(d, id) Find(function(p) p$SPDXID == id, d$packages)$supplier
  for (version in c("2.2", "2.3")) {
    d <- spdx_document(x, version)
    expect_identical(supplier(d, "SPDXRef-R"), "Organization: The R Foundation")
    expect_identical(supplier(d, "SPDXRef-R-methods"), "Organization: The R Foundation")
    expect_null(supplier(d, "SPDXRef-R-utils"))
    # In its usual place, after the package file name and before the originator.
    expect_identical(names(Find(function(p) p$SPDXID == "SPDXRef-R", d$packages))[1:4],
      c("name", "SPDXID", "versionInfo", "supplier"))
  }
  expect_null(supplier(spdx_document(fixture_sbom()), "SPDXRef-R"))
})
