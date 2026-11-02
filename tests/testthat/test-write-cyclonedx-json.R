test_that("the CycloneDX document follows R Observatory's layout", {
  x <- fixture_sbom()
  d <- cdx_document(x)
  expect_equal(d$specVersion, "1.6")
  expect_equal(d$serialNumber, paste0("urn:uuid:", sbom_uuid(x)))
  expect_equal(d$metadata$component$`bom-ref`, "local/srcpkg")
  expect_false("local/srcpkg" %in% vapply(d$components, `[[`, "", "bom-ref"))
  r <- Find(function(c) c$`bom-ref` == "R", d$components)
  expect_equal(vapply(r$components, `[[`, "", "bom-ref"), c("R/methods", "R/utils"))
  cran <- Find(function(c) c$`bom-ref` == "pkg:cran/cranpkg@1.2.0", d$components)
  expect_equal(cran$supplier, list(name = "CRAN", url = list("https://cran.r-project.org")))
  expect_equal(cran$publisher, "Grace Hopper")
  expect_equal(cran$licenses, list(list(expression = "GPL-2.0-only OR GPL-3.0-only")))
  expect_equal(Find(function(c) c$`bom-ref` == "pkg:cran/suggestpkg@2.0.0", d$components)$scope, "optional")
})

test_that("version-specific metadata", {
  x <- fixture_sbom()
  expect_null(names(cdx_document(x, "1.4")$metadata$tools))
  expect_named(cdx_document(x, "1.5")$metadata$tools, "components")
  expect_true("manufacture" %in% names(cdx_document(x, "1.5")$metadata))
  expect_true("manufacturer" %in% names(cdx_document(x, "1.7")$metadata))
})

test_that("every supported version passes its schema", {
  skip_if_not_installed("jsonvalidate")
  x <- fixture_sbom()
  for (v in c("1.4", "1.5", "1.6", "1.7")) {
    tf <- withr::local_tempfile(fileext = ".cdx.json")
    writeLines(cdx_json(x, v), tf, sep = "")
    expect_equal(schema_validate(tf, "cyclonedx-json", v)$status, "pass", label = v)
  }
})

test_that("one-element arrays stay arrays, and notes are written", {
  j <- jsonlite::fromJSON(cdx_json(fixture_sbom()), simplifyVector = FALSE)
  notes <- Filter(function(p) p$name == "sbom:note", j$metadata$properties)
  expect_true(any(vapply(notes, function(p) grepl("^Checksums are only", p$value), TRUE)))
  r <- Find(function(c) c$`bom-ref` == "R", j$components)
  expect_null(names(r$licenses))
})

test_that("licences, platform type, part-of and dependencies follow the rulings", {
  x <- fixture_sbom()
  d <- cdx_document(x)
  find <- function(ref) Find(function(c) c$`bom-ref` == ref, d$components)
  local <- find("local/localpkg")
  expect_equal(local$licenses, list(list(license = list(name = "file LICENSE"))))
  expect_false("sbom:license-as-written" %in% vapply(local$properties, `[[`, "", "name"))
  r <- find("R")
  expect_equal(r$type, "platform")
  expect_equal(cdx_document(x, "1.4")$components[[1]]$type, "application")
  expect_false(any(c("version", "licenses", "supplier") %in% names(r$components[[1]])))
  props <- function(c) setNames(vapply(c$properties, `[[`, "", "value"), vapply(c$properties, `[[`, "", "name"))
  expect_equal(props(r)[["sbom:part-of"]], "R")
  expect_equal(props(r)[["sbom:version-is"]], "minimum")
  expect_equal(props(r$components[[1]])[["sbom:part-of"]], "R")
  deps <- vapply(d$dependencies, `[[`, "", "ref")
  expect_equal(deps, sort(deps, method = "radix"))
  expect_false(any(c("R", "R/utils") %in% deps))
  cran <- d$dependencies[[which(deps == "pkg:cran/cranpkg@1.2.0")]]
  expect_equal(cran$dependsOn, list("R/methods"))
  j <- cdx_json(x)
  expect_match(j, "\n$")
  expect_true(validUTF8(j))
})

test_that("an empty dependsOn is an empty array and bad versions abort", {
  x <- fixture_sbom()
  expect_match(cdx_json(x), "\"ref\": \"pkg:cran/suggestpkg@2.0.0\",\n\\s+\"dependsOn\": \\[\\]")
  expect_error(cdx_document(x, "2.0"), "version")
})
