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
  # 1.4 and 1.5 have no field for the SBOM's organization: their manufacture
  # is the maker of the described component.
  for (v in c("1.4", "1.5")) {
    meta <- cdx_document(x, v)$metadata
    expect_false(any(c("manufacture", "manufacturer") %in% names(meta)), label = v)
    props <- vapply(meta$properties, `[[`, "", "name")
    expect_equal(props[[1]], "sbom:organization", label = v)
    expect_equal(meta$properties[[1]]$value, "Test Org", label = v)
    expect_true(all(props[-1] == "sbom:note"), label = v)
  }
  for (v in c("1.6", "1.7")) {
    meta <- cdx_document(x, v)$metadata
    expect_equal(meta$manufacturer, list(name = "Test Org"), label = v)
    expect_false("sbom:organization" %in% vapply(meta$properties, `[[`, "", "name"), label = v)
  }
})

test_that("every supported version passes its schema", {
  skip_on_cran()
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

test_that("licenses, platform type, part-of and dependencies follow the rulings", {
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
  expect_match(cdx_json(x), "\"ref\": \"local/localpkg\",\n\\s+\"dependsOn\": \\[\\]")
  expect_error(cdx_document(x, "2.0"), "version")
})

test_that("a package reached only through Suggests gets no dependencies entry", {
  note <- "Packages listed only under Suggests are included, but their own dependencies were not read."
  d <- cdx_document(fixture_sbom())
  refs <- vapply(d$dependencies, `[[`, "", "ref")
  expect_false("pkg:cran/suggestpkg@2.0.0" %in% refs)
  root <- d$dependencies[[which(refs == "local/srcpkg")]]
  expect_true("pkg:cran/suggestpkg@2.0.0" %in% unlist(root$dependsOn))
  notes <- Filter(function(p) p$name == "sbom:note", d$metadata$properties)
  expect_true(note %in% vapply(notes, `[[`, "", "value"))

  # Suggested and also required: its dependencies were read, so it is listed.
  lib <- local_fake_lib(list(
    b = c(Version = "1", Repository = "CRAN", Imports = "s"),
    s = c(Version = "1", Repository = "CRAN")
  ))
  top <- withr::local_tempdir()
  writeLines(c("Package: top", "Version: 1", "Imports: b", "Suggests: s"), file.path(top, "DESCRIPTION"))
  x <- sbom_package(top, lib = lib)
  expect_true("pkg:cran/s@1" %in% vapply(cdx_document(x)$dependencies, `[[`, "", "ref"))
  expect_false(note %in% x$metadata$notes)
})

test_that("dependencies list nested components that have their own, but not a root whose are unknown", {
  x <- minimal_sbom()
  x$components$parent_ref[x$components$ref == "pkg:cran/b@2.0"] <- "pkg:cran/a@1.0"
  x$relationships <- data.frame(
    from = c("pkg:cran/a@1.0", "pkg:cran/b@2.0"), to = c("pkg:cran/b@2.0", "R"),
    field = c("contains", "Depends"), spec = NA_character_, evidence = "declared"
  )
  refs <- function(x) vapply(cdx_document(x)$dependencies, `[[`, "", "ref")
  # The nested b has a dependency of its own, so it is listed.
  expect_identical(refs(x), c("pkg:cran/a@1.0", "pkg:cran/b@2.0"))
  x$components$deps_known[x$components$is_root] <- FALSE
  expect_identical(refs(x), "pkg:cran/b@2.0")
})

test_that("a package listed only under Suggests gets no dependencies entry, whatever its relationships", {
  x <- minimal_sbom()
  x$components$scope[x$components$ref == "pkg:cran/b@2.0"] <- "optional"
  x$relationships <- data.frame(
    from = c("pkg:cran/a@1.0", "pkg:cran/b@2.0"), to = c("pkg:cran/b@2.0", "R"),
    field = c("Suggests", "system_requirement"), spec = NA_character_, evidence = "declared"
  )
  expect_identical(vapply(cdx_document(x)$dependencies, `[[`, "", "ref"), "pkg:cran/a@1.0")
})
