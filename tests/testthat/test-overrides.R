build_with <- function(ov) {
  sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
}

ov_row <- function(component = "cranpkg", field = "maintainer", value = "Someone Else",
                   asserted_by = "Me", reason = "Test") {
  data.frame(component = component, field = field, value = value,
             asserted_by = asserted_by, reason = reason)
}

test_that("a CSV override fills an unknown licence and clears its issue", {
  csv <- withr::local_tempfile(fileext = ".csv")
  writeLines(c("component,field,value,asserted_by,reason",
               "localpkg,license_spdx,Apache-2.0,Legal team,Reviewed LICENSE file 2026-11-01"), csv)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = csv)
  comps <- sbom_components(x)
  row <- comps$name == "localpkg"
  expect_equal(comps$license_spdx[row], "Apache-2.0")
  expect_equal(comps$asserted[row][[1]]$asserted_by, "Legal team")
  expect_false(any(sbom_issues(x)$code == "license-no-spdx" & sbom_issues(x)$ref == "local/localpkg"))
})

test_that("an override that contradicts found data is recorded", {
  x <- build_with(ov_row())
  expect_equal(sbom_issues(x)$message[sbom_issues(x)$code == "override-conflict"],
               "The maintainer of cranpkg was Grace Hopper as found and is Someone Else as asserted by Me.")
  expect_equal(sbom_issues(x)$severity[sbom_issues(x)$code == "override-conflict"], "info")
})

test_that("bad overrides fail loudly", {
  expect_error(build_with(ov_row(component = "nope", field = "version", value = "1")), "nope")
  expect_error(build_with(ov_row(field = "colour")), "colour")
})

test_that("errors name the data row, and missing columns are reported", {
  ov <- rbind(ov_row(), ov_row(component = "nope"))
  expect_error(build_with(ov), "row 2")
  expect_error(build_with(ov_row(field = "colour")), "row 1")
  expect_error(build_with(ov_row()[, c("component", "field")]), "value")
  expect_error(build_with(ov_row(value = NA)), "row 1")
  expect_error(build_with(42), "overrides")
  expect_error(build_with(file.path(tempdir(), "missing.csv")), "does not exist")
})

test_that("a component matches by ref, and an ambiguous name is an error", {
  x <- build_with(ov_row(component = "pkg:cran/cranpkg@1.2.0", field = "supplier_name",
                         value = "Acme"))
  comps <- sbom_components(x)
  expect_equal(comps$supplier_name[comps$ref == "pkg:cran/cranpkg@1.2.0"], "Acme")

  base <- build_with(NULL)
  dup <- base$components[base$components$ref == "pkg:cran/cranpkg@1.2.0", ]
  dup$ref <- "unknown/cranpkg"
  base$components <- rbind(base$components, dup)
  expect_error(apply_overrides(base, ov_row()), "unknown/cranpkg")
  expect_equal(apply_overrides(base, ov_row(component = "unknown/cranpkg"))$components$maintainer[
    base$components$ref == "unknown/cranpkg"], "Someone Else")
})

test_that("rows append in order and a later row wins", {
  ov <- rbind(ov_row(value = "First"), ov_row(value = "Second", asserted_by = "You"))
  x <- build_with(ov)
  comps <- sbom_components(x)
  row <- comps$ref == "pkg:cran/cranpkg@1.2.0"
  expect_equal(comps$maintainer[row], "Second")
  expect_equal(comps$asserted[row][[1]]$value, c("First", "Second"))
  expect_equal(names(comps$asserted[row][[1]]), c("field", "value", "asserted_by", "reason"))
  conflicts <- sbom_issues(x)$message[sbom_issues(x)$code == "override-conflict"]
  expect_match(conflicts[2], "was First as found and is Second", fixed = TRUE)
})

test_that("asserting a licence extends the comment and clears both licence issues", {
  x <- build_with(ov_row(component = "localpkg", field = "license_spdx", value = "Apache-2.0",
                         asserted_by = "Legal", reason = "Reviewed"))
  comps <- sbom_components(x)
  comment <- comps$license_comment[comps$name == "localpkg"]
  expect_match(comment, " Asserted by Legal: Reviewed.", fixed = TRUE)
  iss <- sbom_issues(x)
  expect_false(any(iss$ref == "local/localpkg" &
                     iss$code %in% c("license-no-spdx", "license-missing")))
})

test_that("asserting a supplier clears supplier-unknown", {
  before <- sbom_issues(build_with(NULL))
  target <- before$ref[before$code == "supplier-unknown"][1]
  skip_if(is.na(target))
  x <- build_with(ov_row(component = target, field = "supplier_name", value = "Acme"))
  iss <- sbom_issues(x)
  expect_false(any(iss$ref == target & iss$code == "supplier-unknown"))
})

test_that("NULL overrides change nothing", {
  x <- build_with(NULL)
  expect_identical(apply_overrides(x, NULL), x)
})
