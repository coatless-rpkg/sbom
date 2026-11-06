test_that("every supported version passes its XSD", {
  x <- fixture_sbom()
  for (v in c("1.4", "1.5", "1.6", "1.7")) {
    tf <- withr::local_tempfile(fileext = ".cdx.xml")
    writeLines(cdx_xml(x, v), tf, sep = "")
    expect_equal(schema_validate(tf, "cyclonedx-xml", v)$status, "pass", label = v)
  }
})

test_that("XML carries the same components as JSON", {
  x <- fixture_sbom()
  doc <- xml2::read_xml(cdx_xml(x))
  xml2::xml_ns_strip(doc)
  expect_equal(xml2::xml_attr(xml2::xml_find_first(doc, "/bom/metadata/component"), "bom-ref"), "local/srcpkg")
  n_json <- length(cdx_document(x)$components)
  expect_equal(length(xml2::xml_find_all(doc, "/bom/components/component")), n_json)
})

test_that("the organization is a property in 1.4 and 1.5, manufacturer later", {
  x <- fixture_sbom()
  meta <- function(v) {
    doc <- xml2::read_xml(cdx_xml(x, v))
    xml2::xml_ns_strip(doc)
    xml2::xml_find_first(doc, "/bom/metadata")
  }
  for (v in c("1.4", "1.5")) {
    m <- meta(v)
    expect_length(xml2::xml_find_all(m, "manufacture|manufacturer"), 0L)
    org <- xml2::xml_find_all(m, "properties/property[@name='sbom:organization']")
    expect_equal(xml2::xml_text(org), "Test Org", label = v)
  }
  m <- meta("1.6")
  expect_equal(xml2::xml_text(xml2::xml_find_all(m, "manufacturer/name")), "Test Org")
  expect_length(xml2::xml_find_all(m, "properties/property[@name='sbom:organization']"), 0L)
})

test_that("layout: declaration on line 1, bom on line 2, trailing newline", {
  out <- cdx_xml(fixture_sbom())
  lines <- strsplit(out, "\n", fixed = TRUE)[[1]]
  expect_equal(lines[1], '<?xml version="1.0" encoding="UTF-8"?>')
  expect_match(lines[2], "^<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\" serialNumber=\"urn:uuid:")
  expect_match(out, "\n$")
  expect_equal(Encoding(out) %in% c("UTF-8", "unknown"), TRUE)
})

test_that("non-ASCII text is written as UTF-8, not entities", {
  x <- fixture_sbom()
  x$components$maintainer[1] <- "Gábor Csárdi"
  out <- cdx_xml(x)
  expect_match(out, "Gábor Csárdi", fixed = TRUE)
  expect_false(grepl("&#", out, fixed = TRUE))
})

test_that("unsupported versions are rejected", {
  expect_error(cdx_xml(fixture_sbom(), "1.3"), "must be one of")
})

test_that("U+FFFE and U+FFFF, which XML does not allow, are written as the reference of U+FFFD", {
  x <- minimal_sbom()
  x$components$description[x$components$ref == "pkg:cran/b@2.0"] <- "a￾b￿c"
  out <- cdx_xml(x, "1.6")
  expect_false(grepl("￾", out, fixed = TRUE))
  expect_false(grepl("￿", out, fixed = TRUE))
  expect_match(out, "<description>a&#xFFFD;b&#xFFFD;c</description>", fixed = TRUE)
  doc <- xml2::read_xml(out)
  xml2::xml_ns_strip(doc)
  expect_identical(
    xml2::xml_text(xml2::xml_find_first(doc, "//component[@bom-ref='pkg:cran/b@2.0']/description")),
    "a�b�c"
  )
  # So in an attribute.
  expect_identical(xml_escape("x￾y￿", attr = TRUE), "x&#xFFFD;y&#xFFFD;")
})

test_that("text that is not UTF-8 stops the writer, as it did when xml2 wrote the document", {
  skip_if_not(isTRUE(l10n_info()[["UTF-8"]]), "Only a UTF-8 locale keeps bytes that are not UTF-8 as they are.")
  x <- minimal_sbom()
  x$components$description[x$components$ref == "pkg:cran/b@2.0"] <- paste0("a", rawToChar(as.raw(0xff)), "b")
  expect_error(suppressWarnings(cdx_xml(x, "1.6")), "input string 1 is invalid", fixed = TRUE)
})
