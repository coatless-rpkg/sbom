test_that("SPDX XML is the SPDX JSON document, in XML", {
  x <- fixture_sbom()
  txt <- spdx_xml(x)
  expect_match(txt, '^<\\?xml version="1.0" encoding="UTF-8"\\?>\n<Document>\n')
  expect_match(txt, "\n$")
  tf <- withr::local_tempfile(fileext = ".spdx.xml"); write_text(txt, tf)
  expect_equal(spdx_xml_read(tf), jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE))
})

test_that("XML escapes &, < and quotes", {
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, 'A & B <c> "d".')
  txt <- spdx_xml(x)
  expect_match(txt, "A &amp; B &lt;c&gt;", fixed = TRUE)
  tf <- withr::local_tempfile(fileext = ".spdx.xml"); write_text(txt, tf)
  expect_equal(spdx_xml_read(tf)$comment, spdx_document(x)$comment)
})

test_that("SPDX XML is checked through the JSON model, and says so", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".spdx.xml"); write_text(spdx_xml(fixture_sbom()), tf)
  res <- schema_validate(tf, "spdx-xml")
  expect_equal(res$status, "partial")
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "no official XML schema")
})

test_that("a broken SPDX XML fails, without the partial note", {
  skip_if_not_installed("jsonvalidate")
  bad <- withr::local_tempfile(fileext = ".spdx.xml"); write_text("<Document><a>", bad)
  res <- schema_validate(bad, "spdx-xml")
  expect_equal(res$status, "fail")
  expect_match(res$findings$message, "^The file is not well-formed XML")
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Document><spdxVersion>SPDX-2.3</spdxVersion></Document>\n", tf)
  res <- schema_validate(tf, "spdx-xml")
  expect_equal(res$status, "fail")
  expect_false(any(grepl("no official XML schema", res$findings$message)))
})

test_that("an XML file whose root is not Document fails", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(sub("^(<\\?xml[^>]*>\n)<Document>", "\\1<Foo>", spdx_xml(fixture_sbom())) |>
    sub(pattern = "</Document>\n$", replacement = "</Foo>\n"), tf)
  res <- schema_validate(tf, "spdx-xml")
  expect_equal(res$status, "fail")
  expect_equal(res$findings$location, "")
  expect_equal(res$findings$message, "The root element is <Foo>, not <Document>.")
})

test_that("spdx_xml_read() keeps single array elements as lists and repeats", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    "<Document><filesAnalyzed>false</filesAnalyzed>",
    "<packages><name>a</name><checksums><algorithm>SHA1</algorithm></checksums></packages>",
    "<odd>1</odd><odd>2</odd></Document>"
  ), tf)
  doc <- spdx_xml_read(tf)
  expect_identical(doc$filesAnalyzed, FALSE)
  expect_equal(doc$packages[[1]]$checksums, list(list(algorithm = "SHA1")))
  expect_equal(doc$odd, list("1", "2"))
})

test_that("SPDX XML keeps non-ASCII text under a C locale", {
  local_c_ctype()
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, "Maintained by G\u00e1bor Cs\u00e1rdi.")
  tf <- withr::local_tempfile(fileext = ".spdx.xml"); write_text(spdx_xml(x), tf)
  bytes <- readBin(tf, "raw", file.size(tf))
  expect_true(any(bytes == as.raw(0xc3)))
  expect_equal(spdx_xml_read(tf)$comment, spdx_document(x)$comment)
})

test_that("SPDX XML matches R Observatory's dplyr 1.2.1 sample", {
  skip_on_cran()
  tf <- withr::local_tempfile(fileext = ".spdx.xml"); write_text(spdx_xml(parity_sbom()), tf)
  expect_equal(normalize_spdx(spdx_xml_read(tf)),
               normalize_spdx(spdx_xml_read(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx.xml"))))
})
