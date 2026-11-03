tv_file <- function(txt, env = parent.frame()) {
  tf <- withr::local_tempfile(fileext = ".spdx", .local_envir = env)
  write_text(txt, tf)
  tf
}

test_that("tag-value carries every field of the JSON document", {
  x <- fixture_sbom()
  txt <- spdx_tv(x)
  expect_match(txt, "^SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n")
  expect_match(txt, "\n$")
  expect_match(txt, "\n\n## Creation Information\nCreator: ", fixed = TRUE)
  expect_match(txt, "\n\n## Package Information\nPackageName: ", fixed = TRUE)
  expect_match(txt, "\n\n## Relationships\nRelationship: ", fixed = TRUE)
  expect_equal(
    sort_keys(spdx_tv_read(tv_file(txt))),
    sort_keys(jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE))
  )
})

test_that("SPDX 2.2 tag-value round-trips too", {
  x <- fixture_sbom()
  expect_equal(
    sort_keys(spdx_tv_read(tv_file(spdx_tv(x, "2.2")))),
    sort_keys(jsonlite::fromJSON(spdx_json(x, "2.2"), simplifyVector = FALSE))
  )
})

test_that("both edges between srcpkg and cranpkg survive", {
  rel <- spdx_tv_read(tv_file(spdx_tv(fixture_sbom())))$relationships
  hits <- Filter(function(r) r$spdxElementId == "SPDXRef-local-srcpkg" && r$relatedSpdxElement == "SPDXRef-cran-cranpkg", rel)
  expect_setequal(vapply(hits, `[[`, "", "comment"), c("Imports: cranpkg (>= 1.0.0)", "LinkingTo: cranpkg"))
})

test_that("multi-line text survives, and a literal </text> is dropped", {
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, "First line.\nSecond: line </text> end.")
  expect_match(spdx_tv_read(tv_file(spdx_tv(x)))$comment, "First line.\nSecond: line  end.", fixed = TRUE)
})

test_that("tag-value is checked through the JSON model, and says so", {
  skip_if_not_installed("jsonvalidate")
  res <- schema_validate(tv_file(spdx_tv(fixture_sbom())), "spdx-tv")
  expect_equal(res$status, "partial")
  expect_equal(res$findings$location, "")
  expect_equal(res$findings$message, "Tag-value has no schema, so the document was checked after conversion to the JSON model.")
})

test_that("a file that is not tag-value fails, without the partial note", {
  skip_if_not_installed("jsonvalidate")
  txt <- spdx_tv(fixture_sbom())
  first <- schema_validate(tv_file("DataLicense: CC0-1.0\n"), "spdx-tv")
  expect_equal(first$status, "fail")
  expect_equal(first$findings$message, "The file is not valid SPDX tag-value: the first tag is not `SPDXVersion`.")
  bad <- schema_validate(tv_file(sub("PackageName: ", "PackageName ", txt, fixed = TRUE)), "spdx-tv")
  expect_equal(bad$status, "fail")
  expect_match(bad$findings$message, "^The file is not valid SPDX tag-value: line \\d+ is not a `Tag: value` pair\\.$")
  open <- schema_validate(tv_file("SPDXVersion: SPDX-2.3\nDocumentComment: <text>oops\n"), "spdx-tv")
  expect_equal(open$status, "fail")
  expect_match(open$findings$message, "never closed")
  broken <- schema_validate(tv_file("SPDXVersion: SPDX-2.3\n"), "spdx-tv")
  expect_equal(broken$status, "fail")
  expect_false(any(grepl("no schema", broken$findings$message)))
})

test_that("unknown tags, comments and blank lines are ignored", {
  tf <- tv_file(paste0(
    "# a comment\n\nSPDXVersion: SPDX-2.3\nFoo: bar\nBaz: <text>a\nb: c</text>\n",
    "PackageName: a\nPackageFlavour: odd\nFilesAnalyzed: false\n"
  ))
  expect_equal(spdx_tv_read(tf), list(
    spdxVersion = "SPDX-2.3",
    packages = list(list(name = "a", filesAnalyzed = FALSE))
  ))
})

test_that("tag-value text is UTF-8 and literal in a C locale", {
  local_c_ctype()
  dir <- local_latin1_pkg()
  x <- sbom_package(dir, lib = dirname(dir))
  txt <- spdx_tv(x)
  expect_true(grepl("Gábor Csárdi", txt, fixed = TRUE))
  expect_identical(Encoding(txt), "UTF-8")
  doc <- spdx_tv_read(tv_file(txt))
  expect_true(any(grepl("Gábor Csárdi", unlist(doc$packages), fixed = TRUE)))
})

test_that("tag-value matches R Observatory's dplyr 1.2.1 sample", {
  expect_equal(
    normalize_spdx(spdx_tv_read(tv_file(spdx_tv(parity_sbom())))),
    normalize_spdx(spdx_tv_read(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx")))
  )
})

test_that("a removed </text> cannot re-form into a new one", {
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, "Odd </te</text>xt> note.")
  doc <- spdx_tv_read(tv_file(spdx_tv(x)))
  expect_match(doc$comment, "Odd  note.", fixed = TRUE)
  expect_false(grepl("</text>", doc$comment, fixed = TRUE))
})

test_that("a note that looks like tags stays inside its text", {
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, "Look:\n## Package Information\nPackageName: fake\nRelationship: A DEPENDS_ON B")
  want <- spdx_document(x)
  doc <- spdx_tv_read(tv_file(spdx_tv(x)))
  expect_equal(doc$comment, want$comment)
  expect_length(doc$packages, length(want$packages))
  expect_length(doc$relationships, length(want$relationships))
})

test_that("CRLF line endings read the same", {
  txt <- spdx_tv(fixture_sbom())
  expect_equal(
    spdx_tv_read(tv_file(gsub("\n", "\r\n", txt, fixed = TRUE))),
    spdx_tv_read(tv_file(txt))
  )
})

test_that("a newline in a plain tag becomes one space", {
  expect_equal(tv_line("PackageName", "a \n  b"), "PackageName: a b")
})
