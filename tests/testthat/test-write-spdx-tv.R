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

test_that("unknown tags are skipped and named; comments and blank lines are ignored", {
  tf <- tv_file(paste0(
    "# a comment\n\nSPDXVersion: SPDX-2.3\nFoo: bar\nBaz: <text>a\nb: c</text>\n",
    "PackageName: a\nPackageFlavour: odd\nFilesAnalyzed: false\n"
  ))
  expect_equal(spdx_tv_read(tf), structure(
    list(
      spdxVersion = "SPDX-2.3",
      packages = list(list(name = "a", filesAnalyzed = FALSE))
    ),
    skipped_tags = c("Foo", "Baz", "PackageFlavour")
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

tv_with_file <- function() {
  paste0(paste(
    "SPDXVersion: SPDX-2.3", "DataLicense: CC0-1.0", "SPDXID: SPDXRef-DOCUMENT",
    "DocumentName: d", "DocumentNamespace: https://example.org/d",
    "Creator: Tool: x", "Created: 2024-01-01T00:00:00Z", "",
    "PackageName: pkg", "SPDXID: SPDXRef-Package", "PackageDownloadLocation: NOASSERTION",
    "FilesAnalyzed: true", "PackageVerificationCode: abc",
    "PackageLicenseConcluded: NOASSERTION", "PackageLicenseDeclared: NOASSERTION",
    "PackageCopyrightText: NOASSERTION", "",
    "FileName: ./a.c", "SPDXID: SPDXRef-File1",
    "FileChecksum: SHA1: 0000000000000000000000000000000000000000",
    "LicenseConcluded: NOASSERTION", "FileCopyrightText: NOASSERTION", "",
    "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package",
    "Relationship: SPDXRef-Package CONTAINS SPDXRef-File1",
    sep = "\n"
  ), "\n")
}

test_that("a file section's tags are not read into the package before it", {
  doc <- spdx_tv_read(tv_file(tv_with_file()))
  expect_identical(doc$SPDXID, "SPDXRef-DOCUMENT")
  expect_length(doc$packages, 1L)
  expect_identical(doc$packages[[1]]$SPDXID, "SPDXRef-Package")
  expect_identical(doc$packages[[1]]$licenseConcluded, "NOASSERTION")
  expect_identical(doc$packages[[1]]$hasFiles, list("SPDXRef-File1"))
  expect_identical(doc$files, list(list(
    fileName = "./a.c", SPDXID = "SPDXRef-File1",
    checksums = list(list(algorithm = "SHA1", checksumValue = strrep("0", 40))),
    licenseConcluded = "NOASSERTION", copyrightText = "NOASSERTION"
  )))
  expect_length(doc$relationships, 2L)
  expect_null(attr(doc, "skipped_tags"))
})

test_that("the partial note names the tags that were not checked", {
  skip_if_not_installed("jsonvalidate")
  txt <- paste0(
    tv_with_file(),
    "PackageFlavour: odd\nReviewer: Person: B\nReviewDate: 2024-01-02T00:00:00Z\n"
  )
  res <- schema_validate(tv_file(txt), "spdx-tv")
  expect_equal(res$status, "partial")
  expect_equal(res$findings$message, paste(
    "Tag-value has no schema, so the document was checked after conversion to the JSON model.",
    "These tags were not checked: PackageFlavour, Reviewer, ReviewDate."
  ))
})

test_that("snippet, licence, annotation and review sections close the package too", {
  starts <- c(
    "SnippetSPDXID: SPDXRef-Snippet1", "LicenseID: LicenseRef-1",
    "Annotator: Person: A", "Reviewer: Person: B"
  )
  for (start in starts) {
    doc <- spdx_tv_read(tv_file(paste0(
      "SPDXVersion: SPDX-2.3\nPackageName: pkg\nSPDXID: SPDXRef-Package\n", start,
      "\nSPDXID: SPDXRef-Other\nPackageComment: <text>not the package's</text>\n"
    )))
    expect_identical(doc$packages, list(list(name = "pkg", SPDXID = "SPDXRef-Package")), label = start)
    expect_null(doc$SPDXID)
    # Reviews are not read at all; the other sections read their first tag.
    skipped <- c(if (startsWith(start, "Reviewer")) "Reviewer", "SPDXID", "PackageComment")
    expect_identical(attr(doc, "skipped_tags"), skipped, label = start)
  }
})

test_that("an external document reference closes the package but not the creation section", {
  doc <- spdx_tv_read(tv_file(paste0(
    "SPDXVersion: SPDX-2.3\n",
    "ExternalDocumentRef: DocumentRef-x https://example.org/x SHA1: 00\n",
    "Creator: Tool: x\nCreated: 2024-01-01T00:00:00Z\n",
    "PackageName: pkg\nExternalDocumentRef: DocumentRef-y https://example.org/y SHA1: 00\n",
    "PackageComment: <text>not the package's</text>\n"
  )))
  expect_identical(doc$creationInfo, list(creators = list("Tool: x"), created = "2024-01-01T00:00:00Z"))
  expect_identical(doc$packages, list(list(name = "pkg")))
  expect_identical(
    vapply(doc$externalDocumentRefs, `[[`, "", "externalDocumentId"),
    c("DocumentRef-x", "DocumentRef-y")
  )
  expect_identical(attr(doc, "skipped_tags"), "PackageComment")
})

test_that("a file that starts with a UTF-8 byte-order mark reads", {
  bom <- rawToChar(as.raw(c(0xef, 0xbb, 0xbf)))
  Encoding(bom) <- "UTF-8"
  txt <- spdx_tv(fixture_sbom())
  expect_equal(spdx_tv_read(tv_file(paste0(bom, txt))), spdx_tv_read(tv_file(txt)))
})

test_that("SPDX 2.2 tag-value spells the category PACKAGE-MANAGER, and reads it back", {
  x <- fixture_sbom()
  tv22 <- spdx_tv(x, "2.2")
  expect_match(tv22, "\nExternalRef: PACKAGE-MANAGER purl pkg:cran/cranpkg@1.2.0\n", fixed = TRUE)
  expect_false(grepl("PACKAGE_MANAGER", tv22, fixed = TRUE))
  for (txt in list(spdx_json(x, "2.2"), spdx_yaml(x, "2.2"), spdx_xml(x, "2.2"))) {
    expect_match(txt, "PACKAGE_MANAGER", fixed = TRUE)
  }
  tf <- tv_file(tv22)
  cats <- unlist(lapply(spdx_tv_read(tf)$packages, function(p) {
    vapply(p$externalRefs, function(r) r$referenceCategory, "")
  }))
  expect_true("PACKAGE_MANAGER" %in% cats)
  expect_false("PACKAGE-MANAGER" %in% cats)
  skip_if_not_installed("jsonvalidate")
  expect_equal(schema_validate(tf, "spdx-tv", "2.2")$status, "partial")
})
