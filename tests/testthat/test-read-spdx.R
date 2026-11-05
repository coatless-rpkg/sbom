tp <- function(...) test_path("fixtures", "third-party", ...)

spdx_example <- function(version, format) {
  file <- switch(format,
    json = sprintf("SPDXJSONExample-v%s.spdx.json", version),
    yaml = sprintf("SPDXYAMLExample-%s.spdx.yaml", version),
    xml = sprintf("SPDXXMLExample-v%s.spdx.xml", version),
    tv = sprintf("SPDXTagExample-v%s.spdx", version)
  )
  path <- tp(paste0("spdx-", version), file)
  switch(format,
    json = jsonlite::read_json(path),
    yaml = spdx_yaml_read(path),
    xml = spdx_xml_read(path),
    tv = spdx_tv_read(path)
  )
}

# The parts of an SPDX 2 document that all four serializations should agree
# on, each sorted.
spdx_model_summary <- function(doc) {
  srt <- function(x) sort(as.character(unlist(x)), method = "radix")
  field <- function(items, name) {
    vapply(items, function(x) if (is.null(x[[name]])) "" else x[[name]], "")
  }
  rels <- doc$relationships
  list(
    packages = srt(field(doc$packages, "SPDXID")),
    files = srt(field(doc$files, "SPDXID")),
    snippets = srt(field(doc$snippets, "SPDXID")),
    names = srt(paste(field(doc$packages, "name"), field(doc$packages, "versionInfo"))),
    relationships = srt(paste(
      field(rels, "spdxElementId"), field(rels, "relationshipType"),
      field(rels, "relatedSpdxElement")
    )),
    licenses = srt(field(doc$hasExtractedLicensingInfos, "licenseId")),
    creators = srt(doc$creationInfo$creators),
    created = doc$creationInfo$created
  )
}

test_that("the four SPDX 2.3 examples read to the same model", {
  skip_if_not_installed("yaml")
  want <- spdx_model_summary(spdx_example("2.3", "json"))
  expect_length(want$files, 5L)
  expect_length(want$snippets, 1L)
  expect_length(want$licenses, 5L)
  expect_identical(spdx_model_summary(spdx_example("2.3", "yaml")), want)
  expect_identical(spdx_model_summary(spdx_example("2.3", "xml")), want)
  # The tag-value example differs from the other three in the 2.3 release:
  # - it states the document's DESCRIBES relationships, which the others give
  #   as documentDescribes instead;
  # - it has "SPDXRef-Package CONTAINS SPDXRef-JenaLib", which the others give
  #   only as the package's hasFiles.
  want_tv <- want
  want_tv$relationships <- sort(c(
    want$relationships,
    "SPDXRef-DOCUMENT DESCRIBES SPDXRef-File",
    "SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package",
    "SPDXRef-Package CONTAINS SPDXRef-JenaLib"
  ), method = "radix")
  expect_identical(spdx_model_summary(spdx_example("2.3", "tv")), want_tv)
})

test_that("the four SPDX 2.2 examples read to the same model", {
  skip_if_not_installed("yaml")
  want <- spdx_model_summary(spdx_example("2.2", "json"))
  expect_length(want$files, 4L)
  expect_length(want$snippets, 1L)
  expect_length(want$licenses, 5L)
  for (format in c("yaml", "xml", "tv")) {
    expect_identical(spdx_model_summary(spdx_example("2.2", format)), want, label = format)
  }
})

test_that("SPDX XML integers, booleans and one-element arrays get their JSON types", {
  doc <- spdx_example("2.3", "xml")
  range <- doc$snippets[[1]]$ranges[[1]]
  expect_identical(range$startPointer$offset, 310L)
  expect_identical(range$endPointer$offset, 420L)
  file <- Filter(function(f) f$SPDXID == "SPDXRef-DoapSource", doc$files)[[1]]
  expect_identical(file$licenseInfoInFiles, list("Apache-2.0"))
  expect_identical(doc$packages[[2]]$filesAnalyzed, FALSE)

  # The example has no crossRefs.
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    "<Document><hasExtractedLicensingInfos><licenseId>LicenseRef-x</licenseId>",
    "<crossRefs><isLive>true</isLive><isValid>false</isValid>",
    "<isWayBackLink>false</isWayBackLink><order>0</order>",
    "<url>https://example.org/x</url></crossRefs>",
    "</hasExtractedLicensingInfos></Document>"
  ), tf)
  refs <- spdx_xml_read(tf)$hasExtractedLicensingInfos[[1]]$crossRefs
  expect_identical(refs, list(list(
    isLive = TRUE, isValid = FALSE, isWayBackLink = FALSE, order = 0L,
    url = "https://example.org/x"
  )))
})

test_that("SPDX XML keeps a value that is not of its key's type as text", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    "<Document><filesAnalyzed>maybe</filesAnalyzed>",
    "<snippets><ranges><startPointer><offset>3.5</offset></startPointer></ranges></snippets>",
    "</Document>"
  ), tf)
  doc <- spdx_xml_read(tf)
  expect_identical(doc$filesAnalyzed, "maybe")
  expect_identical(doc$snippets[[1]]$ranges[[1]]$startPointer$offset, "3.5")
})

test_that("SPDX YAML integers and booleans are typed by their key", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(paste0(
    "spdxVersion: SPDX-2.3\n",
    "packages:\n",
    "  - name: no\n    versionInfo: 1.10\n    filesAnalyzed: false\n",
    "snippets:\n",
    "  - name: s\n    ranges:\n",
    "      - startPointer:\n          offset: 310\n          reference: SPDXRef-f\n",
    "        endPointer:\n          lineNumber: 0x10\n          reference: 420\n",
    "hasExtractedLicensingInfos:\n",
    "  - licenseId: LicenseRef-x\n    crossRefs:\n",
    "      - isLive: yes\n        order: 2\n        url: true\n"
  ), tf)
  doc <- spdx_yaml_read(tf)
  p <- doc$packages[[1]]
  expect_identical(p$name, "no")
  expect_identical(p$versionInfo, "1.10")
  expect_identical(p$filesAnalyzed, FALSE)
  range <- doc$snippets[[1]]$ranges[[1]]
  expect_identical(range$startPointer$offset, 310L)
  # Only a decimal literal is an integer; a string key keeps a number's text.
  expect_identical(range$endPointer$lineNumber, "0x10")
  expect_identical(range$endPointer$reference, "420")
  ref <- doc$hasExtractedLicensingInfos[[1]]$crossRefs[[1]]
  expect_identical(ref, list(isLive = TRUE, order = 2L, url = "true"))
})

test_that("tag-value files, snippets, licences and annotations are read", {
  doc <- spdx_example("2.3", "tv")
  pkgs <- stats::setNames(doc$packages, vapply(doc$packages, `[[`, "", "SPDXID"))
  # ./package/foo.c comes before every package, so no package has it.
  expect_identical(
    pkgs[["SPDXRef-Package"]]$hasFiles,
    list("SPDXRef-Specification", "SPDXRef-CommonsLangSrc", "SPDXRef-JenaLib", "SPDXRef-DoapSource")
  )
  expect_null(pkgs[["SPDXRef-Saxon"]]$hasFiles)
  expect_identical(pkgs[["SPDXRef-Package"]]$packageVerificationCode, list(
    packageVerificationCodeValue = "d6a770ba38583ed4bb4525bd96e50461655d2758",
    packageVerificationCodeExcludedFiles = list("./package.spdx")
  ))
  expect_identical(
    pkgs[["SPDXRef-Package"]]$licenseInfoFromFiles,
    list("GPL-2.0-only", "LicenseRef-2", "LicenseRef-1")
  )
  expect_identical(pkgs[["SPDXRef-Package"]]$summary, "GNU C library.")
  expect_identical(pkgs[["SPDXRef-Package"]]$validUntilDate, "2014-01-29T18:30:22Z")
  expect_length(pkgs[["SPDXRef-Package"]]$attributionTexts, 1L)

  snippet <- doc$snippets[[1]]
  expect_identical(snippet$snippetFromFile, "SPDXRef-DoapSource")
  expect_identical(snippet$ranges, list(
    list(
      startPointer = list(offset = 310L, reference = "SPDXRef-DoapSource"),
      endPointer = list(offset = 420L, reference = "SPDXRef-DoapSource")
    ),
    list(
      startPointer = list(lineNumber = 5L, reference = "SPDXRef-DoapSource"),
      endPointer = list(lineNumber = 23L, reference = "SPDXRef-DoapSource")
    )
  ))
  expect_identical(snippet$licenseInfoInSnippets, list("GPL-2.0-only"))

  lic <- doc$hasExtractedLicensingInfos
  expect_identical(
    vapply(lic, `[[`, "", "licenseId"),
    c("LicenseRef-1", "LicenseRef-2", "LicenseRef-4", "LicenseRef-Beerware-4.2", "LicenseRef-3")
  )
  expect_identical(lic[[4]]$seeAlsos, list("http://people.freebsd.org/~phk/"))
  expect_identical(
    lic[[5]]$seeAlsos,
    list("http://people.apache.org/~andyc/neko/LICENSE", "http://justasample.url.com")
  )

  # Annotations go to the element their SPDXREF names.
  expect_length(doc$annotations, 3L)
  expect_identical(pkgs[["SPDXRef-Package"]]$annotations[[1]]$comment, "Package level annotation")
  foo <- Filter(function(f) f$SPDXID == "SPDXRef-File", doc$files)[[1]]
  expect_identical(foo$annotations, list(list(
    annotator = "Person: File Commenter", annotationDate = "2011-01-29T18:30:22Z",
    comment = "File level annotation", annotationType = "OTHER"
  )))
  expect_identical(foo$fileTypes, list("SOURCE"))
  expect_identical(foo$licenseInfoInFiles, list("GPL-2.0-only", "LicenseRef-2"))
  expect_length(foo$fileContributors, 3L)

  expect_identical(doc$creationInfo$licenseListVersion, "3.17")
  expect_identical(doc$externalDocumentRefs, list(list(
    externalDocumentId = "DocumentRef-spdx-tool-1.2",
    spdxDocument = "http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301",
    checksum = list(algorithm = "SHA1", checksumValue = "d6a770ba38583ed4bb4525bd96e50461655d2759")
  )))
  expect_null(attr(doc, "skipped_tags"))
})

test_that("an annotation of an unknown element is not attached, and its SPDXREF is skipped", {
  tf <- withr::local_tempfile(fileext = ".spdx")
  annotation <- function(target) {
    paste0(
      "Annotator: Person: X\nAnnotationDate: 2024-01-01T00:00:00Z\n",
      "AnnotationType: OTHER\nSPDXREF: ", target, "\nAnnotationComment: c\n"
    )
  }
  write_text(paste0(
    "SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nPackageName: a\nSPDXID: SPDXRef-a\n",
    annotation("DocumentRef-y:SPDXRef-z"), annotation("SPDXRef-DOCUMENT")
  ), tf)
  doc <- spdx_tv_read(tf)
  expect_null(doc$packages[[1]]$annotations)
  expect_identical(doc$annotations, list(list(
    annotator = "Person: X", annotationDate = "2024-01-01T00:00:00Z",
    annotationType = "OTHER", comment = "c"
  )))
  expect_identical(attr(doc, "skipped_tags"), "SPDXREF")
})

test_that("a repeated single-valued tag keeps its first value and is skipped", {
  tf <- withr::local_tempfile(fileext = ".spdx")
  write_text(paste0(
    "SPDXVersion: SPDX-2.3\nCreated: 2024-01-01T00:00:00Z\nCreated: 2025-01-01T00:00:00Z\n",
    "PackageName: a\nPackageVersion: 1\nPackageVersion: 2\n",
    "FilesAnalyzed: false\nFilesAnalyzed: true\n",
    "ExternalRef: OTHER x y\nExternalRefComment: first\nExternalRefComment: second\n"
  ), tf)
  doc <- spdx_tv_read(tf)
  expect_identical(doc$creationInfo$created, "2024-01-01T00:00:00Z")
  expect_identical(doc$packages[[1]]$versionInfo, "1")
  expect_identical(doc$packages[[1]]$filesAnalyzed, FALSE)
  expect_identical(doc$packages[[1]]$externalRefs[[1]]$comment, "first")
  expect_identical(
    attr(doc, "skipped_tags"),
    c("Created", "PackageVersion", "FilesAnalyzed", "ExternalRefComment")
  )
})

test_that("tag-value FilesAnalyzed is typed as in XML and YAML", {
  tf <- withr::local_tempfile(fileext = ".spdx")
  write_text("SPDXVersion: SPDX-2.3\nPackageName: a\nFilesAnalyzed: maybe\nPackageName: b\nFilesAnalyzed: true\n", tf)
  doc <- spdx_tv_read(tf)
  expect_identical(doc$packages[[1]]$filesAnalyzed, "maybe")
  expect_identical(doc$packages[[2]]$filesAnalyzed, TRUE)
})

test_that("an integer beyond 32 bits under an integer key is a double", {
  big <- 3000000000
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text("<Document><snippets><ranges><startPointer><offset>3000000000</offset></startPointer></ranges></snippets></Document>", tf)
  expect_identical(spdx_xml_read(tf)$snippets[[1]]$ranges[[1]]$startPointer$offset, big)
  tv <- withr::local_tempfile(fileext = ".spdx")
  write_text("SPDXVersion: SPDX-2.3\nSnippetSPDXID: SPDXRef-s\nSnippetByteRange: 3000000000:3000000010\n", tv)
  range <- spdx_tv_read(tv)$snippets[[1]]$ranges[[1]]
  expect_identical(range$startPointer$offset, big)
  expect_identical(range$endPointer$offset, big + 10)
  skip_if_not_installed("yaml")
  y <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text("snippets:\n  - ranges:\n      - startPointer:\n          offset: 3000000000\n", y)
  expect_identical(spdx_yaml_read(y)$snippets[[1]]$ranges[[1]]$startPointer$offset, big)
})

# The YAML of a billion-laughs attack: each line repeats the one before ten
# times, through aliases.
yaml_alias_bomb <- function() {
  lines <- "a: &a [x, x, x, x, x, x, x, x, x, x]"
  for (i in 2:6) {
    lines <- c(lines, sprintf(
      "%s: &%s [%s]", letters[i], letters[i],
      paste(rep(paste0("*", letters[i - 1]), 10), collapse = ", ")
    ))
  }
  paste0("spdxVersion: SPDX-2.3\nextra:\n", paste0("  ", lines, collapse = "\n"), "\n")
}

test_that("YAML aliases are refused before they are expanded", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(yaml_alias_bomb(), tf)
  expect_error(
    spdx_yaml_read(tf),
    paste0(basename(tf), " uses YAML aliases (*a), which sbom does not expand."),
    fixed = TRUE
  )
  elapsed <- system.time(res <- schema_validate(tf, "spdx-yaml"))[["elapsed"]]
  expect_lt(elapsed, 1)
  expect_identical(res$status, "fail")
  expect_match(res$findings$message, "uses YAML aliases (*a), which sbom does not expand.", fixed = TRUE)

  ok <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text('spdxVersion: SPDX-2.3\npackages:\n  - name: "R&D *note"\n', ok)
  expect_identical(spdx_yaml_read(ok)$packages[[1]]$name, "R&D *note")
})

test_that("a NUL byte in YAML or tag-value is an error that quotes nothing", {
  # write_text() cannot hold a NUL, so these bytes are written directly.
  tv <- withr::local_tempfile(fileext = ".spdx")
  writeBin(c(charToRaw("SPDXVersion: SPDX-2.3\nPackageName: secret"), as.raw(0), charToRaw("x\n")), tv)
  expect_error(spdx_tv_read(tv), "^the file contains a NUL byte$")
  skip_if_not_installed("yaml")
  y <- withr::local_tempfile(fileext = ".spdx.yaml")
  writeBin(c(charToRaw("spdxVersion: secret"), as.raw(0), charToRaw("\n")), y)
  expect_error(spdx_yaml_read(y), "^the file contains a NUL byte$")
})

test_that("text that is not UTF-8 is an error that quotes nothing", {
  # write_text() writes UTF-8, so these Latin-1 bytes are written directly.
  tv <- withr::local_tempfile(fileext = ".spdx")
  writeBin(c(charToRaw("SPDXVersion: SPDX-2.3\nPackageName: caf"), as.raw(0xe9), charToRaw("\n")), tv)
  expect_error(spdx_tv_read(tv), "^the file is not valid UTF-8$")
})

test_that("a malformed snippet range is an error", {
  tf <- withr::local_tempfile(fileext = ".spdx")
  write_text("SPDXVersion: SPDX-2.3\nSnippetSPDXID: SPDXRef-s\nSnippetByteRange: 10-20\n", tf)
  expect_error(spdx_tv_read(tf), "is not two numbers separated by a colon")
})

test_that("spdx_xml_read() rejects a root other than <Document>", {
  expect_error(
    spdx_xml_read(tp("cyclonedx", "valid-bom-1.6.xml")),
    "the root element is <bom>, not <Document>",
    fixed = TRUE
  )
})

test_that("an external entity in SPDX XML is never expanded", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<!DOCTYPE Document [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n',
    "<Document><spdxVersion>SPDX-2.3</spdxVersion><name>&x;</name></Document>\n"
  ), tf)
  expect_no_error(doc <- spdx_xml_read(tf))
  expect_identical(doc$spdxVersion, "SPDX-2.3")
  expect_false(any(grepl("root:", unlist(doc), fixed = TRUE)))
})

# Property names of each JSON type in an SPDX 2 schema.
spdx_schema_keys <- function(x, type) {
  if (!is.list(x)) {
    return(character())
  }
  props <- x$properties
  hit <- if (is.list(props)) {
    names(props)[vapply(props, function(p) identical(p$type, type), logical(1))]
  }
  c(hit, unlist(lapply(x, spdx_schema_keys, type = type), use.names = FALSE))
}

test_that("the key-type vectors are those of the bundled SPDX 2 schemas", {
  schemas <- lapply(c("2.2", "2.3"), function(v) jsonlite::read_json(schema_file("spdx-json", v)))
  keys <- function(type) {
    sort(unique(unlist(lapply(schemas, spdx_schema_keys, type = type))), method = "radix")
  }
  expect_identical(spdx_json_arrays, keys("array"))
  expect_identical(spdx_json_integers, keys("integer"))
  expect_identical(spdx_json_booleans, keys("boolean"))
})

test_that("an anchor glued to ':' or '?' is still caught", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  for (anchor in c("&a:hello", "&a?world")) {
    write_text(paste0("spdxVersion: SPDX-2.3\ns: ", anchor, "\nt: [*a, *a]\n"), tf)
    expect_error(spdx_yaml_read(tf), "uses YAML aliases (*a), which sbom does not expand.", fixed = TRUE, label = anchor)
  }
  # The name in the message keeps libyaml's anchor characters, at most 40.
  name <- strrep("n", 100)
  write_text(paste0("spdxVersion: SPDX-2.3\ns: &", name, " x\nt: *", name, "\n"), tf)
  msg <- tryCatch(spdx_yaml_read(tf), error = conditionMessage)
  expect_match(msg, paste0("(*", strrep("n", 40), ")"), fixed = TRUE)
  expect_false(grepl(strrep("n", 41), msg, fixed = TRUE))
})

# The re-review's probe: a 20 KB scalar anchored as `&a:`, referenced 5,120
# times, which libyaml expands to a 100 MB model.
test_that("the 40 KB anchor-glued alias file is refused at once", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(paste0(
    "spdxVersion: SPDX-2.3\ns: &a:", strrep("x", 20480), "\n",
    "t: [", paste(rep("*a", 5120), collapse = ", "), "]\n"
  ), tf)
  elapsed <- system.time(res <- schema_validate(tf, "spdx-yaml"))[["elapsed"]]
  expect_lt(elapsed, 1)
  expect_identical(res$status, "fail")
  expect_match(res$findings$message, "uses YAML aliases (*a), which sbom does not expand.", fixed = TRUE)
})
