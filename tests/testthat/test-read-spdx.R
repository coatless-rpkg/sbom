# Whether YAML text nests deeper than sbom reads (yaml_problem()).
yaml_too_deep <- function(txt) identical(yaml_problem(txt, json_max_depth), "deep")

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

test_that("tag-value files, snippets, licenses and annotations are read", {
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
  res <- schema_validate(tf, "spdx-yaml")
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

test_that("SPDX XML elements in another namespace are not read", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    '<Document xmlns:x="urn:foo"><spdxVersion>SPDX-2.3</spdxVersion>',
    "<packages><SPDXID>SPDXRef-a</SPDXID><name>Re<x:i>Spoof</x:i>al</name>",
    "<x:name>Spoof</x:name><versionInfo>1.0</versionInfo>",
    "<x:wrapper><checksums><algorithm>SHA1</algorithm></checksums></x:wrapper></packages>",
    "<x:packages><SPDXID>SPDXRef-spoof</SPDXID><name>Spoof</name></x:packages>",
    "</Document>\n"
  ), tf)
  doc <- spdx_xml_read(tf)
  expect_length(doc$packages, 1L)
  expect_identical(doc$packages[[1]], list(SPDXID = "SPDXRef-a", name = "Real", versionInfo = "1.0"))
  expect_false(any(grepl("Spoof", unlist(doc), fixed = TRUE)))
  expect_identical(read_document(tf)$doc, doc)
})

test_that("SPDX XML in a namespace reads that namespace only", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    '<s:Document xmlns:s="urn:example:spdx" xmlns:x="urn:foo">',
    "<s:spdxVersion>SPDX-2.3</s:spdxVersion><s:name>doc</s:name>",
    "<name>Spoof</name><x:name>Spoof</x:name></s:Document>\n"
  ), tf)
  expect_identical(spdx_xml_read(tf), list(spdxVersion = "SPDX-2.3", name = "doc"))
})

test_that("an spdxVersion in another namespace does not set the version", {
  tf <- withr::local_tempfile(fileext = ".spdx.xml")
  write_text(paste0(
    '<Document xmlns:x="urn:foo"><x:spdxVersion>SPDX-2.2</x:spdxVersion>',
    "<spdxVersion>SPDX-2.3</spdxVersion></Document>\n"
  ), tf)
  d <- read_document(tf)
  expect_identical(c(d$format, d$version, d$doc$spdxVersion), c("spdx-xml", "2.3", "SPDX-2.3"))
  write_text('<Document xmlns:x="urn:foo"><x:spdxVersion>SPDX-2.3</x:spdxVersion></Document>\n', tf)
  expect_error(read_document(tf), "is not an SBOM in a format sbom reads", class = "sbom_read_error")
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
  # The name in the message keeps libyaml's anchor characters, quoted in at
  # most 40 characters.
  name <- strrep("n", 100)
  write_text(paste0("spdxVersion: SPDX-2.3\ns: &", name, " x\nt: *", name, "\n"), tf)
  msg <- tryCatch(spdx_yaml_read(tf), error = conditionMessage)
  expect_match(msg, paste0("(*", strrep("n", 39), "\u2026)"), fixed = TRUE)
  expect_false(grepl(strrep("n", 40), msg, fixed = TRUE))
})

# The re-review's probe: a 20 KB scalar anchored as `&a:`, referenced 5,120
# times, which libyaml expands to a 100 MB model.
anchor_glued_yaml <- function() {
  paste0(
    "spdxVersion: SPDX-2.3\ns: &a:", strrep("x", 20480), "\n",
    "t: [", paste(rep("*a", 5120), collapse = ", "), "]\n"
  )
}

test_that("the 40 KB anchor-glued alias file is refused", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(anchor_glued_yaml(), tf)
  res <- schema_validate(tf, "spdx-yaml")
  expect_identical(res$status, "fail")
  expect_match(res$findings$message, "uses YAML aliases (*a), which sbom does not expand.", fixed = TRUE)
})

# Refused before expansion, both take about 0.01 s here.
test_that("YAML alias files are refused at once, without being expanded", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  times <- numeric()
  for (text in c(yaml_alias_bomb(), anchor_glued_yaml())) {
    write_text(text, tf)
    res <- NULL
    times <- c(times, system.time(res <- schema_validate(tf, "spdx-yaml"))[["elapsed"]])
    expect_identical(res$status, "fail")
  }
  skip_unless_timing()
  expect_lt(max(times), 10)
})

# Nesting depth of YAML, before it is parsed -------------------------------------

test_that("YAML that nests more than 200 levels is refused before it is parsed", {
  skip_if_not_installed("yaml")
  dir <- withr::local_tempdir()
  deep <- c(
    flow = paste0("spdxVersion: SPDX-2.3\nx: ", strrep("[", 1000), strrep("]", 1000), "\n"),
    map = paste0("spdxVersion: SPDX-2.3\nx: ", strrep("{a: ", 1000), "1", strrep("}", 1000), "\n"),
    unclosed = paste0("spdxVersion: SPDX-2.3\nx: ", strrep("[", 1000), "\n"),
    indented = paste0("spdxVersion: SPDX-2.3\n", paste0(strrep(" ", 0:450), "k:", collapse = "\n"), " 1\n"),
    dashes = paste0("spdxVersion: SPDX-2.3\nx:\n", strrep("- ", 300), "1\n")
  )
  for (kind in names(deep)) {
    path <- file.path(dir, paste0(kind, ".spdx.yaml"))
    write_text(deep[[kind]], path)
    cnd <- expect_error(read_sbom(path), class = "sbom_read_error")
    expect_identical(
      cnd$sentence, paste0(kind, ".spdx.yaml is not valid SPDX YAML: it nests more than 200 levels deep."),
      label = kind
    )
    res <- schema_validate(path, "spdx-yaml")
    expect_identical(
      res$findings$message, "The file is not valid YAML for an SBOM: it nests more than 200 levels deep.",
      label = kind
    )
  }
})

test_that("brackets in strings, comments, block scalars and plain text do not count as nesting", {
  shallow <- c(
    strings = paste0('d: "', strrep("[", 500), '"\ne: \'', strrep("{", 500), "'\n"),
    comments = paste0("# ", strrep("[", 500), "\na: 1 # ", strrep("{", 500), "\n"),
    block = paste0("t: |\n  ", strrep("[", 500), "\n  more\nu: 1\n"),
    plain = paste0("a: see ", strrep("[", 500), "\n"),
    escaped = paste0('x: ["a\\"', strrep("[", 300), '", \'it\'\'s ', strrep("{", 300), "']\n"),
    flat = paste0("x: [", paste(rep("[1]", 300), collapse = ", "), "]\n"),
    json = paste0('{"a": [', paste(rep('{"b": "[[["}', 300), collapse = ", "), "]}\n"),
    # Quotes that do start a node, after an anchor or an explicit key.
    anchored = paste0('x: [&a "', strrep("[", 300), '"]\n'),
    key = paste0('x: [? "', strrep("[", 300), '"]\n'),
    started = paste0('---\nspdxVersion: SPDX-2.3\nx: "', strrep("[", 300), '"\n'),
    ended = paste0('spdxVersion: SPDX-2.3\nx: "', strrep("[", 300), '"\n...\n')
  )
  for (kind in names(shallow)) expect_false(yaml_too_deep(shallow[[kind]]), label = kind)
  expect_false(yaml_too_deep(paste0("x: ", strrep("[", 200), strrep("]", 200), "\n")))
  expect_true(yaml_too_deep(paste0("x: ", strrep("[", 201), strrep("]", 201), "\n")))
})

test_that("nesting hidden behind what libyaml reads as plain text is still counted", {
  nest <- paste0(strrep("[", 250), strrep("]", 250))
  hidden <- c(
    # Quotes inside a plain scalar in a flow collection.
    apostrophe = paste0("x: [a'b, ", nest, ", c']\n"),
    double = paste0('x: [a "b, ', nest, ', c"]\n'),
    # A quote glued to a colon in a plain scalar.
    glued = paste0('x: [a:"b, ', nest, ', c"]\n'),
    # Closing brackets inside strings and comments.
    strings = paste0("x: [", strrep('"]]]]]]]]]]", [[[[[[[[[[', 30), "1", strrep("]", 301), "\n"),
    comments = paste0("x: [", strrep("[ # ]]]]\n", 250), strrep("]", 251), "\n"),
    multiline = paste0("x: [", strrep('"\n]]]]]]]]]]\n", [[[[[[[[[[', 30), "1", strrep("]", 301), "\n"),
    # A quote at the start of a line that goes on with a plain scalar.
    continued = paste0('k: word\n  "x\nb: ', nest, '\nc: "\n'),
    continued_dash = paste0('k: word\n  - "x\nb: ', nest, '\nc: "\n'),
    continued_deeper = paste0('key: word\n    more\n  "x\nb: ', nest, '\nc: "\n'),
    # A quote inside a block scalar, which ends at a less indented line.
    block = paste0("a: |\n  'start\nb: ", nest, "\nc: 'end'\n"),
    block_in_sequence = paste0("- key: |\n  b: ", nest, "\n"),
    # The re-review's: a quote after a plain word ending in ?, or after a
    # plain word starting with & or !, is plain text.
    question = paste0('x: [a? "b, ', nest, ', c"]\n'),
    question_single = paste0("x: [a? 'b, ", nest, ", c']\n"),
    ampersand = paste0('x: [a &b "x, ', nest, ', y"]\n'),
    exclamation = paste0('x: [a !b "x, ', nest, ', y"]\n'),
    # A flow collection on the --- line starts the document's root.
    document = paste0("--- ", nest, "\n"),
    document_map = paste0("--- ", strrep("{a: ", 250), "1", strrep("}", 250), "\n"),
    document_tag = paste0("--- !!seq ", nest, "\n"),
    document_anchor = paste0("--- &a ", nest, "\n"),
    directive = paste0("%YAML 1.1\n--- ", nest, "\n"),
    # A plain value given on the line after its key goes on below.
    continued_value = paste0('key:\n  word\n  "x\nb: ', nest, '\nc: "\n')
  )
  for (kind in names(hidden)) expect_true(yaml_too_deep(hidden[[kind]]), label = kind)
})

test_that("the official SPDX YAML examples and sbom's own YAML are not too deep", {
  for (f in c(
    test_path("fixtures", "third-party", "spdx-2.3", "SPDXYAMLExample-2.3.spdx.yaml"),
    test_path("fixtures", "third-party", "spdx-2.2", "SPDXYAMLExample-2.2.spdx.yaml"),
    test_path("fixtures", "r-observatory", "dplyr-1.2.1.spdx.yaml")
  )) {
    bytes <- charToRaw(read_utf8_text(f))
    expect_false(yaml_scan(bytes, yaml_text_lines(bytes), 3L)$deep, label = f)
    expect_identical(yaml_later_markers(yaml_text_lines(bytes)), integer(), label = f)
  }
  path <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_sbom(fixture_sbom(), path, format = "spdx-yaml")
  bytes <- charToRaw(read_utf8_text(path))
  expect_false(yaml_scan(bytes, yaml_text_lines(bytes), 2L)$deep)
  # JSON is YAML; its depth is that of its objects and arrays.
  json <- charToRaw(read_utf8_text(test_path("fixtures", "third-party", "spdx-2.3", "SPDXJSONExample-v2.3.spdx.json")))
  expect_false(yaml_scan(json, yaml_text_lines(json), 6L)$deep)
  expect_true(yaml_scan(json, yaml_text_lines(json), 5L)$deep)
  expect_identical(yaml_json_depth(rawToChar(json)), 6L)
})

# The review's files: 100,000 levels of `{a: ` took 117 s, and 100,000 of `[`
# 68 s, before the depth was checked. Refused, each takes about 0.1 s here.
test_that("the review's deeply nested YAML files are refused at once", {
  skip_if_not_installed("yaml")
  path <- withr::local_tempfile(fileext = ".spdx.yaml")
  times <- numeric()
  for (text in c(
    paste0("spdxVersion: SPDX-2.3\nx: ", strrep("{a: ", 1e5), "1", strrep("}", 1e5), "\n"),
    paste0("spdxVersion: SPDX-2.3\nx: ", strrep("[", 1e5), strrep("]", 1e5), "\n")
  )) {
    write_text(text, path)
    v <- NULL
    times <- c(times, system.time(expect_error(read_sbom(path), class = "sbom_read_error"))[["elapsed"]])
    times <- c(times, system.time(v <- validate_sbom(path))[["elapsed"]])
    expect_identical(v$status, "fail")
  }
  skip_unless_timing()
  expect_lt(max(times), 10)
})

# A tag-value document of one package with `n` repeats of the tag `tag`.
tv_repeated <- function(n, tag = "PackageLicenseInfoFromFiles: MIT") {
  paste0(paste(c(
    "SPDXVersion: SPDX-2.3", "DataLicense: CC0-1.0", "SPDXID: SPDXRef-DOCUMENT", "DocumentName: x",
    "DocumentNamespace: https://example.org/x", "Creator: Organization: X", "Created: 2026-01-01T00:00:00Z",
    "PackageName: p", "SPDXID: SPDXRef-p", "PackageDownloadLocation: NOASSERTION", "FilesAnalyzed: false",
    rep(tag, n)
  ), collapse = "\n"), "\n")
}

test_that("repeated tag-value tags gather every value, in order, keeping the first of a text tag", {
  doc <- spdx_tv_parse(paste0(
    tv_repeated(3, "PackageLicenseInfoFromFiles: MIT"),
    "PackageLicenseInfoFromFiles: Apache-2.0\nPackageChecksum: SHA1: 85ed0817af83a24ad8da68c2b5094de69833983c\n",
    "PackageVersion: 1.0\nPackageVersion: 2.0\nExternalRef: OTHER vcs https://example.org/a\n",
    "ExternalRefComment: first\nExternalRefComment: second\nExternalRef: OTHER vcs https://example.org/b\n",
    "PackageChecksum: MD5: 624c1abb3664f4b35547e7c73864ad24\nCreator: Tool: late\n"
  ))
  p <- doc$packages[[1]]
  expect_identical(names(p), c(
    "name", "SPDXID", "downloadLocation", "filesAnalyzed", "licenseInfoFromFiles", "checksums",
    "versionInfo", "externalRefs"
  ))
  expect_identical(p$licenseInfoFromFiles, list("MIT", "MIT", "MIT", "Apache-2.0"))
  expect_identical(p$versionInfo, "1.0")
  expect_identical(vapply(p$checksums, `[[`, "", "algorithm"), c("SHA1", "MD5"))
  expect_identical(lapply(p$externalRefs, `[[`, "comment"), list("first", NULL))
  expect_identical(attr(doc, "skipped_tags"), c("PackageVersion", "ExternalRefComment", "Creator"))
  # Creators are gathered too, before the package section starts.
  doc <- spdx_tv_parse(sub("Creator: Organization: X", "Creator: Organization: X\nCreator: Tool: t-1", tv_repeated(1)))
  expect_identical(doc$creationInfo, list(creators = list("Organization: X", "Tool: t-1"), created = "2026-01-01T00:00:00Z"))
})

# The review measured 32 s for 100,000 repeated lines (3 MB), and the time
# grew with the square of the lines. Now it takes about 1 s here.
test_that("a tag-value file of 100,000 repeated lines reads in linear time", {
  skip_on_cran()
  path <- withr::local_tempfile(fileext = ".spdx")
  write_text(tv_repeated(1e5), path)
  package_time <- system.time(x <- read_sbom(path))[["elapsed"]]
  # The package, and the placeholder root of a document that describes none.
  expect_identical(nrow(x$components), 2L)
  write_text(sub("Creator: Organization: X", strrep("Creator: Tool: t-1\n", 5e4), tv_repeated(1), fixed = TRUE), path)
  creator_time <- system.time(x <- read_sbom(path))[["elapsed"]]
  expect_identical(x$metadata$organization, NA_character_)
  skip_unless_timing()
  expect_lt(package_time, 10)
  expect_lt(creator_time, 10)
})

test_that("SPDX YAML that holds more than one document is refused before it is parsed", {
  skip_if_not_installed("yaml")
  dir <- withr::local_tempdir()
  nest <- paste0(strrep("[", 1000), strrep("]", 1000))
  documents <- c(
    second = "spdxVersion: SPDX-2.3\n---\nspdxVersion: SPDX-2.3\n",
    after_end = "spdxVersion: SPDX-2.3\n...\nname: x\n",
    after_block = "spdxVersion: SPDX-2.3\ncomment: |\n  text\n---\nname: x\n"
  )
  for (kind in names(documents)) {
    path <- file.path(dir, paste0(kind, ".spdx.yaml"))
    write_text(documents[[kind]], path)
    cnd <- expect_error(read_sbom(path), class = "sbom_read_error")
    expect_identical(
      cnd$sentence, paste0(kind, ".spdx.yaml is not valid SPDX YAML: it holds more than one YAML document."),
      label = kind
    )
    expect_identical(
      schema_validate(path, "spdx-yaml")$findings$message,
      "The file is not valid YAML for an SBOM: it holds more than one YAML document.",
      label = kind
    )
  }
  # A --- before the content, a ... that ends it, and a --- inside a block
  # scalar are one document.
  expect_identical(yaml_problem('---\nspdxVersion: SPDX-2.3\n...\n'), NA_character_)
  expect_identical(yaml_problem("spdxVersion: SPDX-2.3\ncomment: |\n  ---\n  text\n"), NA_character_)
  # The re-review's second document, nested 40,000 levels deep, which
  # yaml.load() parsed and dropped unchecked.
  path <- file.path(dir, "nested.spdx.yaml")
  write_text(paste0("spdxVersion: SPDX-2.3\n--- ", paste0(strrep("[", 40000), strrep("]", 40000)), "\n"), path)
  expect_error(read_sbom(path), class = "sbom_read_error")
})

# The re-review's files, each 78 KB: a quote after `a?`, `a &b` or `a !b` hid
# 40,000 levels of nesting, which took 6.5 s to refuse after parsing, and a
# second document of them took 19 s and was never refused. Each is now
# refused in about 0.05 s here.
test_that("the re-review's hidden and second-document nesting is refused at once", {
  skip_if_not_installed("yaml")
  nest <- paste0(strrep("[", 40000), strrep("]", 40000))
  path <- withr::local_tempfile(fileext = ".spdx.yaml")
  times <- numeric()
  for (text in c(
    paste0('spdxVersion: SPDX-2.3\nx: [a? "b, ', nest, ', c"]\n'),
    paste0('spdxVersion: SPDX-2.3\nx: [a &b "x, ', nest, ', y"]\n'),
    paste0('spdxVersion: SPDX-2.3\nx: [a !b "x, ', nest, ', y"]\n'),
    paste0("spdxVersion: SPDX-2.3\n--- ", nest, "\n")
  )) {
    write_text(text, path)
    v <- NULL
    times <- c(times, system.time(expect_error(read_sbom(path), class = "sbom_read_error"))[["elapsed"]])
    times <- c(times, system.time(v <- validate_sbom(path))[["elapsed"]])
    expect_identical(v$status, "fail")
  }
  skip_unless_timing()
  expect_lt(max(times), 10)
})

# The re-review's 80 KB file: one plain scalar of 80,000 brackets. The scan
# looked at the line from its start for each bracket, and read_sbom() took
# 45 s; now the scan is linear, and the read takes about 0.8 s here.
test_that("the YAML pre-scan takes linear time on long lines", {
  skip_on_cran()
  skip_if_not_installed("yaml")
  path <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(paste0("spdxVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nname: d\ncomment: see ", strrep("[", 80000), "\n"), path)
  read_time <- system.time(x <- read_sbom(path))[["elapsed"]]
  expect_s3_class(x, "sbom")
  # sbom's own SPDX YAML of about 2 MB, with long license comments full of
  # brackets, quotes, # and |.
  sbom <- fixture_sbom()
  sbom$components$license_comment <- paste(rep('see [1] | "a" # {b} [c', 12000), collapse = " ")
  yaml <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_sbom(sbom, yaml, format = "spdx-yaml")
  expect_gt(file.size(yaml), 2e6)
  txt <- read_utf8_text(yaml)
  bytes <- charToRaw(txt)
  problem_time <- system.time(problem <- yaml_problem(txt))[["elapsed"]]
  expect_identical(problem, NA_character_)
  scan_time <- system.time(scan <- yaml_scan(bytes, yaml_text_lines(bytes), 2L))[["elapsed"]]
  expect_false(scan$deep)
  skip_unless_timing()
  expect_lt(read_time, 10)
  expect_lt(problem_time, 10)
  expect_lt(scan_time, 10)
})
