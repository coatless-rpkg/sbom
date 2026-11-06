fx <- function(f) test_path("fixtures/r-observatory", f)

test_that("R Observatory's samples pass their schemas", {
  skip_if_not_installed("jsonvalidate")
  expect_equal(schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.6")$status, "pass")
  expect_equal(schema_validate(fx("dplyr-1.2.1.spdx.json"), "spdx-json")$status, "pass")
  expect_equal(schema_validate(fx("dplyr-1.2.1.cdx.xml"), "cyclonedx-xml", "1.6")$status, "pass")
})

test_that("a broken document fails with a location", {
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$type <- "not-a-type"
  tf <- withr::local_tempfile(fileext = ".json")
  jsonlite::write_json(doc, tf, auto_unbox = TRUE)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_true(any(grepl("/components/0/type", res$findings$location)))
})

test_that("a broken XML document fails with findings", {
  doc <- xml2::read_xml(fx("dplyr-1.2.1.cdx.xml"))
  node <- xml2::xml_find_first(doc, "//*[local-name()='component']")
  xml2::xml_set_attr(node, "type", "not-a-type")
  tf <- withr::local_tempfile(fileext = ".xml")
  xml2::write_xml(doc, tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_equal(res$status, "fail")
  expect_named(res$findings, c("location", "message"))
  expect_match(res$findings$message[[1]], "not-a-type")
})

test_that("validation does not depend on the working directory", {
  skip_if_not_installed("jsonvalidate")
  path <- normalizePath(fx("dplyr-1.2.1.cdx.json"))
  xml_path <- normalizePath(fx("dplyr-1.2.1.cdx.xml"))
  withr::local_dir(tempdir())
  the$schemas <- NULL
  expect_equal(schema_validate(path, "cyclonedx-json", "1.6")$status, "pass")
  expect_equal(schema_validate(xml_path, "cyclonedx-xml", "1.6")$status, "pass")
})

test_that("schemas referenced by a sibling file are enforced", {
  skip_if_not_installed("jsonvalidate")
  # The license id enum lives in spdx.schema.json, reached through a $ref.
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$licenses <- list(list(license = list(id = "Not-An-SPDX-Id")))
  tf <- withr::local_tempfile(fileext = ".json")
  jsonlite::write_json(doc, tf, auto_unbox = TRUE)
  withr::local_dir(tempdir())
  the$schemas <- NULL
  expect_equal(schema_validate(tf, "cyclonedx-json", "1.6")$status, "fail")
})

test_that("every supported CycloneDX version has its schema files", {
  for (v in c("1.4", "1.5", "1.6", "1.7")) {
    expect_true(file.exists(schema_file("cyclonedx-json", v)))
    expect_true(file.exists(schema_file("cyclonedx-xml", v)))
  }
  expect_true(file.exists(schema_file("spdx-json", NULL)))
})

test_that("without jsonvalidate the JSON check is skipped, never passed", {
  local_mocked_bindings(has_jsonvalidate = function() FALSE)
  res <- schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.6")
  expect_equal(res$status, "skipped")
  expect_equal(res$findings$message, "jsonvalidate is not installed, so the JSON schema was not checked.")
})

test_that("compiled schemas are cached", {
  skip_if_not_installed("jsonvalidate")
  the$schemas <- NULL
  a <- compiled_json_schema("spdx-json", "2.3")
  expect_identical(compiled_json_schema("spdx-json", "2.3"), a)
  expect_named(the$schemas, "spdx-json/2.3")
})

test_that("unsupported versions and formats are errors", {
  expect_error(schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.3"), "not supported")
  expect_error(schema_validate(fx("dplyr-1.2.1.spdx.json"), "spdx-json", "2.1"), "not supported")
  expect_error(schema_validate(fx("dplyr-1.2.1.cdx.json"), "yaml"), "format")
})

test_that("bundled schema files match the manifest", {
  m <- utils::read.csv(system.file("schemas", "MANIFEST.csv", package = "sbom"), colClasses = "character")
  expect_gt(nrow(m), 0)
  for (i in seq_len(nrow(m))) {
    f <- system.file("schemas", m$file[i], package = "sbom")
    expect_equal(cli::hash_file_sha256(f), m$sha256[i], label = m$file[i])
  }
})

test_that("a file that is not valid JSON fails with a finding", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".json")
  writeLines("{not json", tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(nrow(res$findings), 1L)
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "^The file is not valid JSON: .*\\.$")
})

test_that("a file that is not well-formed XML fails with a finding", {
  tf <- withr::local_tempfile(fileext = ".xml")
  writeLines("<bom><unclosed>", tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(nrow(res$findings), 1L)
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "^The file is not well-formed XML: ")
})

test_that("malformed JSON fails before the schema is looked at", {
  tf <- withr::local_tempfile(fileext = ".json")
  write_text("{", tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(res$findings$location, "")
  expect_match(res$findings$message, "^The file is not valid JSON: .+\\.$")
})

test_that("a validator that errors gives skipped, not a parse failure", {
  local_mocked_bindings(
    has_jsonvalidate = function() TRUE,
    compiled_json_schema = function(format, version) {
      list(validate = function(...) stop("V8 fell over."))
    }
  )
  res <- schema_validate(fx("dplyr-1.2.1.cdx.json"), "cyclonedx-json", "1.6")
  expect_equal(res$status, "skipped")
  expect_equal(res$findings, data.frame(
    location = "", message = "The JSON schema check could not run: V8 fell over."
  ))
})

test_that("a CycloneDX URL that is not an IRI reference fails", {
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$externalReferences <- list(list(type = "website", url = "https://exa mple.org"))
  tf <- withr::local_tempfile(fileext = ".json")
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_equal(res$status, "fail")
  expect_equal(res$findings, data.frame(
    location = "/components/0/externalReferences/0/url",
    message = "https://exa mple.org is not a valid IRI reference."
  ))
})

test_that("each character an IRI reference cannot hold is caught", {
  ok <- c(
    "https://example.org/a%20b?q=1#f", "urn:cdx:3e671687/1#ref", "../relative",
    "https://\u4f8b\u3048.jp/\u30d1\u30b9", ""
  )
  bad <- c(
    "a b", "a\tb", "a\nb", "a\u0001b", "a\u0085b", "a\u00a0b", "a\u3000b",
    "a<b", "a>b", "a\"b", "a{b", "a}b", "a|b", "a\\b", "a^b", "a`b",
    "a%2", "a%zz", "100%"
  )
  expect_identical(iri_reference_bad(ok), rep(FALSE, length(ok)))
  expect_identical(iri_reference_bad(bad), rep(TRUE, length(bad)))
  invalid <- rawToChar(as.raw(c(0x61, 0xff)))
  Encoding(invalid) <- "UTF-8"
  expect_true(iri_reference_bad(invalid))
})

test_that("every IRI-reference key is checked, in strings and arrays of strings", {
  doc <- list(
    metadata = list(supplier = list(url = list("https://ok.example", "bad url"))),
    services = list(list(
      endpoints = list("bad endpoint"),
      data = list(list(source = list("bad source"), destination = list("bad destination")))
    )),
    vulnerabilities = list(list(
      source = list(name = "NVD", url = "bad nvd"),
      references = list(list(id = "x", source = list(url = "bad ref")))
    )),
    releaseNotes = list(featuredImage = "bad image", socialImage = "bad social"),
    components = list(list(name = "bad name", `a/b~c` = list(url = "bad escaped")))
  )
  res <- cdx_iri_findings(doc)
  expect_setequal(res$location, c(
    "/metadata/supplier/url/1", "/services/0/endpoints/0",
    "/services/0/data/0/source/0", "/services/0/data/0/destination/0",
    "/vulnerabilities/0/source/url", "/vulnerabilities/0/references/0/source/url",
    "/releaseNotes/featuredImage", "/releaseNotes/socialImage",
    "/components/0/a~1b~0c/url"
  ))
  expect_identical(nrow(cdx_iri_findings(list(components = list()))), 0L)

  # One bad item alone, in an array of strings or as its only item.
  one <- function(doc) cdx_iri_findings(doc)$location
  expect_identical(one(list(services = list(list(endpoints = list("https://ok.example", "bad endpoint"))))), "/services/0/endpoints/1")
  expect_identical(one(list(metadata = list(supplier = list(url = list("bad url"))))), "/metadata/supplier/url/0")
  # Text with spaces under other keys is not an IRI reference.
  expect_identical(one(list(components = list(list(name = "a b", description = "c d", url = "https://ok.example")))), character())
})

test_that("the official SPDX examples validate", {
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  for (v in c("2.3", "2.2")) {
    ex <- function(f) test_path("fixtures", "third-party", paste0("spdx-", v), sprintf(f, v))
    expect_equal(schema_validate(ex("SPDXJSONExample-v%s.spdx.json"), "spdx-json", v)$status, "pass", label = v)
    expect_equal(schema_validate(ex("SPDXYAMLExample-%s.spdx.yaml"), "spdx-yaml", v)$status, "pass", label = v)
    expect_equal(schema_validate(ex("SPDXXMLExample-v%s.spdx.xml"), "spdx-xml", v)$status, "partial", label = v)
    tv <- schema_validate(ex("SPDXTagExample-v%s.spdx"), "spdx-tv", v)
    expect_equal(tv$status, "partial", label = v)
    # Every tag of the example is read, so the note names none as unchecked.
    expect_false(grepl("not checked", tv$findings$message, fixed = TRUE), label = v)
  }
})

test_that("the CycloneDX test files validate as upstream says", {
  skip_if_not_installed("jsonvalidate")
  dir <- test_path("fixtures", "third-party", "cyclonedx")
  files <- list.files(dir, pattern = "^valid-.*\\.(json|xml)$")
  version <- sub("^.*-(1\\.[0-9]+)\\.(json|xml)$", "\\1", files)
  # sbom bundles no schema for CycloneDX 1.3, so valid-bom-1.3.json is left out.
  keep <- version %in% schema_versions[["cyclonedx-json"]]
  expect_true(all(c("valid-bom-1.4.json", "valid-bom-1.5.xml", "valid-bom-1.7.json") %in% files[keep]))
  for (i in which(keep)) {
    format <- if (endsWith(files[i], ".json")) "cyclonedx-json" else "cyclonedx-xml"
    res <- schema_validate(file.path(dir, files[i]), format, version[i])
    expect_identical(res$status, "pass", label = files[i])
  }
  bad <- schema_validate(file.path(dir, "invalid-component-type-1.6.json"), "cyclonedx-json", "1.6")
  expect_identical(bad$status, "fail")
  expect_identical(bad$findings$location, "/components/0/type")
})

test_that("our own output validates in every format", {
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  expect_valid_in_every_format(fixture_sbom(), "fixture")
})

test_that("an XML file whose root is not Document fails the SPDX XML check", {
  res <- schema_validate(test_path("fixtures", "third-party", "cyclonedx", "valid-bom-1.6.xml"), "spdx-xml")
  expect_equal(res$status, "fail")
  expect_equal(res$findings$message, "The root element is <bom>, not <Document>.")
})

test_that("a JSON file with code in a comment never runs it, and fails", {
  sentinel <- file.path(normalizePath(withr::local_tempdir(), winslash = "/"), "ran.txt")
  payload <- sprintf("console.r.eval(\"writeLines('ran', '%s')\")", sentinel)
  base <- '{"bomFormat":"CycloneDX","specVersion":"1.6"'
  # JavaScript ends a // comment at a carriage return or U+2028; yajl does not.
  for (end in c("\r", " ")) {
    tf <- withr::local_tempfile(fileext = ".json")
    write_text(paste0(base, " //", end, ",\"x\": ", payload, "\n}"), tf)
    res <- schema_validate(tf, "cyclonedx-json", "1.6")
    expect_false(file.exists(sentinel))
    expect_identical(res$status, "fail")
    expect_identical(
      res$findings$message,
      "The file is not valid JSON: it contains comments or other text outside JSON values."
    )
  }
  tf <- withr::local_tempfile(fileext = ".json")
  write_text(paste0(base, ",\"x\": ", payload, "}"), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_false(file.exists(sentinel))
  expect_identical(res$status, "fail")
})

test_that("a __proto__ member reaches the schema as an ordinary property", {
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]][["__proto__"]] <- structure(list(), names = character())
  tf <- withr::local_tempfile(fileext = ".json")
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE), tf)
  expect_match(readChar(tf, file.size(tf), useBytes = TRUE), '"__proto__":{}', fixed = TRUE)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_true(any(
    res$findings$location == "/components/0" &
      res$findings$message == "must NOT have additional properties"
  ))
})

test_that("a block comment fails, and comment marks inside strings do not", {
  tf <- withr::local_tempfile(fileext = ".json")
  write_text('{"bomFormat":"CycloneDX",/*c*/"specVersion":"1.6"}', tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(
    res$findings$message,
    "The file is not valid JSON: it contains comments or other text outside JSON values."
  )
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::read_json(fx("dplyr-1.2.1.cdx.json"))
  doc$components[[1]]$description <- "See https://example.org // not \"a\" /* comment */ \\ at all."
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE), tf)
  expect_identical(schema_validate(tf, "cyclonedx-json", "1.6")$status, "pass")
})

test_that("a NUL byte or text that is not UTF-8 fails with a fixed message", {
  tf <- withr::local_tempfile(fileext = ".json")
  # write_text() writes only UTF-8 text, so these bytes are written directly.
  writeBin(c(charToRaw('{"a":"'), as.raw(0), charToRaw(strrep("x", 300)), charToRaw('"}')), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(res$findings$message, "The file is not valid JSON: it contains a NUL byte.")
  writeBin(c(charToRaw('{"a":"caf'), as.raw(0xe9), charToRaw('"}')), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$findings$message, "The file is not valid JSON: it is not valid UTF-8.")
})

test_that("empty objects and arrays survive the JSON handed to the schema", {
  expect_identical(
    as.character(json_model_text(jsonlite::parse_json('{"a":{},"b":[],"c":[{}],"d":[[]],"e":null}'))),
    '{"a":{},"b":[],"c":[{}],"d":[[]],"e":null}'
  )
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".json")
  write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{},"components":[]}', tf)
  expect_identical(schema_validate(tf, "cyclonedx-json", "1.6")$status, "pass")
})

test_that("the schema is given JSON written from the parsed document, never the file", {
  seen <- new.env()
  local_mocked_bindings(
    has_jsonvalidate = function() TRUE,
    compiled_json_schema = function(format, version) {
      list(validate = function(json, ...) {
        seen$json <- c(seen$json, list(json))
        TRUE
      })
    }
  )
  skip_if_not_installed("yaml")
  x <- fixture_sbom()
  files <- c(
    `cyclonedx-json` = ".cdx.json", `spdx-json` = ".spdx.json", `spdx-yaml` = ".spdx.yaml",
    `spdx-xml` = ".spdx.xml", `spdx-tv` = ".spdx"
  )
  for (f in names(files)) {
    tf <- withr::local_tempfile(fileext = files[[f]])
    write_sbom(x, tf, format = f)
    seen$json <- NULL
    schema_validate(tf, f)
    expect_length(seen$json, 1L)
    json <- seen$json[[1]]
    expect_s3_class(json, "json")
    # Code sbom writes around JSON.parse() of one escaped string literal
    # written by jsonlite: one line, never the path or the file's own text.
    expect_match(json, 'JSON\\.parse\\("\\{[^\n]*\\}"\\)', label = f)
    expect_false(grepl("\n", json, fixed = TRUE), label = f)
    expect_false(identical(as.character(json), tf), label = f)
  }
})

test_that("a string that is never closed fails, and so does text after the value", {
  tf <- withr::local_tempfile(fileext = ".json")
  write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}"x', tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(res$findings$message, "The file is not valid JSON: it has a string that is never closed.")
  # jsonlite itself rejects any other text after the top-level value.
  for (txt in c("{} x", "{}{}", "{} 1", "[1] 2")) {
    write_text(txt, tf)
    res <- schema_validate(tf, "cyclonedx-json", "1.6")
    expect_identical(res$status, "fail", label = txt)
    expect_match(res$findings$message, "^The file is not valid JSON: ", label = txt)
  }
})

test_that("an empty or repeated key fails rather than being renamed", {
  tf <- withr::local_tempfile(fileext = ".json")
  base <- '{"bomFormat":"CycloneDX","specVersion":"1.6"'
  for (rest in c(',"":1}', ',"version":1,"version":2}', ',"metadata":{"component":{"":1}}}')) {
    write_text(paste0(base, rest), tf)
    res <- schema_validate(tf, "cyclonedx-json", "1.6")
    expect_identical(res$status, "fail", label = rest)
    expect_identical(
      res$findings$message,
      "The file is not valid JSON for an SBOM: an object has an empty or repeated key.",
      label = rest
    )
  }
  skip_if_not_installed("yaml")
  y <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text('spdxVersion: SPDX-2.3\n"": 1\n', y)
  res <- schema_validate(y, "spdx-yaml")
  expect_identical(res$status, "fail")
  expect_identical(
    res$findings$message,
    "The file is not valid YAML for an SBOM: an object has an empty or repeated key."
  )
})

test_that("nesting deeper than 200 levels fails", {
  tf <- withr::local_tempfile(fileext = ".json")
  nest <- function(n) {
    paste0('{"bomFormat":"CycloneDX","specVersion":"1.6","x":', strrep("[", n - 1L), strrep("]", n - 1L), "}")
  }
  deep <- "The file is not valid JSON for an SBOM: it nests more than 200 levels deep."
  for (n in c(201L, 600L, 5000L)) {
    write_text(nest(n), tf)
    res <- schema_validate(tf, "cyclonedx-json", "1.6")
    expect_identical(res$status, "fail", label = n)
    expect_identical(res$findings$message, deep, label = n)
  }
  write_text(nest(200L), tf)
  expect_false(identical(schema_validate(tf, "cyclonedx-json", "1.6")$findings$message, deep))
  skip_if_not_installed("yaml")
  y <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(paste0("spdxVersion: SPDX-2.3\nx: ", strrep("[", 300), strrep("]", 300), "\n"), y)
  res <- schema_validate(y, "spdx-yaml")
  expect_identical(res$status, "fail")
  expect_identical(res$findings$message, "The file is not valid YAML for an SBOM: it nests more than 200 levels deep.")
})

test_that("the validator returns each error's path and message only", {
  skip_if_not_installed("jsonvalidate")
  doc <- jsonlite::parse_json('{"bomFormat":"CycloneDX","specVersion":"1.6","x":1,"components":[{"type":"zzz","name":"a"}]}')
  res <- compiled_json_schema("cyclonedx-json", "1.6")$validate(json_validator_input(doc), verbose = TRUE)
  expect_false(res)
  errors <- attr(res, "errors")
  # ajv's verbose errors would also carry the data and schema at each error.
  expect_setequal(names(errors), c("instancePath", "message", "dataPath"))
  expect_true(all(c("", "/components/0/type") %in% errors$instancePath))
})

# Each root-level error used to carry the whole root schema (about 260 KB) and
# the whole document, so 3,000 stray keys in a 26 KB file aborted R.
test_that("thousands of errors are listed briefly and never abort R", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".json")
  write_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6",',
    paste(sprintf('"x%d":1', 1:3000), collapse = ","), "}"
  ), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(nrow(res$findings), 1001L)
  expect_identical(res$findings$message[1001], "2000 more errors are not listed.")
  expect_named(res$findings, c("location", "message"))
})

test_that("the re-review's 5 MB document with 120 stray keys does not abort R", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".json")
  write_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","big":"', strrep("x", 5 * 2^20), '",',
    paste(sprintf('"x%d":1', 1:120), collapse = ","), "}"
  ), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(nrow(res$findings), 121L)
  expect_lt(max(nchar(res$findings$message)), 200)
})

test_that("a document whose escaped text is too long for V8 is never handed to it", {
  seen <- new.env()
  local_mocked_bindings(
    has_jsonvalidate = function() TRUE,
    compiled_json_schema = function(format, version) {
      list(validate = function(json, ...) {
        seen$n <- c(seen$n, nchar(json))
        TRUE
      })
    },
    json_max_mb = function() 0.01
  )
  tf <- withr::local_tempfile(fileext = ".json")
  # 3,000 backslashes: 6,000 characters in the file, 6,000 in the JSON
  # jsonlite writes, and 12,000 in the string literal around it, which is
  # more than 0.01 MB (10,486 characters).
  write_text(paste0('{"bomFormat":"CycloneDX","specVersion":"1.6","x":"', strrep("\\\\", 3000), '"}'), tf)
  res <- schema_validate(tf, "cyclonedx-json", "1.6")
  expect_identical(res$status, "skipped")
  expect_identical(res$findings, data.frame(
    location = "",
    message = "The document is too large for the JSON schema check (0.1 MB; the limit is 0.01 MB), so the schema was not checked."
  ))
  expect_null(seen$n)
  # Half as many fit, and are handed to the validator.
  write_text(paste0('{"bomFormat":"CycloneDX","specVersion":"1.6","x":"', strrep("\\\\", 1500), '"}'), tf)
  expect_identical(schema_validate(tf, "cyclonedx-json", "1.6")$status, "pass")
  expect_length(seen$n, 1L)
})

test_that("the size limit for V8 is 32 MB", {
  expect_identical(json_max_mb(), 32)
})

test_that("the XSD check lists at most 1,000 errors, each quoting a value briefly", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>',
    '<component type="', strrep("q", 100), '"><name>a</name></component>',
    # libxml2 stops its message about this one inside the quoted value.
    '<component type="', strrep("z", 2e5), '"><name>a</name></component>',
    strrep('<component type="library"><name>a</name><bogus/></component>', 4998), "</components></bom>"
  ), tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_identical(res$status, "fail")
  expect_identical(nrow(res$findings), 1001L)
  expect_identical(res$findings$message[1001], "4000 more errors are not listed.")
  expect_identical(res$findings$location, rep("", 1001L))
  head <- paste0(
    "Element '{http://cyclonedx.org/schema/bom/1.6}component', attribute 'type': ",
    "[facet 'enumeration'] The value '"
  )
  ellipsis <- intToUtf8(0x2026)
  expect_match(
    res$findings$message[1],
    paste0(head, strrep("q", 79), ellipsis, "' is not an element of the set {'application', "),
    fixed = TRUE
  )
  expect_identical(res$findings$message[2], paste0(head, strrep("z", 79), ellipsis))
  expect_lt(max(nchar(res$findings$message)), 2000L)
})

test_that("one error more than the XSD check lists is named in the singular", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>',
    strrep('<component type="library"><name>a</name><bogus/></component>', 1001), "</components></bom>"
  ), tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_identical(nrow(res$findings), 1001L)
  expect_identical(res$findings$message[1001], "1 more error is not listed.")
})

test_that("an XML file whose name holds < or > is checked from its bytes", {
  dir <- withr::local_tempdir()
  path <- file.path(dir, "report<v2>.cdx.xml")
  file.copy(test_path("fixtures", "third-party", "cyclonedx", "valid-bom-1.6.xml"), path)
  expect_identical(schema_validate(path, "cyclonedx-xml", "1.6")$status, "pass")
  expect_identical(validate_sbom(path, checks = "schema")$status, "pass")
})

test_that("an XML document that uses entities declared in its DTD skips the XSD check", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY n "lib">]>',
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>',
    '<component type="library"><name>&n;</name></component></components></bom>'
  ), tf)
  res <- schema_validate(tf, "cyclonedx-xml", "1.6")
  expect_identical(res$status, "skipped")
  expect_identical(
    res$findings$message,
    "The document uses entities declared in its DTD, which sbom does not expand, so the XSD check did not run."
  )
  v <- validate_sbom(tf, checks = "schema")
  expect_identical(v$status, "skipped")
  expect_identical(v$findings$severity, "info")
  # A value that quotes libxml2's words is still an error.
  write_text(paste0(
    '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>',
    '<component type="xmlSchemaVDocWalk entity reference"><name>a</name></component></components></bom>'
  ), tf)
  expect_identical(schema_validate(tf, "cyclonedx-xml", "1.6")$status, "fail")
})

# SWID ---------------------------------------------------------------------------

swid_iso_note <- paste(
  "sbom.swid_xsd is not the ISO/IEC 19770-2:2015 schema as ISO publishes it",
  "(SHA-256 6af9d0554932102ace5c696f723c1dc4a4b1a9846908cddec67ccc0518c0e5d4),",
  "so the tag was checked against sbom's structural rules."
)

swid_imports_note <- paste(
  "The W3C schemas that the ISO/IEC 19770-2:2015 schema imports could not be copied from sbom's installation,",
  "so the tag was checked against sbom's structural rules."
)

swid_bundle_note <- paste(
  "sbom does not bundle the ISO/IEC 19770-2:2015 schema, so the tag was checked against sbom's structural rules;",
  "set the option sbom.swid_xsd to a copy of the ISO schema to check it fully."
)

swid_tag_path <- function(x = fixture_sbom(), env = parent.frame()) {
  tf <- withr::local_tempfile(fileext = ".swidtag", .local_envir = env)
  write_text(swid_tag(x), tf)
  tf
}

swid_text_path <- function(text, env = parent.frame()) {
  tf <- withr::local_tempfile(fileext = ".swidtag", .local_envir = env)
  write_text(text, tf)
  tf
}

notes_of <- function(message) {
  data.frame(location = rep("", length(message)), message = message)
}

# Makes every way xml2 reaches the network fail loudly and be recorded, for
# the rest of the calling test: its entity loader calls download_file_callback()
# in xml2's namespace, which calls utils::download.file(), and read_xml()
# opens a URL with curl::curl() when curl is installed, and with url()
# otherwise. Checks first that the tripwire works on both routes: a schema
# that imports by URL reaches it, and so does read_xml() given a URL.
# Returns the environment whose `urls` lists what was asked for.
local_no_network <- function(env = parent.frame()) {
  hits <- new.env(parent = emptyenv())
  hits$urls <- character()
  record <- function(url, ...) {
    hits$urls <- c(hits$urls, as.character(url)[[1L]])
    stop("sbom must not use the network.")
  }
  local_mocked_bindings(download_file_callback = record, .package = "xml2", .env = env)
  local_mocked_bindings(download.file = record, .package = "utils", .env = env)
  local_mocked_bindings(url = record, .package = "base", .env = env)
  if (requireNamespace("curl", quietly = TRUE)) {
    local_mocked_bindings(curl = record, .package = "curl", .env = env)
  }
  probe <- withr::local_tempfile(fileext = ".xsd")
  write_text(paste0(
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">',
    '<xs:import namespace="urn:a" schemaLocation="http://example.invalid/tripwire.xsd"/>',
    '<xs:element name="r"/></xs:schema>'
  ), probe)
  xml2::xml_validate(xml2::read_xml("<r/>"), xml2::read_xml(probe, options = c("NOBLANKS", "NONET")))
  expect_error(xml2::read_xml("http://example.invalid/tripwire.xml"), "sbom must not use the network.", fixed = TRUE)
  expect_identical(hits$urls, c("http://example.invalid/tripwire.xsd", "http://example.invalid/tripwire.xml"))
  hits$urls <- character()
  hits
}

test_that("the ISO SWID schema is not bundled, and the two W3C schemas it imports are", {
  expect_identical(system.file("schemas", "swid", "swid-2015.xsd", package = "sbom"), "")
  expect_setequal(
    list.files(system.file("schemas", "swid", package = "sbom")), c("xmldsig-core-schema.xsd", "xml.xsd")
  )
  m <- utils::read.csv(system.file("schemas", "MANIFEST.csv", package = "sbom"), colClasses = "character")
  swid <- m[startsWith(m$file, "swid/"), ]
  expect_identical(swid$file, c("swid/xmldsig-core-schema.xsd", "swid/xml.xsd"))
  expect_identical(swid$modified, c("FALSE", "FALSE"))
})

test_that("COPYRIGHTS names every bundled schema and data file, with the W3C notices in full", {
  text <- paste(readLines(system.file("COPYRIGHTS", package = "sbom"), warn = FALSE, encoding = "UTF-8"), collapse = "\n")
  for (dir in c("schemas", "extdata")) {
    for (f in list.files(system.file(dir, package = "sbom"), recursive = TRUE)) {
      path <- file.path("inst", dir, f)
      named <- grepl(path, text, fixed = TRUE) || grepl(paste0(dirname(path), "/*"), text, fixed = TRUE)
      expect_true(named, label = path)
    }
  }
  expect_false(grepl("inst/schemas/swid/swid-2015.xsd", text, fixed = TRUE))
  # W3C-19980720 asks for the full text of its notice; W3C-20150513 too.
  for (sentence in c(
    "W3C® SOFTWARE NOTICE AND LICENSE",
    "The full text of this NOTICE in a location viewable to users of the redistributed or derivative work.",
    "This formulation of W3C's notice and license became active on August 14 1998",
    "If none exist, the W3C Software and Document Short Notice should be included.",
    "Title to copyright in this work will at all times remain with copyright holders."
  )) {
    expect_true(grepl(sentence, text, fixed = TRUE), label = sentence)
  }
})

test_that("COPYRIGHTS gives the xmldsig schema the licence its header states", {
  xsd <- readLines(system.file("schemas", "swid", "xmldsig-core-schema.xsd", package = "sbom"), warn = FALSE)
  expect_true(any(grepl("copyright-software-19980720", xsd, fixed = TRUE)))
  lines <- readLines(system.file("COPYRIGHTS", package = "sbom"), warn = FALSE, encoding = "UTF-8")
  start <- which(lines == "inst/schemas/swid/xmldsig-core-schema.xsd")
  expect_length(start, 1L)
  blank <- which(lines[-seq_len(start)] == "")
  entry <- paste(lines[start:(start + blank[[1]] - 1L)], collapse = "\n")
  expect_match(entry, "W3C Software License (SPDX: W3C-19980720)", fixed = TRUE)
  expect_match(entry, "The Internet Society and W3C", fixed = TRUE)
})

test_that("the option names the ISO schema only by its SHA-256 as ISO publishes it", {
  expect_identical(swid_iso_sha256, "6af9d0554932102ace5c696f723c1dc4a4b1a9846908cddec67ccc0518c0e5d4")
  hits <- local_no_network()
  good <- swid_tag_path()
  broken <- swid_text_path(sub('tagVersion="[0-9]+"', 'tagVersion="x"', swid_tag(fixture_sbom())))
  other <- withr::local_tempfile(fileext = ".xsd")
  write_text('<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>\n', other)
  for (value in list(other, file.path(withr::local_tempdir(), "missing.xsd"), withr::local_tempdir(), TRUE, "")) {
    withr::local_options(sbom.swid_xsd = value)
    label <- paste(format(value), collapse = "")
    # Any other value gets the structural rules, with a note saying so.
    expect_identical(schema_validate(good, "swid"), list(status = "partial", findings = notes_of(swid_iso_note)), label = label)
    # So a broken tag still fails.
    expect_identical(schema_validate(broken, "swid"), list(
      status = "fail",
      findings = data.frame(
        location = c("/SoftwareIdentity", ""),
        message = c("The tagVersion x is not an integer.", swid_iso_note)
      )
    ), label = label)
  }
  expect_identical(hits$urls, character())
  # Unset, the note is the one that says what to set.
  withr::local_options(sbom.swid_xsd = NULL)
  expect_identical(schema_validate(good, "swid"), list(status = "partial", findings = notes_of(swid_bundle_note)))
})

test_that("schemas that would reach the network are never compiled", {
  hits <- local_no_network()
  dir <- withr::local_tempdir()
  xs <- '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"'
  write_text(paste0(xs, '><xs:import namespace="urn:a" schemaLocation="http://example.invalid/a.xsd"/></xs:schema>\n'),
             file.path(dir, "remote.xsd"))
  probes <- list(
    # A file: URL whose target imports by http.
    file_url = paste0(xs, '><xs:include schemaLocation="file://', file.path(dir, "remote.xsd"), '"/></xs:schema>\n'),
    # xml:base turns a relative location into a URL.
    xml_base = paste0(xs, ' xml:base="http://example.invalid/base/"><xs:import namespace="urn:a" schemaLocation="a.xsd"/></xs:schema>\n'),
    # An external entity in a schema it imports.
    entity = paste0(xs, '><xs:import namespace="urn:b" schemaLocation="entity.xsd"/></xs:schema>\n'),
    # A schema that does not compile, so libxml2 would follow the tag's own
    # xsi:schemaLocation.
    broken = paste0(xs, '><xs:element name="SoftwareIdentity" type="nope:type"/></xs:schema>\n')
  )
  write_text(paste0(
    '<!DOCTYPE xs:schema [<!ENTITY e SYSTEM "http://example.invalid/entity">]>\n',
    xs, ' targetNamespace="urn:b"><xs:annotation><xs:documentation>&e;</xs:documentation></xs:annotation></xs:schema>\n'
  ), file.path(dir, "entity.xsd"))
  hinted <- swid_text_path(sub(
    "<SoftwareIdentity ",
    paste0(
      '<SoftwareIdentity xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ',
      'xsi:schemaLocation="http://standards.iso.org/iso/19770/-2/2015/schema.xsd http://example.invalid/evil.xsd" '
    ),
    swid_tag(fixture_sbom()), fixed = TRUE
  ))
  for (nm in names(probes)) {
    path <- file.path(dir, paste0(nm, ".xsd"))
    write_text(probes[[nm]], path)
    withr::local_options(sbom.swid_xsd = path)
    expect_identical(schema_validate(hinted, "swid"), list(status = "partial", findings = notes_of(swid_iso_note)), label = nm)
  }
  expect_identical(hits$urls, character())
})

test_that("a tag the schema accepts still fails without a tagCreator", {
  # Stands in for the ISO schema a schema that accepts any SoftwareIdentity.
  xsd <- withr::local_tempfile(fileext = ".xsd")
  write_text(paste0(
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" ',
    'targetNamespace="http://standards.iso.org/iso/19770/-2/2015/schema.xsd">',
    '<xs:element name="SoftwareIdentity"><xs:complexType><xs:sequence>',
    '<xs:any processContents="skip" minOccurs="0" maxOccurs="unbounded"/>',
    '</xs:sequence><xs:anyAttribute processContents="skip"/></xs:complexType></xs:element></xs:schema>\n'
  ), xsd)
  local_mocked_bindings(
    swid_xsd_option = function() readBin(xsd, "raw", file.size(xsd)),
    swid_with_local_schema = function(bytes, f) f(xsd)
  )
  tag <- swid_tag(fixture_sbom())
  expect_identical(schema_validate(swid_text_path(tag), "swid"), list(status = "pass", findings = empty_findings()))
  orphan <- swid_text_path(sub('role="tagCreator"', 'role="softwareCreator"', tag, fixed = TRUE))
  expect_identical(schema_validate(orphan, "swid"), list(
    status = "fail",
    findings = data.frame(location = "/SoftwareIdentity", message = "No Entity element has the role tagCreator.")
  ))
})

# A file that imports the two W3C schemas as the ISO schema does, standing in
# for it: the test gives sbom its SHA-256 as the ISO schema's.
local_stand_in_xsd <- function(env = parent.frame()) {
  xsd <- withr::local_tempfile(fileext = ".xsd", .local_envir = env)
  write_text(paste0(
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n',
    '<xs:import namespace="http://www.w3.org/2000/09/xmldsig#" ',
    'schemaLocation="http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd"/>\n',
    '<xs:import namespace="http://www.w3.org/XML/1998/namespace" schemaLocation="http://www.w3.org/2001/xml.xsd"/>\n',
    '</xs:schema>\n'
  ), xsd)
  local_mocked_bindings(swid_iso_sha256 = cli::hash_file_sha256(xsd), .env = env)
  withr::local_options(sbom.swid_xsd = xsd, .local_envir = env)
  xsd
}

test_that("the option's file is read once, and the copy holds the bytes that were checked", {
  xsd <- local_stand_in_xsd()
  checked <- readBin(xsd, "raw", file.size(xsd))
  bytes <- swid_xsd_option()
  expect_identical(bytes, checked)
  # The file changes after it was checked; the copy is made from the bytes
  # checked, never from the file.
  write_text('<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>\n', xsd)
  copy <- swid_with_local_schema(bytes, function(schema) {
    list(files = sort(list.files(dirname(schema))), text = rawToChar(readBin(schema, "raw", file.size(schema))))
  })
  expect_identical(copy$files, c("swid-2015.xsd", "xml.xsd", "xmldsig-core-schema.xsd"))
  expected <- sub('"http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd"', '"xmldsig-core-schema.xsd"', rawToChar(checked), fixed = TRUE)
  expect_identical(copy$text, sub('"http://www.w3.org/2001/xml.xsd"', '"xml.xsd"', expected, fixed = TRUE))
})

test_that("a missing bundled W3C schema gives the structural rules, and nothing is compiled", {
  hits <- local_no_network()
  local_stand_in_xsd()
  compiled <- new.env(parent = emptyenv())
  compiled$n <- 0L
  local_mocked_bindings(validate_xml = function(...) {
    compiled$n <- compiled$n + 1L
    validation_result("pass")
  })
  # The install lacks xml.xsd, as a damaged or trimmed one would.
  w3c <- system.file("schemas", "swid", "xmldsig-core-schema.xsd", package = "sbom")
  missing <- file.path(withr::local_tempdir(), "xml.xsd")
  for (files in list(w3c, c(w3c, missing))) {
    local_mocked_bindings(swid_w3c_files = function() files)
    res <- expect_no_warning(schema_validate(swid_tag_path(), "swid"))
    expect_identical(res, list(status = "partial", findings = notes_of(swid_imports_note)))
    broken <- swid_text_path(sub('tagVersion="[0-9]+"', 'tagVersion="x"', swid_tag(fixture_sbom())))
    res <- expect_no_warning(schema_validate(broken, "swid"))
    expect_identical(res, list(
      status = "fail",
      findings = data.frame(
        location = c("/SoftwareIdentity", ""),
        message = c("The tagVersion x is not an integer.", swid_imports_note)
      )
    ))
  }
  expect_identical(compiled$n, 0L)
  expect_identical(hits$urls, character())
})

test_that("with the option naming the ISO schema, a tag is checked fully and offline", {
  xsd <- Sys.getenv("SBOM_TEST_SWID_XSD")
  skip_if(!nzchar(xsd), "SBOM_TEST_SWID_XSD names no copy of the ISO schema.")
  expect_identical(cli::hash_file_sha256(xsd), swid_iso_sha256)
  hits <- local_no_network()
  withr::local_options(sbom.swid_xsd = xsd)
  copies <- function() grep("^sbom-swid-", list.files(tempdir(), all.files = TRUE), value = TRUE)
  expect_identical(copies(), character())
  for (x in list(fixture_sbom(), sbom_installed(lib = fixture_lib()), minimal_sbom())) {
    res <- expect_no_warning(schema_validate(swid_tag_path(x), "swid"))
    expect_identical(res, list(status = "pass", findings = empty_findings()))
  }
  expect_identical(schema_validate(fx("dplyr-1.2.1.swidtag"), "swid")$status, "pass")
  # The structural rules are no stricter than the schema.
  lenient <- paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'name="" tagId="" version="" versionScheme="calendar">',
    '<Entity name="" role="tagCreator"/><Link href="" rel="requires"/></SoftwareIdentity>\n'
  )
  expect_identical(schema_validate(swid_text_path(lenient), "swid")$status, "pass")
  # A tag the schema rejects fails with libxml2's finding, which the
  # structural rules would not have caught: a bad boolean, and a signature
  # that the bundled XML Signature schema rejects.
  tag <- swid_tag(fixture_sbom())
  res <- schema_validate(swid_text_path(sub("<SoftwareIdentity ", "<SoftwareIdentity corpus=\"maybe\" ", tag, fixed = TRUE)), "swid")
  expect_identical(res$status, "fail")
  expect_match(res$findings$message[[1]], "corpus")
  signed <- sub(
    "</SoftwareIdentity>",
    '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Bogus/></Signature></SoftwareIdentity>',
    tag, fixed = TRUE
  )
  res <- schema_validate(swid_text_path(signed), "swid")
  expect_identical(res$status, "fail")
  expect_match(res$findings$message[[1]], "SignedInfo")
  # The schema passes a tag with no tagCreator, which the standard requires.
  orphan <- sub('role="tagCreator"', 'role="softwareCreator"', tag, fixed = TRUE)
  expect_identical(schema_validate(swid_text_path(orphan), "swid"), list(
    status = "fail",
    findings = data.frame(location = "/SoftwareIdentity", message = "No Entity element has the role tagCreator.")
  ))
  # validate_sbom() gets no schema note.
  v <- validate_sbom(swid_tag_path(), profile = "none")
  expect_false("schema" %in% v$findings$check)
  # The ISO schema with one import changed is not the ISO schema.
  changed <- withr::local_tempfile(fileext = ".xsd")
  text <- rawToChar(readBin(xsd, "raw", file.size(xsd)))
  writeBin(charToRaw(sub(
    "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd", "file:///nonexistent/xmldsig-core-schema.xsd",
    text, fixed = TRUE, useBytes = TRUE
  )), changed)
  withr::local_options(sbom.swid_xsd = changed)
  expect_identical(schema_validate(swid_text_path(signed), "swid"), list(status = "partial", findings = notes_of(swid_iso_note)))
  expect_identical(hits$urls, character())
  # The temporary copies of the schema are gone.
  expect_identical(copies(), character())
})

test_that("CycloneDX XSD validation never reaches the network", {
  hits <- local_no_network()
  for (v in c("1.4", "1.5", "1.6", "1.7")) {
    tf <- withr::local_tempfile(fileext = ".cdx.xml")
    write_sbom(fixture_sbom(), tf, format = "cyclonedx-xml", version = v)
    expect_identical(schema_validate(tf, "cyclonedx-xml", v)$status, "pass", label = v)
  }
  # A schemaLocation hint in the document is not followed.
  hinted <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(sub(
    "<bom ",
    paste0(
      '<bom xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ',
      'xsi:schemaLocation="http://cyclonedx.org/schema/bom/1.6 http://example.invalid/bom.xsd" '
    ),
    cdx_xml(fixture_sbom(), "1.6"), fixed = TRUE
  ), hinted)
  expect_identical(schema_validate(hinted, "cyclonedx-xml", "1.6")$status, "pass")
  expect_identical(hits$urls, character())
})
