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

test_that("our own output still passes every schema", {
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
