tp <- function(...) test_path("fixtures", "third-party", ...)

# The sentence of the sbom_read_error that reading `path` raises, or NA when
# it raises none. The printed message holds the same words.
read_error <- function(path, ...) {
  cnd <- tryCatch(read_document(path, ...), sbom_read_error = identity)
  if (!inherits(cnd, "sbom_read_error")) {
    return(NA_character_)
  }
  expect_identical(trimws(gsub("[[:space:]]+", " ", conditionMessage(cnd))), cnd$sentence)
  cnd$sentence
}

test_that("our own formats and versions are detected from the content, whatever the extension", {
  skip_on_cran()
  skip_if_not_installed("yaml")
  x <- fixture_sbom()
  formats <- sbom_formats()
  formats <- formats[formats$format != "csv", ]
  expect_setequal(formats$format, read_formats)
  dir <- withr::local_tempdir()
  for (i in seq_len(nrow(formats))) {
    format <- formats$format[i]
    for (version in strsplit(formats$versions[i], ", ", fixed = TRUE)[[1]]) {
      label <- paste(format, version)
      path <- file.path(dir, paste0("sbom", formats$extension[i]))
      write_sbom(x, path, format = format, version = version)
      d <- read_document(path)
      expect_identical(
        d[c("format", "version", "path")],
        list(format = format, version = version, path = path),
        label = label
      )
      expect_type(d$doc, "list")
      renamed <- file.path(dir, "x.txt")
      file.rename(path, renamed)
      d <- read_document(renamed)
      expect_identical(d[c("format", "version")], list(format = format, version = version), label = label)
      unlink(renamed)
    }
  }
})

test_that("read_formats is every registry format but the CSV inventory", {
  expect_identical(read_formats, setdiff(names(format_registry()), "csv"))
})

test_that("third-party files are detected", {
  skip_if_not_installed("yaml")
  cases <- list(
    list(tp("spdx-2.3", "SPDXTagExample-v2.3.spdx"), "spdx-tv", "2.3"),
    list(tp("spdx-2.2", "SPDXTagExample-v2.2.spdx"), "spdx-tv", "2.2"),
    list(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"), "spdx-json", "2.3"),
    list(tp("spdx-2.3", "SPDXYAMLExample-2.3.spdx.yaml"), "spdx-yaml", "2.3"),
    list(tp("spdx-2.2", "SPDXXMLExample-v2.2.spdx.xml"), "spdx-xml", "2.2"),
    list(tp("cyclonedx", "valid-bom-1.5.xml"), "cyclonedx-xml", "1.5"),
    list(tp("cyclonedx", "valid-bom-1.3.json"), "cyclonedx-json", "1.3"),
    list(tp("spdx-3", "package_sbom.json"), "spdx3-jsonld", "3.0.1"),
    list(tp("swid", "hand.swidtag"), "swid", "2015")
  )
  for (case in cases) {
    d <- read_document(case[[1]])
    expect_identical(c(d$format, d$version), c(case[[2]], case[[3]]), label = basename(case[[1]]))
  }
})

test_that("a format that is given must be the file's format", {
  cdx <- tp("cyclonedx", "valid-bom-1.6.json")
  expect_identical(read_document(cdx, format = "cyclonedx-json")$version, "1.6")
  expect_identical(
    read_error(cdx, format = "spdx-json"),
    "valid-bom-1.6.json is CycloneDX JSON, not SPDX JSON."
  )
  # The file is parsed with the given format's parser before its family is
  # checked.
  expect_identical(read_error(cdx, format = "cyclonedx-xml"), "valid-bom-1.6.json is not valid CycloneDX XML.")
  expect_identical(
    read_error(tp("cyclonedx", "valid-bom-1.6.xml"), format = "spdx-xml"),
    "valid-bom-1.6.xml is CycloneDX XML, not SPDX XML."
  )
  expect_error(read_document(cdx, format = "csv"), "cannot read its CSV inventory")
  msg <- tryCatch(read_document(cdx, format = "nope"), error = conditionMessage)
  for (f in read_formats) expect_match(msg, f, fixed = TRUE)
})

test_that("files that are not SBOMs are read errors", {
  skip_on_cran()
  dir <- withr::local_tempdir()
  empty <- file.path(dir, "empty.json")
  write_text("", empty)
  name_only <- file.path(dir, "name.json")
  write_text('{"name":"x"}', name_only)
  text <- file.path(dir, "notes.txt")
  write_text("These are notes, not an SBOM.\nspdx is mentioned here.\n", text)
  csv <- file.path(dir, "inventory.csv")
  write_sbom(fixture_sbom(), csv, format = "csv")
  lock <- test_path("fixtures", "renv", "modern", "renv.lock")
  for (path in c(empty, lock, name_only, text, csv)) {
    expect_identical(
      read_error(path),
      paste0(basename(path), " is not an SBOM in a format sbom reads."),
      label = basename(path)
    )
  }
  expect_identical(read_error(file.path(dir, "missing.json")), "missing.json does not exist.")
})

test_that("UTF-16 and UTF-32 are refused, and a UTF-8 byte-order mark is dropped", {
  tf <- withr::local_tempfile(fileext = ".json")
  # write_text() writes only UTF-8, so these bytes are written directly.
  boms <- list(
    `UTF-16` = c(0xff, 0xfe, 0x7b, 0x00, 0x7d, 0x00),
    `UTF-16` = c(0xfe, 0xff, 0x00, 0x7b, 0x00, 0x7d),
    `UTF-32` = c(0xff, 0xfe, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00),
    `UTF-32` = c(0x00, 0x00, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x7b)
  )
  for (i in seq_along(boms)) {
    writeBin(as.raw(boms[[i]]), tf)
    expect_identical(
      read_error(tf),
      paste0(basename(tf), " is ", names(boms)[i], " text; sbom reads SBOMs written in UTF-8.")
    )
  }
  write_text('\ufeff{"bomFormat":"CycloneDX","specVersion":"1.6"}', tf)
  expect_identical(read_document(tf)$format, "cyclonedx-json")
  write_text('\ufeff<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>', tf)
  expect_identical(read_document(tf)$format, "cyclonedx-xml")
})

test_that("the JSON checks of the schema layer apply when reading", {
  tf <- withr::local_tempfile(fileext = ".json")
  file <- basename(tf)
  write_text('{"bomFormat":"CycloneDX",/* note */"specVersion":"1.6"}', tf)
  expect_identical(
    read_error(tf),
    paste0(file, " is not valid JSON: it contains comments or other text outside JSON values.")
  )
  write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}"x', tf)
  expect_identical(read_error(tf), paste0(file, " is not valid JSON: it has a string that is never closed."))
  write_text(paste0('{"bomFormat":"CycloneDX","specVersion":"1.6","x":', strrep("[", 300), strrep("]", 300), "}"), tf)
  expect_identical(read_error(tf), paste0(file, " is not valid JSON: it nests more than 200 levels deep."))
  write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"version":2}', tf)
  expect_identical(
    read_error(tf),
    paste0(file, " is not valid CycloneDX JSON: an object has an empty or repeated key.")
  )
  # write_text() cannot hold a NUL, so these bytes are written directly.
  writeBin(c(charToRaw('{"a":"'), as.raw(0), charToRaw('"}')), tf)
  expect_identical(read_error(tf), paste0(file, " is not valid JSON: it contains a NUL byte."))
})

test_that("read errors name the file by its basename and quote none of its text", {
  dir <- withr::local_tempdir()
  json <- file.path(dir, "bad.json")
  write_text('{"bomFormat":"CycloneDX", "token" sbom-secret-marker}', json)
  msg <- read_error(json)
  expect_match(msg, "^bad\\.json is not valid JSON: [^\n]*\\.$")
  xml <- file.path(dir, "bad.xml")
  write_text('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><name>sbom-secret-marker</bom>', xml)
  expect_identical(read_error(xml), "bad.xml is not well-formed XML.")
  tv <- file.path(dir, "bad.spdx")
  write_text("SPDXVersion: SPDX-2.3\nRelationship: SPDXRef-DOCUMENT sbom-secret-marker\n", tv)
  expect_identical(read_error(tv), "bad.spdx is not valid SPDX tag-value: a relationship does not have three parts.")
  for (path in c(json, xml, tv)) {
    msg <- read_error(path)
    expect_false(grepl("sbom-secret-marker", msg, fixed = TRUE), label = basename(path))
    expect_false(grepl(dir, msg, fixed = TRUE), label = basename(path))
  }
})

test_that("errors are reported against the caller", {
  caller <- function(path) read_document(path)
  missing <- file.path(withr::local_tempdir(), "missing.json")
  cnd <- tryCatch(caller(missing), error = identity)
  expect_s3_class(cnd, "sbom_read_error")
  expect_identical(cnd$call, quote(caller(missing)))
})

test_that("an SPDX 3 document needs an @graph array", {
  tf <- withr::local_tempfile(fileext = ".json")
  for (graph in c("", ',"@graph":{}', ',"@graph":"x"')) {
    write_text(paste0('{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"', graph, "}"), tf)
    expect_identical(
      read_error(tf),
      paste0(basename(tf), " is not valid SPDX 3 JSON-LD: it has no @graph array."),
      label = graph
    )
  }
  write_text(paste0(
    '{"@context":["https://example.org/x.jsonld",',
    '"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],"@graph":[]}'
  ), tf)
  d <- read_document(tf)
  expect_identical(c(d$format, d$version), c("spdx3-jsonld", "3.0.1"))
})

test_that("SPDX YAML needs the yaml package, and its aliases are refused", {
  path <- tp("spdx-2.3", "SPDXYAMLExample-2.3.spdx.yaml")
  local({
    local_mocked_bindings(has_yaml = function() FALSE)
    want <- "Reading SPDX YAML needs the yaml package, so SPDXYAMLExample-2.3.spdx.yaml was not read."
    expect_identical(read_error(path), want)
    expect_identical(read_error(path, format = "spdx-yaml"), want)
  })
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text("spdxVersion: SPDX-2.3\nname: &a x\nother: *a\n", tf)
  expect_identical(read_error(tf), paste0(basename(tf), " uses YAML aliases (*a), which sbom does not expand."))
})

test_that("an external entity in CycloneDX XML or SWID is never expanded", {
  secret <- withr::local_tempfile(fileext = ".txt")
  write_text("sbom-secret-marker\n", secret)
  doctype <- function(root) {
    # file:///C:/... on Windows, file:///tmp/... elsewhere.
    url <- paste0("file:///", sub("^/", "", normalizePath(secret, winslash = "/")))
    sprintf('<!DOCTYPE %s [<!ENTITY x SYSTEM "%s">]>\n', root, url)
  }
  cdx <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n', doctype("bom"),
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>',
    '<component type="library"><name>&x;</name><version>1.0</version></component>',
    "</components></bom>\n"
  ), cdx)
  expect_no_error(d <- read_document(cdx))
  expect_identical(d$format, "cyclonedx-xml")
  expect_identical(d$doc$components[[1]]$version, "1.0")
  expect_false(any(grepl("sbom-secret-marker", unlist(d$doc), fixed = TRUE)))

  swid <- withr::local_tempfile(fileext = ".swidtag")
  write_text(paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n', doctype("SoftwareIdentity"),
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="x" tagId="x">',
    '<Entity name="Example" regid="example.org" role="tagCreator">&x;</Entity></SoftwareIdentity>\n'
  ), swid)
  expect_no_error(d <- read_document(swid))
  expect_identical(d$format, "swid")
  expect_false(any(grepl("sbom-secret-marker", unlist(d$doc), fixed = TRUE)))
})

test_that("recursive entities are a read error, not an expansion", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  levels <- vapply(1:9, function(i) {
    sprintf('<!ENTITY e%d "%s">', i, strrep(sprintf("&e%d;", i - 1L), 10))
  }, "")
  write_text(paste0(
    '<?xml version="1.0"?>\n<!DOCTYPE bom [<!ENTITY e0 "lol">', paste(levels, collapse = ""), "]>\n",
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><metadata><timestamp>&e9;</timestamp></metadata></bom>\n'
  ), tf)
  expect_identical(read_error(tf), paste0(basename(tf), " is not well-formed XML."))
})

test_that("an XML warning from the parser is a read error", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><x:name>a</x:name></bom>', tf)
  expect_identical(read_error(tf), paste0(basename(tf), " is not well-formed XML."))
})

test_that("a read error keeps its whole sentence however narrow the console", {
  skip_if_not_installed("yaml")
  withr::local_options(cli.width = 30, cli.condition_width = 30)
  dir <- withr::local_tempdir()
  yaml <- file.path(dir, "my-company-product-release-candidate-sbom-2026-11-06.spdx.yaml")
  write_text("spdxVersion: SPDX-2.3\nname: &a x\nother: *a\n", yaml)
  json <- file.path(dir, "c.json")
  write_text('{"bomFormat":"CycloneDX",/* c */"specVersion":"1.6"}', json)
  tv <- file.path(dir, "t.spdx")
  write_text("SPDXVersion: SPDX-2.3\nRelationship: SPDXRef-DOCUMENT x\n", tv)
  want <- c(
    paste0(basename(yaml), " uses YAML aliases (*a), which sbom does not expand."),
    "c.json is not valid JSON: it contains comments or other text outside JSON values.",
    "t.spdx is not valid SPDX tag-value: a relationship does not have three parts."
  )
  paths <- c(yaml, json, tv)
  for (i in seq_along(paths)) {
    cnd <- tryCatch(read_document(paths[i]), sbom_read_error = identity)
    expect_identical(cnd$sentence, want[i])
    # The printed form wraps, but keeps every word.
    expect_match(conditionMessage(cnd), "\n", fixed = TRUE)
    expect_identical(trimws(gsub("[[:space:]]+", " ", conditionMessage(cnd))), want[i])
  }
})

test_that("parser messages give way to a fixed phrase, with no line taken from their text", {
  skip_on_cran()
  dir <- withr::local_tempdir()
  cases <- c(
    enc.xml = '<?xml version="1.0" encoding="sbom-secret-marker"?>\n<bom/>\n',
    uri.xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6 sbom-secret-marker"/>\n',
    tag.xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6">\n<sbom-secret-marker>\n</bom>\n',
    ent.xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6">&sbomsecretmarker;</bom>\n',
    # libxml2 quotes the namespace; a "line" in it must not become one.
    u.xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.6 line 31337"/>\n'
  )
  want <- c(
    enc.xml = "enc.xml is not well-formed XML.",
    uri.xml = "uri.xml is not well-formed XML.",
    tag.xml = "tag.xml is not well-formed XML.",
    ent.xml = "ent.xml is not well-formed XML.",
    u.xml = "u.xml is not well-formed XML."
  )
  for (name in names(cases)) {
    path <- file.path(dir, name)
    write_text(cases[[name]], path)
    expect_identical(read_error(path), want[[name]], label = name)
  }
  expect_identical(
    read_error(file.path(dir, "tag.xml"), format = "cyclonedx-xml"),
    "tag.xml is not valid CycloneDX XML."
  )
  skip_if_not_installed("yaml")
  dup <- file.path(dir, "dup.yaml")
  write_text("spdxVersion: SPDX-2.3\nsbom-secret-marker: 1\nsbom-secret-marker: 2\n", dup)
  expect_identical(read_error(dup), "dup.yaml is not valid SPDX YAML.")
  flow <- file.path(dir, "flow.yaml")
  write_text("spdxVersion: SPDX-2.3\nname: [sbom-secret-marker, 2\n", flow)
  expect_identical(read_error(flow), "flow.yaml is not valid SPDX YAML.")
  key <- file.path(dir, "k.yaml")
  write_text("spdxVersion: SPDX-2.3\nline 4242: 1\nline 4242: 2\n", key)
  expect_identical(read_error(key), "k.yaml is not valid SPDX YAML.")
})

test_that("a warning from the YAML parser is a read error, and never escapes", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text("spdxVersion: SPDX-2.3\nname: !!bool sbom-secret-marker\n", tf)
  expect_no_warning(msg <- read_error(tf))
  expect_identical(msg, paste0(basename(tf), " is not valid SPDX YAML."))
})

test_that("a version must be numbers separated by dots", {
  tf <- withr::local_tempfile(fileext = ".json")
  bad <- function(name) paste0(basename(tf), " is not valid ", name, ": its version is not one sbom recognizes.")
  cases <- list(
    list('{"bomFormat":"CycloneDX","specVersion":"abc def"}', "CycloneDX JSON"),
    list('{"bomFormat":"CycloneDX","specVersion":"1.6 "}', "CycloneDX JSON"),
    list('{"bomFormat":"CycloneDX","specVersion":1.6}', "CycloneDX JSON"),
    list('{"bomFormat":"CycloneDX"}', "CycloneDX JSON"),
    list('{"spdxVersion":"SPDX-2.3-beta"}', "SPDX JSON"),
    list('{"@context":"https://spdx.org/rdf/3./x","@graph":[]}', "SPDX 3 JSON-LD"),
    list('<bom xmlns="http://cyclonedx.org/schema/bom/1.6/"/>', "CycloneDX XML"),
    list('<bom xmlns="http://cyclonedx.org/schema/bom/"/>', "CycloneDX XML")
  )
  for (case in cases) {
    write_text(case[[1]], tf)
    expect_identical(read_error(tf), bad(case[[2]]), label = case[[1]])
  }
  # The version comes from the spdx.org/rdf/ segment that matched, not a later one.
  write_text('{"@context":"https://example.org/spdx.org/rdf/3.0.1/a?spdx.org/rdf/zzz","@graph":[]}', tf)
  expect_identical(read_document(tf)$version, "3.0.1")
})

test_that("each file is read once, and its bytes are handed to the parser", {
  skip_if_not_installed("yaml")
  local_mocked_bindings(read_utf8_text = function(...) stop("The file was read a second time."))
  files <- c(
    tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"),
    tp("spdx-2.3", "SPDXYAMLExample-2.3.spdx.yaml"),
    tp("spdx-2.3", "SPDXTagExample-v2.3.spdx"),
    tp("spdx-3", "package_sbom.json"),
    tp("cyclonedx", "valid-bom-1.6.json")
  )
  for (path in files) {
    expect_no_error(read_document(path))
  }
})

test_that("a SoftwareIdentity outside the ISO namespace is not a SWID tag", {
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_text('<x:SoftwareIdentity xmlns:x="urn:example:x" name="x" tagId="x"/>', tf)
  expect_identical(read_error(tf), paste0(basename(tf), " is not an SBOM in a format sbom reads."))
})

test_that("the tag-value sniffer looks at the first 1,000 lines and 64 KB only", {
  tf <- withr::local_tempfile(fileext = ".spdx")
  tv <- "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n"
  write_text(paste0(strrep("#\n", 999), tv), tf)
  expect_identical(read_document(tf)$format, "spdx-tv")
  for (lead in c(strrep("#\n", 1000), paste0("#", strrep("x", 70000), "\n"))) {
    write_text(paste0(lead, tv), tf)
    expect_identical(read_error(tf), paste0(basename(tf), " is not an SBOM in a format sbom reads."))
    expect_identical(read_document(tf, format = "spdx-tv")$format, "spdx-tv")
  }
})

test_that("an escaped NUL in JSON is refused, which jsonlite would cut the string at", {
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  file <- basename(tf)
  doc <- function(name) {
    paste0('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"library","name":"', name, '"}}}')
  }
  for (name in c("a\\u0000b", "a\\\\\\u0000b", "a\\U0000b")) {
    write_text(doc(name), tf)
    expect_identical(read_error(tf), paste0(file, " is not valid JSON: it contains a NUL character."), label = name)
    res <- schema_validate(tf, "cyclonedx-json", "1.6")
    expect_identical(res$status, "fail", label = name)
    expect_identical(res$findings$message, "The file is not valid JSON: it contains a NUL character.", label = name)
  }
  # An escaped backslash before u0000 is text, not a NUL.
  write_text(doc("a\\\\u0000b"), tf)
  expect_identical(read_document(tf)$doc$metadata$component$name, "a\\u0000b")
  write_text(doc("a\\u0001b"), tf)
  expect_identical(read_document(tf)$doc$metadata$component$name, "a\u0001b")
})

test_that("a version longer than 20 characters is not one sbom recognizes", {
  skip_on_cran()
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  file <- basename(tf)
  cdx <- function(version) {
    paste0('{"bomFormat":"CycloneDX","specVersion":"', version, '","version":1}')
  }
  write_text(cdx(paste0("1.", strrep("6", 1e6))), tf)
  msg <- read_error(tf)
  expect_identical(msg, paste0(file, " is not valid CycloneDX JSON: its version is not one sbom recognizes."))
  v <- validate_sbom(tf)
  expect_identical(v$findings$message, msg)
  expect_lt(sum(nchar(utils::capture.output(print(v)))), 1000L)
  write_text(cdx(paste0("1.", strrep("6", 18))), tf)
  expect_identical(read_document(tf)$version, paste0("1.", strrep("6", 18)))
  write_text(cdx(paste0("1.", strrep("6", 19))), tf)
  expect_error(read_document(tf), class = "sbom_read_error")
  spdx <- withr::local_tempfile(fileext = ".spdx.json")
  write_text(paste0('{"spdxVersion":"SPDX-2.', strrep("3", 1e6), '","SPDXID":"SPDXRef-DOCUMENT"}'), spdx)
  expect_identical(
    read_error(spdx), paste0(basename(spdx), " is not valid SPDX JSON: its version is not one sbom recognizes.")
  )
})
