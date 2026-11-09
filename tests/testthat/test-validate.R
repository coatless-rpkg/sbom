tp <- function(...) test_path("fixtures", "third-party", ...)

# fixture_sbom() with every NTIA minimum element present: the suppliers,
# versions and purls sbom cannot find are asserted with overrides.
described_sbom <- function(env = parent.frame()) {
  r_supplier <- "The R Foundation"
  ov <- data.frame(
    component = c(
      "R", "R", "methods", "methods", "methods", "utils", "utils", "utils",
      "localpkg", "localpkg", "srcpkg", "srcpkg", "local/srcpkg#embedded/cranpkg"
    ),
    field = c(
      "supplier_name", "purl", "supplier_name", "version", "purl", "supplier_name", "version", "purl",
      "supplier_name", "purl", "supplier_name", "purl", "supplier_name"
    ),
    value = c(
      r_supplier, "pkg:generic/r@4.1.0", r_supplier, "4.1.0", "pkg:generic/methods@4.1.0",
      r_supplier, "4.1.0", "pkg:generic/utils@4.1.0", "Alan Turing", "pkg:generic/localpkg@0.0.1",
      "Ada Lovelace", "pkg:cran/srcpkg@0.1.0", "CRAN"
    ),
    asserted_by = "Test", reason = "Fixture"
  )
  sbom_package(
    test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(env = env), author = "Test Author",
    organization = "Test Org", timestamp = as.POSIXct("2026-11-04", tz = "UTC"), overrides = ov
  )
}

# Writes `x` as `format` at its default version into a new temporary folder,
# as `name` (a fixed name, for snapshots) or srcpkg with the format's
# extension, and returns the path.
write_format <- function(x, format, name = NULL, env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  path <- file.path(dir, if (is.null(name)) paste0("srcpkg", format_registry()[[format]]$extension) else name)
  write_sbom(x, path, format = format)
  path
}

# The findings of `v` with the check `check`, with fresh row names.
only <- function(v, check) {
  f <- v$findings
  out <- f[f$check == check, , drop = FALSE]
  rownames(out) <- NULL
  out
}

findings_frame <- function(check = character(), severity = character(), location = character(),
                           message = character()) {
  data.frame(
    check = check, severity = severity, location = location, message = message,
    stringsAsFactors = FALSE
  )
}

# A CycloneDX 1.6 document with every NTIA element, whose one dependency has
# the license expression `license`.
cdx_text <- function(license = "MIT", name = "alpha") {
  doc <- list(
    bomFormat = "CycloneDX", specVersion = "1.6", version = 1L,
    metadata = list(
      timestamp = "2026-11-06T00:00:00Z",
      authors = list(list(name = "Ann Author")),
      component = list(
        type = "application", `bom-ref` = "app", name = "app", version = "1.0",
        supplier = list(name = "Acme"), purl = "pkg:generic/app@1.0"
      )
    ),
    components = list(list(
      type = "library", `bom-ref` = "pkg:cran/alpha@1.0", name = name, version = "1.0",
      supplier = list(name = "CRAN"), purl = "pkg:cran/alpha@1.0",
      licenses = list(list(expression = license))
    )),
    dependencies = list(
      list(ref = "app", dependsOn = list("pkg:cran/alpha@1.0")),
      list(ref = "pkg:cran/alpha@1.0")
    )
  )
  paste0(jsonlite::toJSON(doc, auto_unbox = TRUE), "\n")
}

local_cdx_file <- function(text, env = parent.frame()) {
  tf <- withr::local_tempfile(fileext = ".cdx.json", .local_envir = env)
  write_text(text, tf)
  tf
}

# Files ------------------------------------------------------------------------

test_that("sbom's own files, fully described, pass as their formats allow, and SWID lacks a timestamp", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  x <- described_sbom()
  expected <- c(
    `cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
    `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "fail"
  )
  reg <- format_registry()
  for (f in names(expected)) {
    path <- write_format(x, f)
    v <- validate_sbom(path)
    expect_s3_class(v, "sbom_validation")
    expect_named(v, c("status", "findings", "format", "version", "file", "profile", "checks"))
    expect_identical(v$status, expected[[f]], label = f)
    expect_identical(v$format, f)
    expect_identical(v$version, reg[[f]]$default_version)
    expect_identical(v$file, basename(path))
    expect_identical(v$profile, "ntia-2021")
    expect_identical(v$checks, c("schema", "content"))
    if (f == "swid") {
      # A SWID tag has no field for its timestamp, and describes only itself.
      # sbom does not bundle its schema, so the schema layer is partial.
      expect_identical(v$findings, findings_frame(
        check = c("ntia-timestamp", "schema", "swid-links"), severity = c("error", "info", "info"),
        location = c("", "", "/links"),
        message = c(
          "A SWID tag has no field for the time it was made, so it has no timestamp.",
          paste(
            "sbom does not bundle the ISO/IEC 19770-2:2015 schema, so the tag was checked against sbom's structural rules;",
            "set the option sbom.swid_xsd to a copy of the ISO schema to check it fully."
          ),
          "A SWID tag describes only itself, so the 6 tags it links to were not checked."
        )
      ))
    } else if (expected[[f]] == "partial") {
      # The one note says what the schema could not check.
      expect_identical(v$findings$check, "schema", label = f)
      expect_identical(v$findings$severity, "info", label = f)
    } else {
      expect_identical(v$findings, findings_frame(), label = f)
    }
  }
})

test_that("a version with no bundled schema gets a note, and the content is still checked", {
  path <- tp("cyclonedx", "valid-bom-1.3.json")
  v <- validate_sbom(path)
  expect_identical(v$format, "cyclonedx-json")
  expect_identical(v$version, "1.3")
  expect_identical(only(v, "schema"), findings_frame(
    check = "schema", severity = "info", location = "",
    message = "sbom bundles the CycloneDX JSON schema for versions 1.4, 1.5, 1.6 and 1.7, so version 1.3 was not checked."
  ))
  # The schema layer alone is skipped; the content has NTIA errors.
  expect_identical(validate_sbom(path, checks = "schema")$status, "skipped")
  expect_identical(v$status, "fail")
  expect_identical(
    unique(v$findings$check[v$findings$severity == "error"]),
    c("ntia-identifier", "ntia-relationships")
  )
})

test_that("an SPDX 2 version with no bundled schema is named as the SPDX JSON schema's", {
  dir <- withr::local_tempdir()
  as_spdx21 <- function(fixture, name) {
    src <- tp("spdx-2.3", fixture)
    txt <- readChar(src, file.size(src), useBytes = TRUE)
    path <- file.path(dir, name)
    write_text(sub("SPDX-2.3", "SPDX-2.1", txt, fixed = TRUE), path)
    path
  }
  v <- validate_sbom(as_spdx21("SPDXTagExample-v2.3.spdx", "doc.spdx"), checks = "schema")
  expect_identical(c(v$format, v$version, v$status), c("spdx-tv", "2.1", "skipped"))
  expect_identical(v$findings, findings_frame(
    check = "schema", severity = "info", location = "",
    message = "sbom checks SPDX tag-value against the bundled SPDX JSON schema for versions 2.2 and 2.3, so version 2.1 was not checked."
  ))
  # SPDX JSON has the schema itself.
  v <- validate_sbom(as_spdx21("SPDXJSONExample-v2.3.spdx.json", "doc.spdx.json"), checks = "schema")
  expect_identical(c(v$format, v$version), c("spdx-json", "2.1"))
  expect_identical(
    v$findings$message,
    "sbom bundles the SPDX JSON schema for versions 2.2 and 2.3, so version 2.1 was not checked."
  )
})

test_that("a file that fails its schema fails with schema findings, written as sentences", {
  skip_if_not_installed("jsonvalidate")
  v <- validate_sbom(tp("cyclonedx", "invalid-component-type-1.6.json"))
  expect_identical(v$status, "fail")
  expect_identical(only(v, "schema"), findings_frame(
    check = "schema", severity = "error", location = "/components/0/type",
    message = "The value must be equal to one of the allowed values."
  ))
  # The schema findings come first among the errors.
  expect_identical(v$findings$check[1], "schema")
  # An error at the root is the document's.
  tf <- local_cdx_file('{"bomFormat":"CycloneDX","specVersion":"1.6","zz":1}\n')
  expect_identical(only(validate_sbom(tf), "schema"), findings_frame(
    check = "schema", severity = "error", location = "",
    message = "The document must NOT have additional properties."
  ))
})

test_that("a file that is not an SBOM fails with one read finding, never an R error", {
  dir <- withr::local_tempdir()
  empty <- file.path(dir, "empty.json")
  write_text("", empty)
  utf16 <- file.path(dir, "utf16.json")
  # write_text() writes only UTF-8, so these bytes are written directly.
  writeBin(as.raw(c(0xff, 0xfe, 0x7b, 0x00, 0x7d, 0x00)), utf16)
  lock <- test_path("fixtures", "renv", "modern", "renv.lock")
  sentences <- c(
    "empty.json is not an SBOM in a format sbom reads.",
    "renv.lock is not an SBOM in a format sbom reads.",
    "utf16.json is UTF-16 text; sbom reads SBOMs written in UTF-8."
  )
  paths <- c(empty, lock, utf16)
  for (i in seq_along(paths)) {
    expect_no_error(v <- validate_sbom(paths[i]))
    expect_identical(v$status, "fail")
    expect_identical(v$findings, findings_frame(
      check = "read", severity = "error", location = "", message = sentences[i]
    ))
    expect_identical(v$file, basename(paths[i]))
    expect_identical(v$format, NA_character_)
    expect_identical(v$version, NA_character_)
  }
  # A path that names no file is a mistake in the call, not a finding.
  expect_error(validate_sbom(file.path(dir, "missing.json")), "existing file")
  expect_error(validate_sbom(dir), "existing file")
})

test_that("without jsonvalidate the JSON schema is skipped, so a passing file is partial", {
  local_mocked_bindings(has_jsonvalidate = function() FALSE)
  v <- validate_sbom(write_format(described_sbom(), "cyclonedx-json"))
  expect_identical(v$status, "partial")
  expect_identical(v$findings, findings_frame(
    check = "schema", severity = "info", location = "",
    message = "jsonvalidate is not installed, so the JSON schema was not checked."
  ))
})

test_that("a document too large for V8 skips the schema, and the content is still checked", {
  local_mocked_bindings(
    has_jsonvalidate = function() TRUE,
    compiled_json_schema = function(format, version) stop("V8 must not be called."),
    json_max_mb = function() 0.001
  )
  v <- validate_sbom(write_format(fixture_sbom(), "cyclonedx-json"))
  schema <- only(v, "schema")
  expect_identical(schema[c("check", "severity", "location")], findings_frame(
    check = "schema", severity = "info", location = "", message = character(1)
  )[c("check", "severity", "location")])
  expect_match(schema$message, paste0(
    "^The document is too large for the JSON schema check \\([0-9]+(\\.[0-9])? MB; ",
    "the limit is 0\\.001 MB\\), so the schema was not checked\\.$"
  ))
  expect_identical(v$status, "fail")
  expect_true(any(startsWith(v$findings$check, "ntia-")))
})

test_that("checks = \"content\" leaves out the schema, and profile = \"none\" the NTIA checks", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  path <- write_format(described_sbom(), "spdx-xml")
  expect_identical(validate_sbom(path)$status, "partial")
  v <- validate_sbom(path, checks = "content")
  expect_identical(v$status, "pass")
  expect_identical(v$checks, "content")
  expect_identical(v$findings, findings_frame())
  v <- validate_sbom(path, checks = "schema")
  expect_identical(v$status, "partial")
  expect_identical(unique(v$findings$check), "schema")

  v <- validate_sbom(tp("cyclonedx", "valid-bom-1.3.json"), profile = "none")
  expect_false(any(startsWith(v$findings$check, "ntia-")))
  expect_identical(v$profile, "none")
  # The schema is skipped and the content passes.
  expect_identical(v$status, "partial")
})

test_that("the arguments are checked", {
  path <- tp("cyclonedx", "valid-bom-1.3.json")
  expect_error(validate_sbom(1), "path of an SBOM file")
  expect_error(validate_sbom(c(path, path)), "path of an SBOM file")
  expect_error(validate_sbom(path, checks = "everything"), "checks")
  expect_error(validate_sbom(path, checks = character()), "checks")
  expect_error(validate_sbom(path, profile = "cisa"), "profile")
  expect_error(validate_sbom(path, error_on = "always"), "error_on")
})

# Objects ----------------------------------------------------------------------

test_that("an <sbom> object gets the content checks only", {
  skip_on_cran()
  x <- fixture_sbom()
  v <- validate_sbom(x)
  expect_s3_class(v, "sbom_validation")
  expect_identical(v$file, NA_character_)
  expect_identical(v$format, NA_character_)
  expect_identical(v$version, NA_character_)
  expect_identical(v$checks, "content")
  expect_false("schema" %in% v$findings$check)
  expect_identical(v$findings, content_findings(sbom_tables(x), NA_character_))
  expect_true(all(v$findings$location %in% c("", paste("component", x$components$ref))))
  # R, its base packages and the local packages have no purl.
  expect_identical(v$status, "fail")
  expect_identical(validate_sbom(x, checks = "content")$status, "fail")
  msg <- "An <sbom> object has no file to check against a schema; write it with write_sbom() and validate the file."
  expect_error(validate_sbom(x, checks = "schema"), msg, fixed = TRUE)
  expect_error(validate_sbom(x, checks = c("schema", "content")), "has no file", fixed = TRUE)
  # Fully described, it passes.
  v <- validate_sbom(described_sbom())
  expect_identical(v$status, "pass")
  expect_identical(v$findings, findings_frame())
})

test_that("an <sbom>'s overrides count: an asserted supplier is present", {
  x <- fixture_sbom()
  expect_true("component R" %in% only(validate_sbom(x), "ntia-supplier")$location)
  ov <- data.frame(
    component = "R", field = "supplier_name", value = "The R Foundation",
    asserted_by = "Test", reason = "Fixture"
  )
  y <- sbom_package(
    test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), author = "Test Author",
    organization = "Test Org", timestamp = as.POSIXct("2026-11-04", tz = "UTC"), overrides = ov
  )
  expect_false("component R" %in% only(validate_sbom(y), "ntia-supplier")$location)
})

test_that("sbom_tables() gives document_tables()-shaped tables of an <sbom>", {
  x <- fixture_sbom()
  t <- sbom_tables(x)
  d <- document_tables(read_document(write_format(x, "cyclonedx-json")))
  expect_named(t, names(d))
  for (tab in c("elements", "licenses", "purls", "relationships")) {
    expect_named(t[[tab]], names(d[[tab]]))
  }
  expect_named(t$document, names(d$document))
  comps <- x$components
  expect_identical(t$elements$location, paste("component", comps$ref))
  expect_identical(t$elements$id, comps$ref)
  expect_identical(t$elements$supplier, comps$supplier_name)
  expect_identical(t$elements$originator, comps$maintainer)
  expect_identical(t$elements$is_root, comps$is_root)
  has_purl <- !is.na(comps$purl)
  expect_identical(t$elements$identifiers[has_purl], as.list(paste0("purl:", comps$purl[has_purl])))
  expect_identical(lengths(t$elements$identifiers[!has_purl]), rep(0L, sum(!has_purl)))
  expect_identical(t$purls$purl, comps$purl[has_purl])
  expect_identical(t$licenses$expression, comps$license_spdx[!is.na(comps$license_spdx)])
  expect_identical(t$relationships$from, x$relationships$from)
  expect_identical(t$relationships$to, x$relationships$to)
  expect_identical(t$relationships$location, paste("component", x$relationships$from))
  # The metadata's author is a person and its organization an organization;
  # sbom itself is a tool.
  expect_identical(t$document$authors, data.frame(
    name = c("Test Author", "Test Org", "sbom"), kind = c("person", "organization", "tool"),
    location = c("metadata$author", "metadata$organization", "metadata$tool_version"),
    stringsAsFactors = FALSE
  ))
  expect_identical(t$document$timestamp, "2026-11-04T00:00:00Z")
  expect_identical(t$document$root, "local/srcpkg")
  expect_identical(t$document$ids, comps$ref)
})

test_that("an <sbom>'s file components are files, which get no NTIA component checks", {
  x <- sbom_shiny(test_path("fixtures", "rsconnect"), system = FALSE)
  t <- sbom_tables(x)
  is_file <- x$components$type %in% "file"
  expect_true(any(is_file))
  expect_identical(t$elements$kind, ifelse(is_file, "file", "component"))
  f <- validate_sbom(x)$findings
  expect_false(any(startsWith(f$check, "ntia-") & f$location %in% t$elements$location[is_file]))
})

test_that("an <sbom> that names no author names only sbom, the tool", {
  withr::local_options(sbom.author = NULL, sbom.organization = NULL, sbom.regid = NULL)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), system = FALSE, lib = fixture_lib())
  expect_identical(only(validate_sbom(x), "ntia-author"), findings_frame(
    check = "ntia-author", severity = "warning", location = "metadata$tool_version",
    message = "The document names only a tool (sbom) as its author; NTIA asks for the person or organization that made the SBOM data."
  ))
})

# error_on ---------------------------------------------------------------------

test_that("error_on = \"error\" turns an error finding into an R error that carries the result", {
  path <- write_format(described_sbom(), "swid")
  cnd <- expect_error(validate_sbom(path, error_on = "error"), class = "sbom_validation_error")
  expect_s3_class(cnd$validation, "sbom_validation")
  expect_identical(cnd$validation$status, "fail")
  expect_identical(cnd$validation$file, basename(path))
  local_plain_cli()
  expect_identical(
    cli::ansi_strip(conditionMessage(cnd)),
    paste0(
      "The SBOM failed validation with 1 error and 0 warnings.\n",
      "i A SWID tag has no field for the time it was made, so it has no timestamp."
    )
  )
  # A read failure is an error too.
  tf <- withr::local_tempfile(fileext = ".json")
  write_text("", tf)
  expect_error(validate_sbom(tf, error_on = "error"), class = "sbom_validation_error")
})

test_that("error_on = \"warning\" also turns a warning into an R error", {
  path <- local_cdx_file(cdx_text(license = "GPL-2.0"))
  v <- validate_sbom(path, error_on = "error")
  expect_identical(v$findings$check[v$findings$severity != "info"], "license-deprecated")
  cnd <- expect_error(validate_sbom(path, error_on = "warning"), class = "sbom_validation_error")
  expect_identical(cnd$validation, v)
  local_plain_cli()
  expect_identical(
    cli::ansi_strip(conditionMessage(cnd)),
    paste0(
      "The SBOM failed validation with 0 errors and 1 warning.\n",
      "i The license expression GPL-2.0 uses the deprecated SPDX license id GPL-2.0."
    )
  )
  expect_no_error(validate_sbom(local_cdx_file(cdx_text()), error_on = "warning"))
})

test_that("error_on = \"never\", the default, never errors", {
  path <- write_format(described_sbom(), "swid")
  expect_no_error(v <- validate_sbom(path))
  expect_identical(v$status, "fail")
  expect_identical(validate_sbom(path, error_on = "never"), v)
})

test_that("the error_on message never carries a control character from the file", {
  local_plain_cli()
  path <- local_cdx_file(cdx_text(name = "alp\u001b[31m\u009bha"))
  cnd <- expect_error(validate_sbom(path, error_on = "error"), class = "sbom_validation_error")
  # The finding quotes the name with its control characters as spaces.
  raw <- only(cnd$validation, "r-package-name")$message
  expect_identical(raw, "alp [31m ha is not a valid R package name, although its purl says it is a CRAN package.")
  msg <- conditionMessage(cnd)
  expect_false(grepl("\033", msg, fixed = TRUE))
  expect_false(grepl("\u009b", msg, fixed = TRUE))
  expect_match(msg, "i alp [31m ha is not a valid R package name", fixed = TRUE)
})

# Output -----------------------------------------------------------------------

test_that("as.data.frame() gives the findings in four columns, without row names", {
  v <- validate_sbom(fixture_sbom())
  df <- as.data.frame(v)
  expect_identical(names(df), c("check", "severity", "location", "message"))
  expect_identical(df, v$findings)
  expect_identical(.row_names_info(df), -nrow(df))
  expect_identical(nrow(as.data.frame(validate_sbom(described_sbom()))), 0L)
})

test_that("print() reports the findings by severity and check, with hints", {
  skip_if_not_installed("jsonvalidate")
  local_plain_cli()
  v <- validate_sbom(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  expect_snapshot(print(v))
  utils::capture.output(res <- withVisible(print(v)))
  expect_false(res$visible)
  expect_identical(res$value, v)
  # A passing file.
  expect_snapshot(print(validate_sbom(write_format(described_sbom(), "cyclonedx-json", "srcpkg.cdx.json"))))
  # An object with more findings of one check than are shown.
  expect_snapshot(print(validate_sbom(fixture_sbom())))
})

test_that("print() shows a read failure, and never prints a control character from the file", {
  local_plain_cli()
  dir <- withr::local_tempdir()
  path <- file.path(dir, "notes.json")
  write_text('{"name":"x"}', path)
  expect_snapshot(print(validate_sbom(path)))
  path <- local_cdx_file(cdx_text(name = "alp\033[2Jha"))
  v <- validate_sbom(path, checks = "content")
  expect_false(any(grepl("\033", v$findings$message, fixed = TRUE)))
  out <- utils::capture.output(print(v))
  expect_false(any(grepl("[\001-\037]", out)))
})

test_that("braces from the file print as they are, in print() and in the error_on message", {
  local_plain_cli()
  odd <- "{.emph x} {nope} }{"
  v <- new_sbom_validation(
    "fail",
    findings_frame(
      check = c("ntia-supplier", "ntia-supplier", "ntia-version"), severity = "error",
      location = c("/a/{nope}", "/b/}{", "/c/{.emph x}"),
      message = c(paste("One", odd, "has no supplier."), paste("Two", odd, "has no supplier."), paste(odd, "has no version."))
    ),
    "cyclonedx-json", "1.6", "{nope}}{.cdx.json", "ntia-2021", c("schema", "content")
  )
  expect_snapshot(print(v))
  out <- paste(utils::capture.output(print(v)), collapse = "\n")
  for (text in c("{nope}}{.cdx.json: FAIL", paste("One", odd), paste("Two", odd), "(/a/{nope})", "(/b/}{)", "(/c/{.emph x})")) {
    expect_true(grepl(text, out, fixed = TRUE), label = text)
  }
  # A real file, named with braces, whose component's name holds them.
  path <- file.path(withr::local_tempdir(), "{nope}}{.cdx.json")
  write_text(cdx_text(name = "{.emph x}{nope}}{"), path)
  out <- paste(utils::capture.output(print(validate_sbom(path, checks = "content"))), collapse = "\n")
  expect_true(grepl("{nope}}{.cdx.json: FAIL", out, fixed = TRUE))
  expect_true(grepl("x {.emph x}{nope}}{ is not a valid R package name", out, fixed = TRUE))
  cnd <- expect_error(validate_sbom(path, error_on = "error"), class = "sbom_validation_error")
  expect_match(
    gsub("[ \n]+", " ", conditionMessage(cnd)),
    "i {.emph x}{nope}}{ is not a valid R package name, although its purl says it is a CRAN package.",
    fixed = TRUE
  )
})

test_that("a 1 MB name, id, purl or license expression gives short messages, and print() stays small", {
  skip_on_cran()
  local_plain_cli()
  big <- strrep("x", 1e6)
  doc <- jsonlite::fromJSON(cdx_text(name = big), simplifyVector = FALSE)
  # Another component, with a 1 MB license expression that does not parse
  # and uses an unknown id, a 1 MB purl, and a 1 MB id it shares with a third.
  doc$components[[2]] <- list(
    type = "library", `bom-ref` = big, name = "beta", version = "1.0", supplier = list(name = "CRAN"),
    purl = paste0("pkg:cran/beta@1.0?", big), licenses = list(list(expression = paste("MIT AND", big, "AND (")))
  )
  doc$components[[3]] <- list(
    type = "library", `bom-ref` = big, name = "gamma", version = "1.0", supplier = list(name = "CRAN"),
    purl = "pkg:cran/gamma@1.0", licenses = list(list(expression = paste(big, "OR", paste0(big, "!"))))
  )
  doc$dependencies[[3]] <- list(ref = "app", dependsOn = list(paste0("ghost", big)))
  path <- local_cdx_file(jsonlite::toJSON(doc, auto_unbox = TRUE))
  v <- validate_sbom(path, checks = "content")
  expect_setequal(
    unique(v$findings$check),
    c("duplicate-id", "dangling-relationship", "license-invalid", "purl-invalid", "r-purl-name")
  )
  expect_lt(max(nchar(v$findings$message)), 300L)
  expect_identical(
    only(v, "r-purl-name")$message,
    paste0("The purl pkg:cran/alpha@1.0 names alpha, not ", strrep("x", 79), "\u2026.")
  )
  expect_lt(sum(nchar(utils::capture.output(print(v)))), 5000L)
  # The license expression that parses uses an unknown id, quoted short.
  doc$components[[3]]$licenses[[1]]$expression <- paste(big, "OR MIT")
  v <- validate_sbom(local_cdx_file(jsonlite::toJSON(doc, auto_unbox = TRUE)), checks = "content")
  unknown <- only(v, "license-unknown")$message
  expect_identical(
    unknown,
    paste0(
      "The license expression ", strrep("x", 79), "\u2026 uses ", strrep("x", 79), "\u2026, which is not on the SPDX License List ",
      spdx_license_list_version(), "."
    )
  )
  # read_sbom()'s issues quote the shared id short too.
  x <- read_sbom(path)
  expect_lt(max(nchar(x$issues$message)), 300L)
})

test_that("a license expression with thousands of unknown ids names at most 20 of them", {
  ids <- sprintf("Unknown%d", 1:5000)
  path <- local_cdx_file(cdx_text(license = paste(ids, collapse = " AND ")))
  msg <- only(validate_sbom(path, checks = "content"), "license-unknown")$message
  expect_lt(nchar(msg), 600L)
  expect_match(msg, "uses Unknown1, Unknown2, ", fixed = TRUE)
  expect_match(msg, "Unknown20, and 4980 more, which are not on the SPDX License List", fixed = TRUE)
})

test_that("validate_sbom() parses an SPDX YAML, XML or tag-value file once", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  x <- described_sbom()
  calls <- new.env(parent = emptyenv())
  calls$n <- 0L
  real <- spdx_tv_parse
  local_mocked_bindings(spdx_tv_parse = function(txt) {
    calls$n <- calls$n + 1L
    real(txt)
  })
  v <- validate_sbom(write_format(x, "spdx-tv"))
  expect_identical(calls$n, 1L)
  expect_identical(v$status, "partial")
  # The schema layer reads no YAML or XML file again either.
  local_mocked_bindings(
    spdx_yaml_read = function(path) stop("The file was parsed again."),
    spdx_xml_read = function(path) stop("The file was parsed again.")
  )
  expect_identical(validate_sbom(write_format(x, "spdx-yaml"))$status, "pass")
  expect_identical(validate_sbom(write_format(x, "spdx-xml"))$status, "partial")
  # schema_validate() still reads a path for its other callers.
  expect_identical(schema_validate(write_format(x, "spdx-tv"), "spdx-tv")$status, "partial")
  expect_identical(calls$n, 2L)
})
