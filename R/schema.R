# The versions of each format sbom reads (read_formats) that the schema layer
# checks. Each has a bundled schema, except SWID: sbom does not bundle the
# ISO/IEC 19770-2:2015 schema, and checks a tag against its own structural
# rules unless the option sbom.swid_xsd names a copy of the schema.
schema_versions <- list(
  `cyclonedx-json` = c("1.4", "1.5", "1.6", "1.7"),
  `cyclonedx-xml` = c("1.4", "1.5", "1.6", "1.7"),
  `spdx-json` = c("2.2", "2.3"),
  `spdx-yaml` = c("2.2", "2.3"),
  `spdx-xml` = c("2.2", "2.3"),
  `spdx-tv` = c("2.2", "2.3"),
  `spdx3-jsonld` = "3.0.1",
  swid = "2015"
)

# Mockable, so tests can simulate a machine without jsonvalidate.
has_jsonvalidate <- function() {
  requireNamespace("jsonvalidate", quietly = TRUE)
}

resolve_schema_version <- function(format, version) {
  if (!is.character(format) || length(format) != 1L || !format %in% read_formats) {
    cli::cli_abort(
      "{.arg format} must be one of {.val {read_formats}}, not {.val {format}}."
    )
  }
  supported <- schema_versions[[format]]
  if (is.null(version)) {
    return(switch(format,
      `spdx3-jsonld` = "3.0.1",
      swid = "2015",
      if (startsWith(format, "spdx")) "2.3" else "1.6"
    ))
  }
  if (!is.character(version) || length(version) != 1L || !version %in% supported) {
    cli::cli_abort(
      "{.arg version} {.val {version}} is not supported for {.val {format}}; use one of {.val {supported}}."
    )
  }
  version
}

# Path of the bundled schema for a format and version. SWID has none.
schema_file <- function(format, version) {
  version <- resolve_schema_version(format, version)
  file <- switch(format,
    `cyclonedx-json` = file.path("cyclonedx", sprintf("bom-%s.schema.json", version)),
    `cyclonedx-xml` = file.path("cyclonedx", sprintf("bom-%s.xsd", version)),
    swid = cli::cli_abort("sbom does not bundle the SWID schema."),
    `spdx-json` = ,
    `spdx-yaml` = ,
    `spdx-xml` = ,
    `spdx-tv` = ,
    `spdx3-jsonld` = file.path("spdx", sprintf("spdx-%s.schema.json", version))
  )
  path <- system.file("schemas", file, package = "sbom")
  if (!nzchar(path)) {
    cli::cli_abort("The bundled schema {.file {file}} is missing from the installed package.")
  }
  path
}

empty_findings <- function() {
  data.frame(location = character(), message = character(), stringsAsFactors = FALSE)
}

validation_result <- function(status, findings = empty_findings()) {
  list(status = status, findings = findings)
}

# Compiled schemas are cached in `the`, keyed by format and version.
compiled_json_schema <- function(format, version) {
  key <- paste(format, version, sep = "/")
  if (is.null(the$schemas)) the$schemas <- list()
  if (is.null(the$schemas[[key]])) {
    path <- schema_file(format, version)
    # ajv resolves the sibling $ref files (spdx, jsf, cryptography) against the
    # schema's directory, but be explicit rather than trust the working
    # directory: compile from there and restore it.
    old <- setwd(dirname(path))
    on.exit(setwd(old), add = TRUE)
    # ajv warns about the unknown format "iri-reference".
    the$schemas[[key]] <- suppressWarnings(
      jsonvalidate::json_schema$new(basename(path), engine = "ajv")
    )
  }
  the$schemas[[key]]
}

# A condition's message as the end of a sentence, without its full stop.
condition_detail <- function(cnd) {
  sub("[.[:space:]]+$", "", conditionMessage(cnd))
}

# A document that cannot be parsed is a validation failure, not an error.
parse_failure <- function(what, cnd) {
  validation_result(
    "fail",
    data.frame(
      location = "",
      message = sprintf("The file is not %s: %s.", what, condition_detail(cnd)),
      stringsAsFactors = FALSE
    )
  )
}

# The keys under which the CycloneDX schemas use `"format": "iri-reference"`,
# which ajv does not check.
cdx_iri_keys <- c(
  "url", "references", "endpoints", "featuredImage", "socialImage", "source",
  "destination"
)

# Whether each string cannot be an IRI reference (RFC 3987): it holds
# whitespace, a control character, one of <>"{}|\^ or the backtick, or a %
# not followed by two hex digits. Invalid UTF-8 cannot be one either.
iri_reference_bad <- function(x) {
  bad <- !validUTF8(x)
  bad[!bad] <- grepl(
    "[\\s\\p{Z}\\p{Cc}<>\"{}|\\\\^`]|%(?![0-9A-Fa-f]{2})",
    x[!bad],
    perl = TRUE
  )
  bad
}

# The strings under an IRI-reference key of a parsed CycloneDX document: the
# key's value when it is a string, else its string items when it is an
# array. Returns a character vector named by JSON pointer.
cdx_iri_values <- function(x, pointer = "") {
  keys <- names(x)
  hits <- if (is.null(keys)) integer() else which(keys %in% cdx_iri_keys)
  nested <- which(vapply(x, is.list, logical(1)) & lengths(x) > 0L)
  if (length(hits) == 0L && length(nested) == 0L) {
    return(character())
  }
  path <- function(i) {
    step <- if (is.null(keys)) i - 1L else gsub("/", "~1", gsub("~", "~0", keys[i], fixed = TRUE), fixed = TRUE)
    paste0(pointer, "/", step)
  }
  found <- list()
  for (i in hits) {
    value <- x[[i]]
    if (is.character(value)) {
      found[[length(found) + 1L]] <- stats::setNames(value, path(i))
    } else if (is.list(value) && is.null(names(value))) {
      items <- which(vapply(value, function(v) is.character(v) && length(v) == 1L, logical(1)))
      if (length(items) == 0L) next
      found[[length(found) + 1L]] <- stats::setNames(
        unlist(value[items], use.names = FALSE),
        paste0(path(i), "/", items - 1L)
      )
    }
  }
  found <- c(found, lapply(nested, function(i) cdx_iri_values(x[[i]], path(i))))
  out <- unlist(unname(found))
  if (is.null(out)) character() else out
}

# Findings for the IRI references in a parsed CycloneDX document that ajv,
# which ignores the format, let through.
cdx_iri_findings <- function(doc) {
  # A quick look first. unlist() names each string by the keys on its path,
  # with a number appended to array items, so the last key narrows the
  # strings to those that could be under an IRI-reference key. Only when one
  # of those is bad is the document walked for exact JSON pointers.
  flat <- unlist(doc)
  if (!is.null(names(flat))) {
    leaf <- sub("[0-9]+$", "", sub("^.*[.]", "", names(flat)))
    if (!any(iri_reference_bad(as.character(flat[leaf %in% cdx_iri_keys])))) {
      return(empty_findings())
    }
  }
  values <- cdx_iri_values(doc)
  bad <- values[iri_reference_bad(values)]
  data.frame(
    location = names(bad),
    message = sprintf("%s is not a valid IRI reference.", quote_value(unname(bad))),
    stringsAsFactors = FALSE
  )
}

# The JSON text the schema validator is given: written by jsonlite from a
# parsed document, never the file's own text. jsonvalidate evaluates its
# input as JavaScript, so a file's text, which can hide code behind a comment
# that JavaScript and jsonlite end at different places, must never reach it.
json_model_text <- function(doc) {
  jsonlite::toJSON(doc, auto_unbox = TRUE, null = "null", digits = NA)
}

# What jsonvalidate is given for a parsed document. jsonvalidate evaluates
# its argument as JavaScript, so it gets only code sbom writes, around one
# string literal that jsonlite escaped:
#
# * JSON.parse("...") parses the document as JSON data. It is never run, and
#   never read as an object literal, in which a "__proto__" key would set the
#   prototype instead of reaching the schema as an ordinary property.
# * jsonvalidate builds ajv with `verbose: true`, so each error carries the
#   data and the schema at its location: a root-level error holds the whole
#   document and the whole root schema (about 260 KB for CycloneDX). Three
#   thousand stray keys in a 26 KB file made a result too long for V8, which
#   aborted R. So the code first wraps jsonvalidate's global `validator` so
#   that it keeps only each error's instancePath and message, for at most
#   json_max_errors errors, and says how many more there were. If there is no
#   such validator, the code throws, and the check reports that it could not
#   run.
#
# * V8 cannot hold a string longer than its kMaxLength, and a longer one
#   aborts R. The string literal doubles every escape of the JSON inside it,
#   so it is the literal that is measured: one longer than json_max_mb()
#   mebibytes (in characters) is an error of class `sbom_json_too_large`,
#   whose field `size` is its length in mebibytes, and V8 never sees it.
#
# The class "json" stops jsonvalidate from taking the text for a file name.
json_validator_input <- function(doc) {
  literal <- jsonlite::toJSON(as.character(json_model_text(doc)), auto_unbox = TRUE)
  size <- nchar(literal, type = "chars") / 2^20
  if (size > json_max_mb()) {
    cli::cli_abort(
      "The document is too large for V8.",
      class = "sbom_json_too_large", size = size, call = NULL
    )
  }
  structure(paste0(json_validator_wrapper, "return JSON.parse(", literal, "); })()"), class = "json")
}

# The longest string literal handed to V8, in mebibytes of characters: a
# function, so that tests can lower it.
json_max_mb <- function() 32

# A number of mebibytes for a sentence, rounded up to one decimal, so that a
# document over the limit is never shown at the limit.
json_mb_text <- function(size) {
  as.character(ceiling(size * 10) / 10)
}

json_max_errors <- 1000L

json_validator_wrapper <- paste0(
  "(function () {",
  " var g = globalThis;",
  " if (typeof g.validator !== 'function') {",
  "  throw new Error('jsonvalidate has no schema validator to call');",
  " }",
  " if (!g.validator.sbomBrief) {",
  "  var full = g.validator;",
  "  var brief = function (data) {",
  "   var ok = full(data);",
  "   if (ok) { brief.errors = null; return ok; }",
  "   var all = full.errors || [];",
  "   brief.errors = all.slice(0, ", json_max_errors, ").map(function (e) {",
  "    return {instancePath: String(e.instancePath), message: String(e.message)};",
  "   });",
  "   var more = all.length - ", json_max_errors, ";",
  "   if (more > 0) {",
  "    brief.errors.push({instancePath: '', message: more +",
  "     (more === 1 ? ' more error is not listed.' : ' more errors are not listed.')});",
  "   }",
  "   return ok;",
  "  };",
  "  brief.sbomBrief = true;",
  "  g.validator = brief;",
  " }",
  " "
)

json_max_depth <- 200L

# A problem a parsed document can have that JSON allows but that would be
# hidden on the way to the schema: an empty or repeated key, which R's names
# would rename, or nesting deeper than json_max_depth levels. Walks the
# document a level at a time, so its depth never deepens R's stack. NA when
# there is none.
json_model_problem <- function(doc) {
  level <- list(doc)
  depth <- 0L
  while (length(level) > 0L) {
    depth <- depth + 1L
    if (depth > json_max_depth) {
      return(sprintf("it nests more than %d levels deep", json_max_depth))
    }
    bad_keys <- vapply(level, function(x) {
      keys <- names(x)
      !is.null(keys) && (!all(nzchar(keys)) || anyDuplicated(keys) > 0L)
    }, logical(1))
    if (any(bad_keys)) {
      return("an object has an empty or repeated key")
    }
    level <- unlist(
      lapply(level, function(x) x[vapply(x, is.list, logical(1))]),
      recursive = FALSE, use.names = FALSE
    )
  }
  NA_character_
}

# Reads and parses a JSON file. A NUL byte, invalid UTF-8, a comment, a
# string that is never closed or any other text outside JSON values is an
# error, whatever jsonlite accepts. So is the escape \u0000, at which
# jsonlite would cut the string short. So is nesting deeper than
# json_max_depth levels, measured before parsing; that error has class
# `sbom_json_limit`.
json_read_strict <- function(path) {
  json_parse_strict(read_utf8_text(path, subject = "it"))
}

# The same, for the text of a file.
json_parse_strict <- function(txt) {
  # A backslash escapes the u when an even number of backslashes come before
  # it.
  if (grepl("(?<!\\\\)(?:\\\\\\\\)*\\\\[uU]0000", txt, perl = TRUE, useBytes = TRUE)) {
    cli::cli_abort("it contains a NUL character", call = NULL)
  }
  # JSON has no `/` or `"` outside its strings. Escapes go first and then
  # string literals, so that no single match has to span a long string,
  # which PCRE would give up on.
  outside <- gsub('"[^"]*+"', "", gsub("\\\\.", "", txt, perl = TRUE), perl = TRUE)
  if (grepl("/", outside, fixed = TRUE)) {
    cli::cli_abort("it contains comments or other text outside JSON values", call = NULL)
  }
  if (grepl('"', outside, fixed = TRUE)) {
    cli::cli_abort("it has a string that is never closed", call = NULL)
  }
  brackets <- utf8ToInt(gsub("[^][{}]", "", outside))
  depth <- max(c(0L, cumsum(ifelse(brackets == 91L | brackets == 123L, 1L, -1L))))
  if (depth > json_max_depth) {
    cli::cli_abort("it nests more than {json_max_depth} levels deep", class = "sbom_json_limit", call = NULL)
  }
  jsonlite::parse_json(txt)
}

# Parses the file first, so that only a parse error is "not valid JSON".
validate_json <- function(path, format, version) {
  doc <- tryCatch(json_read_strict(path), error = identity)
  if (inherits(doc, "sbom_json_limit")) {
    return(parse_failure("valid JSON for an SBOM", doc))
  }
  if (inherits(doc, "error")) {
    return(parse_failure("valid JSON", doc))
  }
  validate_json_model(doc, format, version)
}

# Applies the JSON schema to a parsed document. `what` names the file's
# format in a failure ("valid JSON", "valid YAML" and so on). An error from
# ajv itself means the check could not run.
validate_json_model <- function(doc, format, version, what = "valid JSON") {
  problem <- json_model_problem(doc)
  if (!is.na(problem)) {
    return(validation_result(
      "fail",
      data.frame(
        location = "",
        message = sprintf("The file is not %s for an SBOM: %s.", what, problem),
        stringsAsFactors = FALSE
      )
    ))
  }
  if (!has_jsonvalidate()) {
    return(validation_result(
      "skipped",
      data.frame(
        location = "",
        message = "jsonvalidate is not installed, so the JSON schema was not checked.",
        stringsAsFactors = FALSE
      )
    ))
  }
  # The input is built first, so that a document too large for V8 never
  # reaches it, nor even compiles the schema.
  ok <- tryCatch(
    {
      input <- json_validator_input(doc)
      suppressWarnings(compiled_json_schema(format, version)$validate(input, verbose = TRUE))
    },
    error = identity
  )
  if (inherits(ok, "sbom_json_too_large")) {
    return(validation_result(
      "skipped",
      data.frame(
        location = "",
        message = sprintf(
          "The document is too large for the JSON schema check (%s MB; the limit is %s MB), so the schema was not checked.",
          json_mb_text(ok$size), as.character(json_max_mb())
        ),
        stringsAsFactors = FALSE
      )
    ))
  }
  if (inherits(ok, "error")) {
    return(validation_result(
      "skipped",
      data.frame(
        location = "",
        message = sprintf("The JSON schema check could not run: %s.", condition_detail(ok)),
        stringsAsFactors = FALSE
      )
    ))
  }
  if (!isTRUE(ok)) {
    errs <- attr(ok, "errors")
    findings <- data.frame(
      location = as.character(errs$instancePath),
      message = as.character(errs$message),
      stringsAsFactors = FALSE
    )
    return(validation_result("fail", findings))
  }
  if (format == "cyclonedx-json") {
    findings <- cdx_iri_findings(doc)
    if (nrow(findings) > 0L) {
      return(validation_result("fail", findings))
    }
  }
  validation_result("pass")
}

has_yaml <- function() {
  requireNamespace("yaml", quietly = TRUE)
}

# Parses the YAML, unless `doc` is its model already, and applies the SPDX
# JSON schema.
validate_yaml <- function(path, version, doc = NULL) {
  if (!has_yaml()) {
    return(validation_result(
      "skipped",
      data.frame(
        location = "",
        message = "yaml is not installed, so the YAML document was not checked.",
        stringsAsFactors = FALSE
      )
    ))
  }
  if (is.null(doc)) doc <- tryCatch(spdx_yaml_read(path), error = identity)
  if (inherits(doc, "sbom_json_limit") || inherits(doc, "sbom_yaml_documents")) {
    return(parse_failure("valid YAML for an SBOM", doc))
  }
  if (inherits(doc, "error")) {
    return(parse_failure("valid YAML", doc))
  }
  validate_json_model(doc, "spdx-json", version, what = "valid YAML")
}

# SPDX has no official XML schema. Reads the XML back into the JSON model,
# unless `doc` is that model already, and applies the SPDX JSON schema; a
# pass is only "partial".
validate_spdx_xml <- function(path, version, doc = NULL) {
  if (is.null(doc)) doc <- tryCatch(spdx_xml_read(path), error = identity)
  if (inherits(doc, "sbom_spdx_xml_root")) {
    return(validation_result(
      "fail",
      data.frame(
        location = "",
        message = sprintf("The root element is <%s>, not <Document>.", doc$root),
        stringsAsFactors = FALSE
      )
    ))
  }
  if (inherits(doc, "error")) {
    return(parse_failure("well-formed XML", doc))
  }
  res <- validate_json_model(doc, "spdx-json", version, what = "well-formed XML")
  if (res$status != "pass") {
    return(res)
  }
  validation_result(
    "partial",
    data.frame(
      location = "",
      message = "SPDX has no official XML schema, so the document was checked after conversion to the JSON model.",
      stringsAsFactors = FALSE
    )
  )
}

# Tag-value has no schema either. Reads the file back into the JSON model,
# unless `doc` is that model already, and applies the SPDX JSON schema; a
# pass is only "partial".
validate_spdx_tv <- function(path, version, doc = NULL) {
  if (is.null(doc)) doc <- tryCatch(spdx_tv_read(path), error = identity)
  if (inherits(doc, "error")) {
    return(parse_failure("valid SPDX tag-value", doc))
  }
  skipped <- attr(doc, "skipped_tags", exact = TRUE)
  attr(doc, "skipped_tags") <- NULL
  res <- validate_json_model(doc, "spdx-json", version, what = "valid SPDX tag-value")
  if (res$status != "pass") {
    return(res)
  }
  message <- "Tag-value has no schema, so the document was checked after conversion to the JSON model."
  if (length(skipped) > 0L) {
    message <- paste0(
      message, " These tags were not checked: ", paste(skipped, collapse = ", "), "."
    )
  }
  validation_result(
    "partial",
    data.frame(location = "", message = message, stringsAsFactors = FALSE)
  )
}

# The SPDX 3 JSON schema checks structure and vocabularies; SPDX also defines
# SHACL rules, which are not checked, so a pass is only "partial".
validate_spdx3 <- function(path, version) {
  res <- validate_json(path, "spdx3-jsonld", version)
  if (res$status != "pass") {
    return(res)
  }
  validation_result(
    "partial",
    data.frame(
      location = "",
      message = "The SPDX 3 JSON schema was checked; SPDX's SHACL rules were not.",
      stringsAsFactors = FALSE
    )
  )
}

# Reads an XML file and parses it from its bytes: xml2 takes a string holding
# < or > for XML itself, not a path. Entities are never expanded (no NOENT),
# and nothing is fetched (NONET). Returns list(bytes, doc), where `doc` is the
# error when the file is not well-formed.
xml_parse_file <- function(path) {
  bytes <- readBin(path, "raw", n = file.size(path))
  doc <- tryCatch(xml2::read_xml(bytes, options = c("NOBLANKS", "NONET")), error = identity)
  list(bytes = bytes, doc = doc)
}

# Checks an XML file against the XSD at `schema_path`; `parsed` is the file
# as xml_parse_file() reads it. libxml2 cannot validate a document whose
# entities, declared in its DTD, are left as references, so that check is
# skipped.
validate_xml <- function(path, schema_path, parsed = xml_parse_file(path)) {
  doc <- parsed$doc
  if (inherits(doc, "error")) {
    return(parse_failure("well-formed XML", doc))
  }
  # An XSD imports its companions (spdx.xsd for CycloneDX) by a relative
  # schemaLocation, which libxml2 resolves against the XSD's own URL, not the
  # working directory.
  schema <- xml2::read_xml(schema_path, options = c("NOBLANKS", "NONET"))
  ok <- xml2::xml_validate(doc, schema)
  if (isTRUE(ok)) {
    return(validation_result("pass"))
  }
  errs <- as.character(attr(ok, "errors"))
  # libxml2's own error, which begins its message, not a value it quotes.
  internal <- any(startsWith(errs, "Internal error: xmlSchemaVDocWalk"))
  if (internal && length(grepRaw("<!ENTITY", parsed$bytes, fixed = TRUE)) > 0L) {
    return(validation_result(
      "skipped",
      data.frame(
        location = "",
        message = "The document uses entities declared in its DTD, which sbom does not expand, so the XSD check did not run.",
        stringsAsFactors = FALSE
      )
    ))
  }
  more <- length(errs) - json_max_errors
  message <- xsd_message(utils::head(errs, json_max_errors))
  if (more > 0L) {
    message <- c(message, paste0(more, if (more == 1L) " more error is not listed." else " more errors are not listed."))
  }
  validation_result(
    "fail",
    data.frame(location = rep("", length(message)), message = message, stringsAsFactors = FALSE)
  )
}

# The note of a SWID tag that follows sbom's structural rules.
swid_partial_message <- paste(
  "sbom does not bundle the ISO/IEC 19770-2:2015 schema, so the tag was checked against sbom's structural rules;",
  "set the option sbom.swid_xsd to a copy of the ISO schema to check it fully."
)

# The SHA-256 of the ISO/IEC 19770-2:2015 schema as ISO publishes it, at
# https://standards.iso.org/iso/19770/-2/2015-current/schema.xsd. The option
# sbom.swid_xsd must name a file with exactly these bytes.
swid_iso_sha256 <- "6af9d0554932102ace5c696f723c1dc4a4b1a9846908cddec67ccc0518c0e5d4"

# The two schemas that the ISO schema imports by URL, as its schemaLocation
# values name them; sbom bundles both, unmodified, under the same base names.
swid_iso_imports <- c(
  "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd",
  "http://www.w3.org/2001/xml.xsd"
)

# The note of a SWID tag checked against sbom's structural rules because the
# option sbom.swid_xsd names something other than the ISO schema.
swid_iso_note <- paste0(
  "sbom.swid_xsd is not the ISO/IEC 19770-2:2015 schema as ISO publishes it (SHA-256 ",
  swid_iso_sha256, "), so the tag was checked against sbom's structural rules."
)

# The note of a SWID tag checked against sbom's structural rules because the
# W3C schemas that sbom bundles could not be copied beside the ISO schema.
swid_imports_note <- paste(
  "The W3C schemas that the ISO/IEC 19770-2:2015 schema imports could not be copied from sbom's installation,",
  "so the tag was checked against sbom's structural rules."
)

# The option sbom.swid_xsd: NULL when it is not set; the bytes of the file it
# names when those bytes are the ISO schema; and NA for any other value. The
# file is read once, and the bytes hashed are the bytes used, so only that
# exact schema is ever compiled, even if the file changes meanwhile, and no
# schema a user or a document supplies can make libxml2 load anything: xml2's
# entity loader fetches what a schema imports by URL with download.file(),
# whatever the parser options say.
swid_xsd_option <- function() {
  path <- getOption("sbom.swid_xsd")
  if (is.null(path)) {
    return(NULL)
  }
  if (!is_string(path) || !nzchar(path)) {
    return(NA_character_)
  }
  path <- path.expand(path)
  if (!file.exists(path) || dir.exists(path)) {
    return(NA_character_)
  }
  bytes <- readBin(path, "raw", file.size(path))
  if (!identical(cli::hash_raw_sha256(bytes), swid_iso_sha256)) {
    return(NA_character_)
  }
  bytes
}

# The bundled copies of the two W3C schemas that the ISO schema imports: a
# function, so that a test can stand in for a damaged installation.
swid_w3c_files <- function() {
  system.file("schemas", "swid", basename(swid_iso_imports), package = "sbom")
}

# Calls `f` with the path of a copy of the ISO schema, written from `bytes`,
# whose two imports name the W3C schemas that sbom bundles, copied beside it,
# so that compiling it needs no network. The copy is made in a new temporary
# folder, deleted afterwards. `bytes` are the ISO schema, byte for byte, so
# each import is replaced exactly once. Returns NULL, calling nothing, when
# the W3C schemas cannot be copied: the ISO schema would not compile without
# them, and libxml2 would then follow the tag's own schema location.
swid_with_local_schema <- function(bytes, f) {
  dir <- tempfile("sbom-swid-")
  dir.create(dir)
  on.exit(unlink(dir, recursive = TRUE), add = TRUE)
  w3c <- swid_w3c_files()
  if (length(w3c) != length(swid_iso_imports) || !all(suppressWarnings(file.copy(w3c, dir)))) {
    return(NULL)
  }
  text <- rawToChar(bytes)
  for (location in swid_iso_imports) {
    text <- sub(
      paste0('schemaLocation="', location, '"'), paste0('schemaLocation="', basename(location), '"'),
      text, fixed = TRUE, useBytes = TRUE
    )
  }
  copy <- file.path(dir, "swid-2015.xsd")
  writeBin(charToRaw(text), copy)
  f(copy)
}

# A SWID tag. sbom does not bundle the ISO/IEC 19770-2:2015 schema, so the
# tag gets sbom's structural rules, and at best "partial", unless the option
# sbom.swid_xsd names the ISO schema as ISO publishes it. Then the tag is
# checked against that schema, and against the standard's rule that it has a
# tagCreator, which the schema only documents.
validate_swid <- function(path) {
  parsed <- xml_parse_file(path)
  if (inherits(parsed$doc, "error")) {
    return(parse_failure("well-formed XML", parsed$doc))
  }
  xsd <- swid_xsd_option()
  note <- if (is.null(xsd)) swid_partial_message else swid_iso_note
  if (is.raw(xsd)) {
    res <- swid_with_local_schema(xsd, function(schema) validate_xml(path, schema, parsed))
    if (!is.null(res)) {
      creator <- swid_creator_findings(parsed$doc)
      if (nrow(creator) == 0L) {
        return(res)
      }
      return(validation_result("fail", rbind(if (res$status == "fail") res$findings, creator)))
    }
    note <- swid_imports_note
  }
  findings <- swid_structure_findings(parsed$doc)
  if (nrow(findings) > 0L) {
    if (!is.null(xsd)) {
      findings <- rbind(findings, data.frame(location = "", message = note, stringsAsFactors = FALSE))
    }
    return(validation_result("fail", findings))
  }
  validation_result("partial", data.frame(location = "", message = note, stringsAsFactors = FALSE))
}

# libxml2's messages quote names and values from the document between single
# quotes, and stop at about 64 KB, inside a quote when the value is long.
# Each quoted text is quoted short, and the message as a whole is cut at
# 2,000 characters, which leaves whole the list of the elements a schema
# expects.
xsd_message <- function(errs) {
  errs <- text_utf8(errs)
  quoted <- gregexpr("'[^']*('|$)", errs)
  regmatches(errs, quoted) <- lapply(regmatches(errs, quoted), function(q) {
    closed <- endsWith(q, "'") & nchar(q) > 1L
    inner <- substr(q, 2L, nchar(q) - closed)
    paste0("'", quote_value(inner), ifelse(closed, "'", ""))
  })
  quote_value(errs, 2000L)
}

#' Validate a written document against the schema of its format
#'
#' Returns `list(status, findings)`, where `findings` is a data frame with
#' columns `location` and `message`. `status` is one of:
#'
#' * `"pass"`: the document satisfies the schema.
#' * `"fail"`: it does not, or it could not be parsed; `findings` says why.
#' * `"skipped"`: the package needed to check it is not installed, the JSON
#'   schema check could not run, the document is too large for it, an XML
#'   document uses entities declared in its DTD, which libxml2 cannot
#'   validate unexpanded.
#' * `"partial"`: the format has no official schema (SPDX XML and tag-value),
#'   so the document was read back into the SPDX JSON model and that passed;
#'   the schema covers only part of the rules (SPDX 3, whose SHACL rules are
#'   not checked); or sbom does not bundle the schema (SWID, unless the option
#'   `sbom.swid_xsd` names the ISO schema), and the tag follows sbom's
#'   structural rules. `findings` holds one note saying which.
#'
#' @param path Path of the document.
#' @param format One of the formats sbom reads (`read_formats`).
#' @param version The format version; `NULL` for the default.
#' @param doc For SPDX YAML, XML and tag-value, the document's SPDX JSON model
#'   when it has been read already, as `read_document()` reads it, so that
#'   the file is not parsed again; `NULL` to read `path`.
#' @noRd
schema_validate <- function(path, format, version = NULL, doc = NULL) {
  version <- resolve_schema_version(format, version)
  if (!is.character(path) || length(path) != 1L || !file.exists(path)) {
    cli::cli_abort("{.arg path} must be an existing file, not {.val {path}}.")
  }
  switch(format,
    `cyclonedx-xml` = validate_xml(path, schema_file(format, version)),
    swid = validate_swid(path),
    `spdx-yaml` = validate_yaml(path, version, doc),
    `spdx-xml` = validate_spdx_xml(path, version, doc),
    `spdx-tv` = validate_spdx_tv(path, version, doc),
    `spdx3-jsonld` = validate_spdx3(path, version),
    validate_json(path, format, version)
  )
}
