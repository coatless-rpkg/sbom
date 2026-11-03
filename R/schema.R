schema_formats <- c(
  "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml",
  "spdx-tv", "spdx3-jsonld", "swid"
)
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
  if (!is.character(format) || length(format) != 1L || !format %in% schema_formats) {
    cli::cli_abort(
      "{.arg format} must be one of {.val {schema_formats}}, not {.val {format}}."
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

# Path of the bundled schema for a format and version.
schema_file <- function(format, version) {
  version <- resolve_schema_version(format, version)
  file <- switch(format,
    `cyclonedx-json` = file.path("cyclonedx", sprintf("bom-%s.schema.json", version)),
    `cyclonedx-xml` = file.path("cyclonedx", sprintf("bom-%s.xsd", version)),
    swid = file.path("swid", sprintf("swid-%s.xsd", version)),
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

# A document that cannot be parsed is a validation failure, not an error.
parse_failure <- function(what, cnd) {
  detail <- sub("[.[:space:]]+$", "", conditionMessage(cnd))
  validation_result(
    "fail",
    data.frame(
      location = "",
      message = sprintf("The file is not %s: %s.", what, detail),
      stringsAsFactors = FALSE
    )
  )
}

validate_json <- function(path, format, version) {
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
  schema <- compiled_json_schema(format, version)
  ok <- tryCatch(
    suppressWarnings(schema$validate(path, verbose = TRUE)),
    error = function(e) parse_failure("valid JSON", e)
  )
  if (is.list(ok) && identical(names(ok), c("status", "findings"))) {
    return(ok)
  }
  if (isTRUE(ok)) {
    return(validation_result("pass"))
  }
  errs <- attr(ok, "errors")
  findings <- data.frame(
    location = as.character(errs$instancePath),
    message = as.character(errs$message),
    stringsAsFactors = FALSE
  )
  validation_result("fail", findings)
}

has_yaml <- function() {
  requireNamespace("yaml", quietly = TRUE)
}

# Parses the YAML, writes it as JSON and applies the SPDX JSON schema.
validate_yaml <- function(path, version) {
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
  doc <- tryCatch(
    spdx_yaml_read(path),
    error = function(e) parse_failure("valid YAML", e)
  )
  if (is.list(doc) && identical(names(doc), c("status", "findings"))) {
    return(doc)
  }
  json <- tempfile(fileext = ".json")
  on.exit(unlink(json), add = TRUE)
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE, null = "null"), json)
  validate_json(json, "spdx-json", version)
}

# SPDX has no official XML schema. Reads the XML back into the JSON model and
# applies the SPDX JSON schema; a pass is only "partial".
validate_spdx_xml <- function(path, version) {
  doc <- tryCatch(
    xml2::read_xml(readBin(path, "raw", n = file.size(path))),
    error = function(e) parse_failure("well-formed XML", e)
  )
  if (is.list(doc) && identical(names(doc), c("status", "findings"))) {
    return(doc)
  }
  root <- xml2::xml_name(xml2::xml_root(doc))
  if (root != "Document") {
    return(validation_result(
      "fail",
      data.frame(
        location = "",
        message = sprintf("The root element is <%s>, not <Document>.", root),
        stringsAsFactors = FALSE
      )
    ))
  }
  doc <- spdx_xml_node(xml2::xml_root(doc))
  json <- tempfile(fileext = ".json")
  on.exit(unlink(json), add = TRUE)
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE, null = "null"), json)
  res <- validate_json(json, "spdx-json", version)
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

# Tag-value has no schema either. Reads the file back into the JSON model and
# applies the SPDX JSON schema; a pass is only "partial".
validate_spdx_tv <- function(path, version) {
  doc <- tryCatch(
    spdx_tv_read(path),
    error = function(e) parse_failure("valid SPDX tag-value", e)
  )
  if (is.list(doc) && identical(names(doc), c("status", "findings"))) {
    return(doc)
  }
  json <- tempfile(fileext = ".json")
  on.exit(unlink(json), add = TRUE)
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE, null = "null"), json)
  res <- validate_json(json, "spdx-json", version)
  if (res$status != "pass") {
    return(res)
  }
  validation_result(
    "partial",
    data.frame(
      location = "",
      message = "Tag-value has no schema, so the document was checked after conversion to the JSON model.",
      stringsAsFactors = FALSE
    )
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

validate_xml <- function(path, format, version) {
  schema_path <- schema_file(format, version)
  doc <- tryCatch(
    xml2::read_xml(path),
    error = function(e) parse_failure("well-formed XML", e)
  )
  if (is.list(doc) && identical(names(doc), c("status", "findings"))) {
    return(doc)
  }
  # The XSDs import their companions (spdx.xsd, xmldsig-core-schema.xsd,
  # xml.xsd) by a relative schemaLocation, which libxml2 resolves against the
  # XSD's own URL, not the working directory.
  schema <- xml2::read_xml(schema_path)
  ok <- xml2::xml_validate(doc, schema)
  if (isTRUE(ok)) {
    return(validation_result("pass"))
  }
  errs <- attr(ok, "errors")
  location <- ifelse(
    grepl("^[^ :]*:[0-9]+: ", errs),
    sub("^[^ :]*:([0-9]+): .*$", "\\1", errs),
    ""
  )
  message <- sub("^[^ :]*:[0-9]+: ", "", errs)
  validation_result(
    "fail",
    data.frame(location = location, message = message, stringsAsFactors = FALSE)
  )
}

#' Validate a written document against the bundled schema
#'
#' Returns `list(status, findings)`, where `findings` is a data frame with
#' columns `location` and `message`. `status` is one of:
#'
#' * `"pass"`: the document satisfies the schema.
#' * `"fail"`: it does not, or it could not be parsed; `findings` says why.
#' * `"skipped"`: the package needed to check it is not installed.
#' * `"partial"`: the format has no official schema (SPDX XML and tag-value),
#'   so the document was read back into the SPDX JSON model and that passed;
#'   or the schema covers only part of the rules (SPDX 3, whose SHACL rules are
#'   not checked). `findings` holds one note saying which.
#'
#' @param path Path of the document.
#' @param format One of the formats with a bundled schema.
#' @param version The format version; `NULL` for the default.
#' @noRd
schema_validate <- function(path, format, version = NULL) {
  version <- resolve_schema_version(format, version)
  if (!is.character(path) || length(path) != 1L || !file.exists(path)) {
    cli::cli_abort("{.arg path} must be an existing file, not {.val {path}}.")
  }
  switch(format,
    `cyclonedx-xml` = ,
    swid = validate_xml(path, format, version),
    `spdx-yaml` = validate_yaml(path, version),
    `spdx-xml` = validate_spdx_xml(path, version),
    `spdx-tv` = validate_spdx_tv(path, version),
    `spdx3-jsonld` = validate_spdx3(path, version),
    validate_json(path, format, version)
  )
}
