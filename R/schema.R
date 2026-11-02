schema_formats <- c("cyclonedx-json", "cyclonedx-xml", "spdx-json")
schema_versions <- list(
  `cyclonedx-json` = c("1.4", "1.5", "1.6", "1.7"),
  `cyclonedx-xml` = c("1.4", "1.5", "1.6", "1.7"),
  `spdx-json` = "2.3"
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
    return(if (format == "spdx-json") "2.3" else "1.6")
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
    `spdx-json` = file.path("spdx", "spdx-2.3.schema.json")
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

validate_xml <- function(path, version) {
  schema_path <- schema_file("cyclonedx-xml", version)
  doc <- tryCatch(
    xml2::read_xml(path),
    error = function(e) parse_failure("well-formed XML", e)
  )
  if (is.list(doc) && identical(names(doc), c("status", "findings"))) {
    return(doc)
  }
  # The XSD imports spdx.xsd by a relative schemaLocation, which libxml2
  # resolves against the XSD's own URL, not the working directory.
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

# Validates a written document against the bundled schema. Returns
# list(status = "pass" | "fail" | "skipped", findings = data.frame(location, message)).
schema_validate <- function(path, format, version = NULL) {
  version <- resolve_schema_version(format, version)
  if (!is.character(path) || length(path) != 1L || !file.exists(path)) {
    cli::cli_abort("{.arg path} must be an existing file, not {.val {path}}.")
  }
  switch(format,
    `cyclonedx-xml` = validate_xml(path, version),
    validate_json(path, format, version)
  )
}
