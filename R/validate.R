# validate_sbom() joins the two layers of validation. The schema layer
# (schema_validate()) checks a file against the bundled schema of its format;
# the content layer (content_findings()) checks the neutral tables of the file
# (document_tables()) or of an <sbom> (sbom_tables()). The result is an
# <sbom_validation>: an overall status, and one row per finding.

validation_checks <- c("schema", "content")

validation_error_on <- c("never", "error", "warning")

#' Validate an SBOM
#'
#' Checks an SBOM file against the schema of its format, and checks the
#' content of a file or of an `<sbom>` object against integrity rules and the
#' NTIA 2021 minimum elements. A file can come from sbom or from any other
#' tool, in any of the eight formats that [read_sbom()] reads.
#'
#' @details
#' `validate_sbom()` runs two layers of checks on a file.
#'
#' The **schema layer** checks the file against the schema of its format and
#' version. sbom bundles the schemas, except the ISO schema of SWID tags, so
#' validation works offline:
#'
#' * CycloneDX JSON, SPDX JSON and YAML, and SPDX 3 JSON-LD are checked with
#'   jsonvalidate, which must be installed.
#' * CycloneDX XML is checked against its XSD with xml2.
#' * SPDX has no official schema for XML or tag-value, so those files are
#'   read into the SPDX JSON model and checked against the SPDX JSON schema.
#'   At best they are `partial`.
#' * SPDX 3 is also `partial` at best, since SPDX's SHACL rules are not
#'   checked.
#' * sbom does not bundle the ISO/IEC 19770-2:2015 schema of SWID tags, since
#'   ISO's notice does not clearly allow it to be redistributed. So a SWID tag
#'   is checked against sbom's structural rules, and is `partial` at best.
#'   They are no stricter than the ISO schema: the root is `SoftwareIdentity`
#'   in the 2015 namespace, with a `name` and a `tagId`; every `Entity` has a
#'   `name` and a `role`, and every `Link` an `href` and a `rel`; the roles,
#'   `rel` and `versionScheme` are tokens, and `tagVersion` an integer. As
#'   the standard requires, an `Entity` must also have the role `tagCreator`.
#'
#'   To check a tag fully, download the ISO schema from
#'   <https://standards.iso.org/iso/19770/-2/2015-current/schema.xsd> and set
#'   the option `sbom.swid_xsd` to the path of the file. sbom accepts only
#'   that file, by its SHA-256: as ISO publishes it, with CRLF line endings,
#'   or with LF line endings, as git or an editor may leave it. It checks the
#'   tag against it with xml2, giving `pass` or `fail`, and against the rule
#'   that it has a `tagCreator`. sbom bundles the two W3C schemas that the ISO
#'   schema imports, so the check needs no network. With any other value, the
#'   option gives the structural rules, and a note that says where to
#'   download the file; the note is not an error, even when the tag fails the
#'   structural rules.
#'
#' A version with no bundled schema, such as CycloneDX 1.3, is not checked,
#' and a note names the version that has no bundled schema. Each finding of this layer has the check `schema`. It
#' is an error when the file fails its schema, and otherwise a note that says
#' what could not be checked, or why a SWID tag got the structural rules.
#'
#' The **content layer** reads the file as [read_sbom()] does, and checks the
#' values the document itself holds, not the `<sbom>` that `read_sbom()` makes.
#' So nothing `read_sbom()` leaves out can hide a problem. The integrity checks
#' always run: unique ids, relationships that name elements of the document,
#' license expressions against the bundled SPDX License List, purls, and the
#' names and versions of R packages. The profile adds its own checks. The
#' layer fails when any of its findings is an error; warnings and notes do not
#' fail it.
#'
#' When the file cannot be read, as when it is not an SBOM, the result is
#' `fail` with one finding, of check `read`, and nothing else runs.
#'
#' An `<sbom>` object gets the content checks only, on its components,
#' relationships and metadata, since it has no file to check against a schema.
#' With the default `checks` the schema layer is left out, and asking for it is
#' an error. To check both, write the object with [write_sbom()] and validate
#' the file. An `<sbom>` from [read_sbom()] holds values that `read_sbom()`
#' supplies, such as a timestamp when the document has none, a placeholder
#' root and sbom as the tool, and lacks those it cannot keep, such as CPE
#' identifiers, which may be a component's only identifier. Either changes
#' the result, so validate the file itself to check the document as it was
#' written.
#'
#' @section Statuses:
#' Each layer that runs gives a status, and the result's status joins them:
#'
#' * `"fail"`: a layer failed. The file could not be read, it fails its
#'   schema, or its content has an error.
#' * `"skipped"`: no layer failed, and every layer that ran was skipped. A
#'   schema layer is skipped when jsonvalidate is not installed, when sbom
#'   bundles no schema for the version, when the document is too large, when
#'   the JSON schema check could not run, or when an XML document uses
#'   entities declared in its DTD, which sbom does not expand.
#' * `"partial"`: no layer failed, but one was skipped or could check only
#'   part of the rules (SPDX XML, SPDX tag-value and SPDX 3, and SWID unless
#'   the option `sbom.swid_xsd` names the ISO schema).
#' * `"pass"`: every layer that ran passed.
#'
#' @section The NTIA minimum elements:
#' The `"ntia-2021"` profile checks the minimum elements of the NTIA's 2021
#' report, "The Minimum Elements For a Software Bill of Materials". A value is
#' present when it is not empty and not `NOASSERTION`. A value asserted with an
#' override counts like any other. The component checks apply to components,
#' not to files and snippets (SPDX files, and CycloneDX components of type
#' `file`). The relationships are those of the primary component, the one the
#' document describes. Each element is read from these fields:
#'
#' | Element | CycloneDX | SPDX 2 | SPDX 3 | SWID |
#' |:--|:--|:--|:--|:--|
#' | Supplier | `supplier`, `manufacturer`, `publisher` or an author | `supplier` or `originator` | `suppliedBy` or `originatedBy` | a `distributor`, `softwareCreator` or `maintainer` entity |
#' | Name | `name` | `name` | `name` | `name` |
#' | Version | `version` | `versionInfo` | `software_packageVersion` | `version` |
#' | Identifier | `purl`, `cpe` or `swid` | a purl, CPE or SWID reference | a purl, CPE or SWID identifier | `tagId` |
#' | Relationships | its `dependencies` entry, or nested components | any but `DESCRIBES` | any but `describes` | `requires` and `component` links |
#' | Author | `metadata.authors` or `metadata.manufacturer` | a `Person:` or `Organization:` creator | a person or organization in `createdBy` | the `tagCreator` entity |
#' | Timestamp | `metadata.timestamp` | `creationInfo.created` | `created` | none |
#'
#' A document that names only tools as its authors (CycloneDX tools, SPDX 2
#' `Tool:` creators, SPDX 3 software agents) gets a warning rather than an
#' error, since the NTIA asks for the person or organization that made the
#' SBOM data. For an `<sbom>` object, the elements are each component's
#' `supplier_name` or `maintainer`, `name`, `version`, `purl` and
#' relationships, and the metadata's `author` or `organization` and
#' `timestamp`; sbom itself is a tool author.
#'
#' A SWID tag describes only itself, so only the tag gets the component
#' checks, and a note counts the tags it links to. It has no field for the
#' time it was made, so **a SWID tag cannot meet the NTIA minimum elements**:
#' under `"ntia-2021"` it always fails with an `ntia-timestamp` error.
#'
#' @section Checks:
#' Each finding has one of these checks:
#'
#' * `read` (error): the file is not an SBOM in a format sbom reads.
#' * `schema`: an error where the file fails its schema; otherwise a note.
#' * `duplicate-id` (error): elements share an id.
#' * `dangling-relationship` (error): a relationship names an element the
#'   document does not define. An element of another document is not
#'   checked: one named through an SPDX `DocumentRef-` or an SPDX 3 import,
#'   or a CycloneDX BOM-Link (`urn:cdx:...`), as in a VEX document.
#' * `license-invalid` (error): a license expression is not a valid SPDX
#'   expression.
#' * `license-unknown` (error): it uses an id that is not on the SPDX License
#'   List.
#' * `license-deprecated` (warning): it uses a deprecated SPDX id.
#' * `license-ref-undefined` (error, SPDX 2 only): it uses a `LicenseRef-`
#'   that the document does not define in `hasExtractedLicensingInfos`.
#' * `purl-invalid` (error): a purl does not parse.
#' * `r-package-name` (error): a component whose purl says it is a CRAN
#'   package has a name that is not a valid R package name.
#' * `r-version` (warning): such a component has a version that is not an R
#'   package version.
#' * `r-purl-name` (warning): its purl names another package.
#' * `ntia-author`, `ntia-timestamp`, `ntia-supplier`, `ntia-name`,
#'   `ntia-version`, `ntia-identifier` and `ntia-relationships` (errors): an
#'   NTIA minimum element is missing. `ntia-author` is a warning when the
#'   document names only tools.
#' * `swid-links` (note): the tags a SWID tag links to were not checked.
#'
#' @section Limits:
#' * The JSON schema check runs ajv inside V8, and its time grows
#'   quadratically with the length of a CycloneDX component array: about 45
#'   seconds at 20,000 components. The content layer takes seconds; use
#'   `checks = "content"` to leave the schema out for a large SBOM.
#' * V8 cannot hold a very long string, and trying aborts R. A document whose
#'   JSON, escaped for V8, is longer than 32 MB is not checked against its
#'   schema: the schema layer is skipped, with a note, and the content checks
#'   still run.
#' * SPDX YAML nested more than 200 levels deep, or holding more than one YAML
#'   document, is refused before it is parsed, from a scan of its text that
#'   follows libyaml's rules. A crafted SPDX YAML file can still take tens of
#'   seconds to refuse.
#' * The JSON schema check calls the validator that jsonvalidate keeps inside
#'   V8, which is not part of jsonvalidate's documented interface. If a
#'   version of jsonvalidate changes it, the schema layer reports `skipped`,
#'   with a note, never `pass`.
#'
#' @param x For `validate_sbom()`, the path of an SBOM file, or an `<sbom>`
#'   object. For the methods, an `<sbom_validation>`.
#' @param checks The layers to run: `"schema"`, `"content"` or both. An
#'   `<sbom>` object gets the content checks only.
#' @param profile The content profile: `"ntia-2021"` checks the NTIA 2021
#'   minimum elements as well as the integrity rules, and `"none"` checks only
#'   the integrity rules.
#' @param error_on When to signal an error: `"never"` returns the result
#'   whatever it holds, `"error"` signals an error when any finding is an
#'   error, and `"warning"` when any finding is an error or a warning. The
#'   error has class `sbom_validation_error`, and its field `validation` holds
#'   the result. Use it in scripts and continuous integration.
#' @param ... Ignored.
#' @return `validate_sbom()` returns an `<sbom_validation>` object, a list:
#'
#' * `status`: `"pass"`, `"fail"`, `"partial"` or `"skipped"`.
#' * `findings`: a data frame with one row per finding and the columns
#'   `check`, `severity` (`"error"`, `"warning"` or `"info"`), `location` and
#'   `message` (a sentence). The location is a JSON pointer into the document,
#'   such as `/packages/3`, or `""` for the document as a whole. A file that is
#'   not JSON was read into a JSON model, into which the pointer points: the
#'   CycloneDX JSON model for CycloneDX XML, and the SPDX JSON model for SPDX
#'   YAML, XML and tag-value. An XSD finding (CycloneDX XML, and SWID with the
#'   option `sbom.swid_xsd`) has the location `""`, since xml2 does not say
#'   where libxml2 found the problem. A finding of sbom's structural rules for
#'   SWID has an XPath-like location, such as `/SoftwareIdentity/Entity[2]`
#'   for the second `Entity`.
#'   For an `<sbom>` object, the location is `"component <ref>"` or a metadata
#'   field.
#'   The findings are ordered by severity, the schema findings first, then by
#'   check and by location in document order.
#' * `format` and `version`: the format, as in [sbom_formats()], and its
#'   version; `NA` for an object or a file that could not be read.
#' * `file`: the file's name, without its folder; `NA` for an object.
#' * `profile`: the content profile.
#' * `checks`: the layers asked for; for an object, `"content"`.
#'
#' `print()` reports the findings for a reader, grouped by severity and check,
#' with a hint for each check, and returns `x` invisibly. It names the profile
#' only when the content layer was asked for, since no other layer applies
#' one. Control characters in the text it shows, which a hostile file could
#' use to rewrite the terminal, are shown as spaces, as they are in the
#' message of the `error_on` error. `as.data.frame()`
#' returns the findings, for scripts and for review.
#' @seealso [read_sbom()] to read an SBOM, and [write_sbom()] to write one.
#' @export
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"), system = FALSE)
#' path <- file.path(tempdir(), "sbom.cdx.xml")
#' write_sbom(x, path)
#' v <- validate_sbom(path)
#' v
#' as.data.frame(v)
#'
#' # An <sbom> object gets the content checks only.
#' validate_sbom(x)
validate_sbom <- function(x, checks = c("schema", "content"), profile = "ntia-2021",
                          error_on = c("never", "error", "warning")) {
  explicit <- !missing(checks)
  if (!is.character(checks) || length(checks) == 0L || !all(checks %in% validation_checks)) {
    cli::cli_abort("{.arg checks} must be {.val schema}, {.val content} or both.")
  }
  checks <- validation_checks[validation_checks %in% checks]
  profiles <- names(content_profiles())
  if (!is_string(profile) || !profile %in% profiles) {
    cli::cli_abort("{.arg profile} must be one of {.val {profiles}}, not {.val {profile}}.")
  }
  if (identical(error_on, validation_error_on)) {
    error_on <- "never"
  }
  if (!is_string(error_on) || !error_on %in% validation_error_on) {
    cli::cli_abort("{.arg error_on} must be one of {.val {validation_error_on}}.")
  }

  if (inherits(x, "sbom")) {
    if ("schema" %in% checks && explicit) {
      cli::cli_abort(
        "An <sbom> object has no file to check against a schema; write it with write_sbom() and validate the file."
      )
    }
    checks <- "content"
    found <- content_findings(sbom_tables(x), NA_character_, profile)
    result <- new_sbom_validation(
      validation_status(validation_content_status(found)), found,
      NA_character_, NA_character_, NA_character_, profile, checks
    )
  } else if (is_string(x) && nzchar(x)) {
    # A path that names no file is a mistake in the call, not a finding.
    if (!file.exists(x) || dir.exists(x)) {
      cli::cli_abort("{.arg x} must be the path of an existing file, not {.file {x}}.")
    }
    result <- validation_file(x, checks, profile)
  } else {
    cli::cli_abort(
      "{.arg x} must be the path of an SBOM file or an {.cls sbom} object, not {.obj_type_friendly {x}}."
    )
  }
  validation_raise(result, error_on)
  result
}

new_sbom_validation <- function(status, findings, format, version, file, profile, checks) {
  structure(
    list(
      status = status, findings = findings, format = format, version = version, file = file,
      profile = profile, checks = checks
    ),
    class = "sbom_validation"
  )
}

# The checks of the file at `path`. A read failure is the one finding, and
# nothing else runs. The file is parsed once: the schema layer checks SPDX
# YAML, XML and tag-value in the SPDX JSON model that read_document() built,
# and the content is checked first, so that any other parsed document can go
# before the schema layer parses its file again.
validation_file <- function(path, checks, profile, call = parent.frame()) {
  file <- basename(path)
  d <- tryCatch(read_document(path, call = call), sbom_read_error = identity)
  if (inherits(d, "sbom_read_error")) {
    return(new_sbom_validation(
      "fail", content_rows("read", "error", "", d$sentence),
      NA_character_, NA_character_, file, profile, checks
    ))
  }
  format <- d$format
  version <- d$version
  parts <- list()
  layers <- c(schema = NA_character_, content = NA_character_)
  if ("content" %in% checks) {
    parts$content <- content_findings(document_tables(d), format, profile, call)
    layers[["content"]] <- validation_content_status(parts$content)
  }
  model <- if (format %in% c("spdx-yaml", "spdx-xml", "spdx-tv")) d$doc
  rm(d)
  if ("schema" %in% checks) {
    schema <- validation_schema(path, format, version, model)
    parts$schema <- schema$findings
    layers[["schema"]] <- schema$status
  }
  findings <- content_bind(parts[intersect(c("schema", "content"), names(parts))])
  # By severity, the schema findings first: the content findings are already
  # in order, and a radix sort is stable.
  findings <- findings[order(match(findings$severity, content_severities), method = "radix"), , drop = FALSE]
  rownames(findings) <- NULL
  new_sbom_validation(
    validation_status(layers[!is.na(layers)]), findings, format, version, file, profile, checks
  )
}

validation_content_status <- function(findings) {
  if (any(findings$severity == "error")) "fail" else "pass"
}

# The status of the whole from those of the layers that ran.
validation_status <- function(layers) {
  if (any(layers == "fail")) {
    "fail"
  } else if (length(layers) > 0L && all(layers == "skipped")) {
    "skipped"
  } else if (any(layers %in% c("partial", "skipped"))) {
    "partial"
  } else {
    "pass"
  }
}

# The schema layer: list(status, findings). A version with no bundled schema
# is not checked. SPDX YAML, XML and tag-value have no schema of their own,
# and are checked against the SPDX JSON schema, in `model`, the SPDX JSON
# model of the file when it has been read already.
validation_schema <- function(path, format, version, model = NULL) {
  supported <- schema_versions[[format]]
  if (!version %in% supported) {
    versions <- paste0(if (length(supported) == 1L) "version " else "versions ", and_list(supported))
    message <- paste0(
      if (format %in% c("spdx-yaml", "spdx-xml", "spdx-tv")) {
        paste0("sbom checks ", read_format_name(format), " against the bundled SPDX JSON schema for ")
      } else {
        paste0("sbom bundles the ", read_format_name(format), " schema for ")
      },
      versions, ", so version ", quote_value(version), " was not checked."
    )
    return(list(status = "skipped", findings = content_rows("schema", "info", "", message)))
  }
  res <- schema_validate(path, format, version, doc = model)
  # The findings are errors when the file fails, and notes otherwise; its
  # notes are notes whatever the status.
  location <- as.character(c(res$findings$location, res$notes$location))
  message <- as.character(c(res$findings$message, res$notes$message))
  severity <- rep(c(if (res$status == "fail") "error" else "info", "info"), c(nrow(res$findings), NROW(res$notes)))
  list(
    status = res$status,
    findings = content_rows("schema", severity, location, validation_schema_sentence(location, message))
  )
}

# The schema layer's messages as sentences. ajv's lack a subject ("must have
# required property 'name'"), so they get the document's or the value's, and
# a full stop; libxml2's end in a newline. The layer's own sentences are kept
# as they are: some start with a package name, and an IRI finding with the
# value it quotes.
validation_schema_sentence <- function(location, message) {
  message <- trimws(message, whitespace = "[ \t\r\n]")
  must <- startsWith(message, "must ")
  message[must] <- paste0(ifelse(location[must] == "", "The document ", "The value "), message[must])
  open <- !grepl("[.!?]$", message)
  message[open] <- paste0(message[open], ".")
  message
}

# Signals the sbom_validation_error that `error_on` asks for, if any.
validation_raise <- function(result, error_on, call = parent.frame()) {
  severity <- result$findings$severity
  n_error <- sum(severity == "error")
  n_warning <- sum(severity == "warning")
  counted <- switch(error_on, never = 0L, error = n_error, warning = n_error + n_warning)
  if (counted == 0L) {
    return(invisible())
  }
  # The message quotes the document, which may hold control characters; the
  # result in the field keeps it as it is.
  first <- printable(
    result$findings$message[match(if (n_error > 0L) "error" else "warning", severity)]
  )
  cli::cli_abort(
    c(
      "The SBOM failed validation with {n_error} error{?s} and {n_warning} warning{?s}.",
      i = "{first}"
    ),
    class = "sbom_validation_error", validation = result, call = call
  )
}

#' @export
#' @rdname validate_sbom
print.sbom_validation <- function(x, ...) {
  f <- x$findings
  what <- if (is.na(x$file)) {
    "<sbom> object"
  } else if (is.na(x$format)) {
    x$file
  } else {
    paste0(read_format_name(x$format), " ", quote_value(x$version), ", ", x$file)
  }
  heads <- c(error = "Errors", warning = "Warnings", info = "Notes")
  marks <- c(error = "x", warning = "!", info = "i")
  cut <- FALSE
  lines <- cli::cli_fmt({
    cli::cli_text("{printable(what)}: {toupper(x$status)}")
    if ("content" %in% x$checks) {
      cli::cli_text("Profile: {x$profile}.")
    }
    if (nrow(f) == 0L) {
      cli::cli_text("No findings.")
    }
    for (severity in content_severities) {
      group <- f[f$severity == severity, , drop = FALSE]
      if (nrow(group) == 0L) next
      cli::cli_h2(heads[[severity]])
      for (check in unique(group$check)) {
        rows <- group[group$check == check, , drop = FALSE]
        n <- nrow(rows)
        shown <- printable(paste0(rows$message, validation_where(rows$location)))
        if (n == 1L) {
          cli::cli_bullets(stats::setNames("{shown}", marks[[severity]]))
        } else {
          cli::cli_bullets(stats::setNames("{check}: {n} findings", marks[[severity]]))
        }
        div <- cli::cli_div(class = "sbom-finding", theme = list(".sbom-finding" = list("margin-left" = 2)))
        if (n > 1L) {
          for (line in utils::head(shown, 3L)) {
            cli::cli_bullets(c("*" = "{line}"))
          }
          if (n > 3L) {
            cli::cli_text("{cli::symbol$ellipsis} and {n - 3L} more.")
            cut <- TRUE
          }
        }
        hint <- validation_hint(check, severity)
        if (!is.na(hint)) {
          cli::cli_bullets(c(i = "{hint}"))
        }
        cli::cli_end(div)
      }
    }
    if (cut) {
      cli::cli_text("")
      cli::cli_text("Use as.data.frame() to see every finding.")
    }
  })
  cat(lines, sep = "\n")
  invisible(x)
}

#' @export
#' @rdname validate_sbom
as.data.frame.sbom_validation <- function(x, ...) {
  out <- x$findings[c("check", "severity", "location", "message")]
  rownames(out) <- NULL
  out
}

# Where a finding is, for print(): the location in parentheses after the
# message. An object's location holds a ref, which may be long, so it is
# quoted short.
validation_where <- function(location) {
  ifelse(location == "", "", paste0(" (", quote_value(location, 200L), ")"))
}

# The hint for a check, NA for none. The schema's notes need no hint.
validation_hint <- function(check, severity) {
  hints <- c(
    check_hints(),
    read = "Check that the file is an SBOM in a format sbom reads (see sbom_formats()), written in UTF-8.",
    schema = "Correct each value at the location the schema names, or report the problem to the tool that wrote the document."
  )
  if (check == "schema" && severity != "error") {
    return(NA_character_)
  }
  hint <- hints[check]
  if (is.na(hint)) NA_character_ else unname(hint)
}

#' The neutral tables of an <sbom>
#'
#' The tables `document_tables()` gives for a document, built from an `<sbom>`
#' so that the content checks can run on it. Every row of a component is at
#' the location `"component <ref>"`, and each relationship at that of the
#' component it is from.
#'
#' @param x An `<sbom>`.
#' @return A list of `elements`, `licenses`, `purls`, `relationships` and
#'   `document`, as `document_tables()` returns them. A component of type
#'   `file` has the kind `"file"`, as files in documents do, and the others
#'   the kind `"component"`. The supplier is `supplier_name` and the
#'   originator `maintainer`, as the writers give them. The metadata's
#'   `author` is a person author and its `organization` an organization
#'   author; sbom itself is a tool author.
#' @noRd
sbom_tables <- function(x) {
  comps <- x$components
  meta <- x$metadata
  n <- nrow(comps)
  ref <- as.character(comps$ref)
  location <- tables_paste("component ", ref)
  purl <- tables_present(as.character(comps$purl))
  has_purl <- !is.na(purl)
  is_root <- comps$is_root %in% TRUE
  elements <- tables_elements(
    location = location, id = ref,
    kind = ifelse(comps$type %in% "file", "file", "component"),
    name = comps$name, version = comps$version, supplier = comps$supplier_name,
    originator = comps$maintainer, purl = purl,
    identifiers = tables_group(tables_paste("purl:", purl[has_purl]), which(has_purl), n),
    type = comps$type, scope = comps$scope, is_root = is_root,
    parent = ifelse(is.na(comps$parent_ref), NA_character_, tables_paste("component ", comps$parent_ref)),
    raw = vector("list", n)
  )
  license <- tables_present(as.character(comps$license_spdx))
  has_license <- !is.na(license)
  rel <- x$relationships
  author <- as.character(meta$author)
  organization <- as.character(meta$organization)
  timestamp <- meta$timestamp
  list(
    elements = elements,
    licenses = tables_licenses(
      location[has_license], ref[has_license], license[has_license],
      field = rep("license_spdx", sum(has_license))
    ),
    purls = tables_purls(location[has_purl], ref[has_purl], purl[has_purl]),
    relationships = tables_relationships(
      tables_paste("component ", rel$from), rel$from, rel$to, rel$field
    ),
    document = tables_document(
      timestamp = if (length(timestamp) == 1L && !is.na(timestamp)) {
        format_timestamp(timestamp)
      } else {
        NA_character_
      },
      timestamp_location = "metadata$timestamp",
      authors = tables_authors(
        name = c(author, organization, "sbom"),
        kind = c(rep("person", length(author)), rep("organization", length(organization)), "tool"),
        location = c(
          rep("metadata$author", length(author)), rep("metadata$organization", length(organization)),
          "metadata$tool_version"
        )
      ),
      tools = tables_strings(name = "sbom", version = as.character(meta$tool_version)),
      root = ref[is_root], root_location = location[is_root],
      notes = as.character(meta$notes), ids = ref
    )
  )
}
