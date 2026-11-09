# Reading SPDX 2 documents written as YAML, XML or tag-value: the typing of
# values they share, and the XML reader. YAML is read in read-spdx-yaml.R and
# tag-value in read-spdx-tv.R.

# Property names whose JSON type is array, integer or boolean in the SPDX 2.2
# or 2.3 JSON schema (the union of the two). Neither XML nor YAML says what
# type a value is, so their readers type each value by its key. A test
# recomputes these from the bundled schemas.
spdx_json_arrays <- c(
  "annotations", "artifactOfs", "attributionTexts", "checksums", "creators",
  "crossRefs", "documentDescribes", "externalDocumentRefs", "externalRefs",
  "fileContributors", "fileDependencies", "fileTypes", "files",
  "hasExtractedLicensingInfos", "hasFiles", "licenseInfoFromFiles",
  "licenseInfoInFiles", "licenseInfoInSnippets",
  "packageVerificationCodeExcludedFiles", "packages", "ranges",
  "relationships", "revieweds", "seeAlsos", "snippets"
)
spdx_json_integers <- c("lineNumber", "offset", "order")
spdx_json_booleans <- c("filesAnalyzed", "isLive", "isValid", "isWayBackLink")

# A file's bytes as UTF-8 text, whatever the native locale, without a UTF-8
# byte-order mark. A NUL byte or invalid UTF-8 is an error that quotes
# nothing from the file; `subject` begins its message.
read_utf8_text <- function(path, subject = "the file") {
  utf8_text(readBin(path, "raw", n = file.size(path)), subject)
}

# The same, for bytes already read.
utf8_text <- function(bytes, subject = "the file") {
  if (any(bytes == as.raw(0L))) {
    cli::cli_abort("{subject} contains a NUL byte", call = NULL)
  }
  if (length(bytes) >= 3L && identical(bytes[1:3], as.raw(c(0xef, 0xbb, 0xbf)))) {
    bytes <- bytes[-(1:3)]
  }
  txt <- rawToChar(bytes)
  Encoding(txt) <- "UTF-8"
  if (!validUTF8(txt)) {
    cli::cli_abort("{subject} is not valid UTF-8", call = NULL)
  }
  txt
}

# The value of a decimal integer literal: an integer, or a double when it is
# beyond the 32-bit range, as JSON allows. NA when `text` is not one.
spdx_integer_value <- function(text) {
  if (!grepl("^[[:space:]]*[+-]?[0-9]+[[:space:]]*$", text)) {
    return(NA)
  }
  int <- suppressWarnings(as.integer(text))
  if (is.na(int)) as.numeric(text) else int
}

# Types the text of a scalar under `key`: a decimal integer under an integer
# key becomes a number, and "true" or "false" under a boolean key a logical.
# Anything else keeps its text, for the schema to reject.
spdx_typed_value <- function(value, key) {
  if (!is.character(value) || length(value) != 1L) {
    return(value)
  }
  if (key %in% spdx_json_integers) {
    number <- spdx_integer_value(value)
    if (!is.na(number)) {
      return(number)
    }
  } else if (key %in% spdx_json_booleans) {
    text <- trimws(value)
    if (text == "true") {
      return(TRUE)
    }
    if (text == "false") {
      return(FALSE)
    }
  }
  value
}

# The namespace of an SPDX XML document's root, which may be none, as the
# map and prefixes xml_kids_in() takes.
spdx_xml_ctx <- function(root) {
  ns <- xml_ns_map(root)
  uri <- xml2::xml_find_chr(root, "string(namespace-uri(.))")
  list(ns = ns, prefixes = if (nzchar(uri)) names(ns)[ns == uri] else character())
}

# Converts an element of an SPDX XML document. Only elements in the root's
# namespace are read; any other element is left out, with everything inside
# it, and its text is not part of its parent's.
spdx_xml_node <- function(node, ctx = spdx_xml_ctx(node)) {
  kids <- xml_kids_in(node, ctx$ns, ctx$prefixes)
  if (length(kids) == 0L) {
    return(xml_own_text(node))
  }
  tags <- names(kids)
  out <- list()
  for (key in unique(tags)) {
    values <- lapply(unname(kids[tags == key]), function(kid) {
      spdx_typed_value(spdx_xml_node(kid, ctx), key)
    })
    out[[key]] <- if (key %in% spdx_json_arrays || length(values) > 1L) {
      values
    } else {
      values[[1L]]
    }
  }
  out
}

# Reads an SPDX XML file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. The bytes are decoded by the XML parser, not
# the native locale. External entities are neither fetched nor expanded. A
# root other than <Document> is an error of class `sbom_spdx_xml_root`, whose
# field `root` names it.
spdx_xml_read <- function(path) {
  doc <- xml2::read_xml(
    readBin(path, "raw", n = file.size(path)),
    options = c("NOBLANKS", "NONET")
  )
  root <- xml2::xml_root(doc)
  name <- xml2::xml_name(root)
  if (name != "Document") {
    cli::cli_abort(
      "the root element is <{name}>, not <Document>",
      class = "sbom_spdx_xml_root", root = name, call = NULL
    )
  }
  spdx_xml_node(root)
}
