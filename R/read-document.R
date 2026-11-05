# Reading any of the eight SBOM formats into its raw model. read_document()
# detects the format from a file's content, not its name, and parses it:
# CycloneDX JSON, SPDX 2 JSON and SPDX 3 JSON-LD as JSON; the SPDX 2 YAML,
# XML and tag-value serializations into the SPDX JSON model; CycloneDX XML
# into the CycloneDX JSON model; and a SWID tag into a small list. Files come
# from any tool and may be hostile, so every error is one sentence that names
# the file by its basename and quotes none of its text.

# The formats read_document() reads: every format in format_registry() but
# the CSV inventory. format_registry() names the writers, which are defined
# in files collated after this one, so the list is written out here; a test
# checks it against the registry.
read_formats <- c(
  "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml",
  "spdx-tv", "spdx3-jsonld", "swid"
)

# The syntax each format is parsed as.
read_syntax <- c(
  `cyclonedx-json` = "json", `spdx-json` = "json", `spdx3-jsonld` = "json",
  `cyclonedx-xml` = "xml", `spdx-xml` = "xml", swid = "xml",
  `spdx-yaml` = "yaml", `spdx-tv` = "tv"
)

# The formats whose model is checked as JSON is: no empty or repeated key,
# and no nesting deeper than json_max_depth levels. These are the models the
# schema layer applies a JSON schema to, and the CycloneDX XML model, where
# an attribute and a child element of one name would otherwise both be kept.
read_json_models <- c(
  "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml",
  "spdx-tv", "spdx3-jsonld"
)

cdx_xml_ns <- "http://cyclonedx.org/schema/bom/"

# A version sbom recognises: numbers separated by dots.
read_version_pattern <- "^[0-9]+(\\.[0-9]+)+$"

# Raises the read error whose message is `sentence`, a plain string, which
# the condition also keeps whole in its field `sentence`: cli may wrap the
# printed message, but the sentence is never cut.
read_abort <- function(sentence, call) {
  cli::cli_abort("{sentence}", class = "sbom_read_error", sentence = sentence, call = call)
}

is_string <- function(x) {
  is.character(x) && length(x) == 1L && !is.na(x)
}

read_format_name <- function(format) {
  format_registry()[[format]]$name
}

# The message of one of sbom's own errors as the end of a sentence, at full
# width: unstyled, its lines joined, without control characters or a final
# full stop.
read_cnd_text <- function(cnd) {
  old <- options(cli.width = 10000L, cli.condition_width = Inf, cli.num_colors = 1L)
  on.exit(options(old), add = TRUE)
  msg <- iconv(enc2utf8(conditionMessage(cnd)), "UTF-8", "UTF-8", sub = "")
  lines <- trimws(strsplit(cli::ansi_strip(msg), "\n", fixed = TRUE)[[1]])
  msg <- gsub("\\p{Cc}", "", paste(lines[nzchar(lines)], collapse = " "), perl = TRUE)
  sub("[.[:space:]]+$", "", msg)
}

# The sentence for a condition raised while parsing the file `file` as
# `what` ("valid JSON", "valid SPDX YAML" and so on).
# * sbom's own readers explain the problem without quoting the file, so
#   their message is kept.
# * jsonlite's first line is yajl's own description of the error; the lines
#   after it quote the file.
# * libxml2 and yaml quote names and values from the file, so their message
#   is dropped. Neither xml2 nor yaml gives the error's location other than
#   inside that text, where the file can forge it, so no line is given
#   either. So it is for a warning, and for an error in R itself.
read_failure <- function(file, what, cnd, syntax) {
  if (inherits(cnd, "rlang_error")) {
    return(paste0(file, " is not ", what, ": ", read_cnd_text(cnd), "."))
  }
  if (syntax == "json" && inherits(cnd, "error")) {
    first <- strsplit(conditionMessage(cnd), "\n", fixed = TRUE)[[1]][1]
    first <- sub("[.[:space:]]+$", "", gsub("\\p{Cc}", "", if (is.na(first)) "" else first, perl = TRUE))
    if (nzchar(first)) {
      return(paste0(file, " is not ", what, ": ", first, "."))
    }
  }
  paste0(file, " is not ", what, ".")
}

# Evaluates `expr`, a parser, and turns its error, or its first warning, into
# a read error. The YAML alias refusal is already a sentence naming the file.
read_parse <- function(expr, file, what, syntax, call) {
  seen <- new.env(parent = emptyenv())
  value <- tryCatch(
    withCallingHandlers(expr, warning = function(w) {
      if (is.null(seen$warning)) seen$warning <- w
      invokeRestart("muffleWarning")
    }),
    error = function(cnd) {
      sentence <- if (inherits(cnd, "sbom_yaml_alias")) {
        paste0(read_cnd_text(cnd), ".")
      } else {
        read_failure(file, what, cnd, syntax)
      }
      read_abort(sentence, call)
    }
  )
  if (!is.null(seen$warning)) {
    read_abort(read_failure(file, what, seen$warning, syntax), call)
  }
  value
}

read_check_format <- function(format, call) {
  if (identical(format, "csv")) {
    cli::cli_abort(
      "{.arg format} cannot be {.val csv}: sbom cannot read its CSV inventory, which is not an SBOM.",
      call = call
    )
  }
  if (!is_string(format) || !format %in% read_formats) {
    cli::cli_abort("{.arg format} must be NULL or one of {.val {read_formats}}.", call = call)
  }
}

# The file's bytes, without a UTF-8 byte-order mark. Another Unicode
# byte-order mark is an error.
read_bytes <- function(path, file, call) {
  if (dir.exists(path)) {
    read_abort(paste0(file, " is a directory, not a file."), call)
  }
  if (!file.exists(path)) {
    read_abort(paste0(file, " does not exist."), call)
  }
  bytes <- tryCatch(
    suppressWarnings(readBin(path, "raw", n = file.size(path))),
    error = function(cnd) read_abort(paste0(file, " could not be read."), call)
  )
  starts <- function(mark) {
    length(bytes) >= length(mark) && identical(bytes[seq_along(mark)], as.raw(mark))
  }
  encoding <- if (starts(c(0x00, 0x00, 0xfe, 0xff)) || starts(c(0xff, 0xfe, 0x00, 0x00))) {
    "UTF-32"
  } else if (starts(c(0xfe, 0xff)) || starts(c(0xff, 0xfe))) {
    "UTF-16"
  }
  if (!is.null(encoding)) {
    read_abort(paste0(file, " is ", encoding, " text; sbom reads SBOMs written in UTF-8."), call)
  }
  if (starts(c(0xef, 0xbb, 0xbf))) bytes <- bytes[-(1:3)]
  bytes
}

# Whether the first line of `bytes` that is neither blank nor a `#` comment
# starts "SPDXVersion: SPDX-2.". Looks no further than that line, the first
# 1,000 lines or the first 64 KB, whichever comes first.
read_sniff_tv <- function(bytes) {
  space <- as.raw(c(0x20, 0x09, 0x0d))
  n <- min(length(bytes), 65536L)
  bytes <- bytes[seq_len(n)]
  pos <- 1L
  for (k in seq_len(1000L)) {
    if (pos > n) break
    nl <- grepRaw("\n", bytes, offset = pos, fixed = TRUE)
    end <- if (length(nl) == 0L) n else nl - 1L
    if (end >= pos) {
      # The start of a line is enough to tell what it is.
      head <- bytes[pos:min(end, pos + 63L)]
      blank <- all(head %in% space) && (end < pos + 64L || all(bytes[pos:end] %in% space))
      if (!blank && head[1] != as.raw(0x23)) {
        return(length(grepRaw("^SPDXVersion:[ \t]*SPDX-2[.]", head)) > 0L)
      }
    }
    if (length(nl) == 0L) break
    pos <- nl + 1L
  }
  FALSE
}

# What a file's content says it is: "json" when its first character other
# than a space is `{`, "xml" when it is `<`, and otherwise "tv" or "yaml" by
# its lines. NA when it is none of these. The bytes are searched, never
# converted or split into lines.
read_sniff <- function(bytes) {
  space <- as.raw(c(0x20, 0x09, 0x0a, 0x0d))
  first <- NULL
  # A chunk at a time, so that a large file is not compared byte by byte.
  for (start in seq_len(ceiling(length(bytes) / 65536)) * 65536L - 65535L) {
    chunk <- bytes[start:min(start + 65535L, length(bytes))]
    hit <- which(!chunk %in% space)
    if (length(hit) > 0L) {
      first <- chunk[hit[1]]
      break
    }
  }
  if (is.null(first)) {
    return(NA_character_)
  }
  if (first == as.raw(0x7b)) {
    return("json")
  }
  if (first == as.raw(0x3c)) {
    return("xml")
  }
  if (read_sniff_tv(bytes)) {
    return("tv")
  }
  key <- '"?spdxVersion"?[ \t]*:'
  if (length(grepRaw(paste0("^", key), bytes)) > 0L || length(grepRaw(paste0("\n", key), bytes)) > 0L) {
    return("yaml")
  }
  NA_character_
}

# The SPDX 2 version a parsed document states, such as "2.3", or NA.
spdx2_version <- function(doc) {
  version <- if (is.list(doc)) doc[["spdxVersion"]]
  if (is_string(version) && grepl("^SPDX-2\\.", version)) {
    sub("^SPDX-", "", version)
  } else {
    NA_character_
  }
}

# The format and version of a parsed document, as list(format, version), or
# NULL when it is not an SBOM. The version is what the document states, NA
# when it states none; read_document() checks it.
read_family <- function(parsed, syntax) {
  found <- function(format, version) list(format = format, version = version)
  if (syntax == "xml") {
    root <- xml2::xml_root(parsed)
    name <- xml2::xml_name(root)
    ns <- xml2::xml_find_chr(root, "string(namespace-uri(.))")
    if (name == "bom" && startsWith(ns, cdx_xml_ns)) {
      return(found("cyclonedx-xml", substring(ns, nchar(cdx_xml_ns) + 1L)))
    }
    if (name == "SoftwareIdentity" && ns == swid_iso_ns) {
      return(found("swid", "2015"))
    }
    if (name == "Document") {
      # The spdxVersion child in the root's own namespace, if any.
      version <- xml2::xml_find_chr(
        root, "string(*[local-name() = 'spdxVersion' and namespace-uri() = namespace-uri(..)][1])"
      )
      version <- spdx2_version(list(spdxVersion = version))
      if (!is.na(version)) {
        return(found("spdx-xml", version))
      }
    }
    return(NULL)
  }
  version <- spdx2_version(parsed)
  if (syntax != "json") {
    format <- if (syntax == "yaml") "spdx-yaml" else "spdx-tv"
    return(if (is.na(version)) NULL else found(format, version))
  }
  if (identical(parsed[["bomFormat"]], "CycloneDX")) {
    version <- parsed[["specVersion"]]
    return(found("cyclonedx-json", if (is_string(version)) version else NA_character_))
  }
  if (!is.na(version)) {
    return(found("spdx-json", version))
  }
  context <- parsed[["@context"]]
  if (is.list(context)) {
    context <- unlist(context[vapply(context, is_string, logical(1))], use.names = FALSE)
  }
  hit <- if (is.character(context)) context[grepl("spdx.org/rdf/3.", context, fixed = TRUE)]
  if (length(hit) > 0L) {
    # The version is the path segment after the first spdx.org/rdf/ that
    # matched.
    segment <- regmatches(hit[1], regexpr("spdx\\.org/rdf/3\\.[^/]*", hit[1]))
    return(found("spdx3-jsonld", sub("^spdx\\.org/rdf/", "", segment)))
  }
  NULL
}

#' Read an SBOM file into its format's raw model
#'
#' Detects the format from the content, ignoring the file name, unless
#' `format` is given; then the file is parsed with that format's parser and
#' must be of that format. The file is read once, and JSON is checked as the
#' schema layer checks it (`json_parse_strict()`, `json_model_problem()`), so
#' a JSON SBOM with comments is an error here too.
#'
#' @param path Path of the file.
#' @param format `NULL`, or one of `read_formats`.
#' @param call The call errors are reported against.
#' @return `list(format, version, doc, path)`. `doc` is the CycloneDX JSON
#'   model for CycloneDX JSON and XML, the SPDX JSON model for the four SPDX 2
#'   serializations, the JSON-LD document for SPDX 3, and `swid_model()`'s
#'   list for a SWID tag. Errors have class `sbom_read_error`; each is one
#'   sentence naming the file by its basename, kept whole in the field
#'   `sentence`.
#' @noRd
read_document <- function(path, format = NULL, call = parent.frame()) {
  if (!is_string(path) || !nzchar(path)) {
    cli::cli_abort("{.arg path} must be the path of a file.", call = call)
  }
  if (!is.null(format)) {
    read_check_format(format, call)
  }
  file <- basename(path)
  bytes <- read_bytes(path, file, call)
  syntax <- if (is.null(format)) read_sniff(bytes) else read_syntax[[format]]
  if (is.na(syntax)) {
    read_abort(paste0(file, " is not an SBOM in a format sbom reads."), call)
  }

  # Until it is parsed, JSON or XML is known only by its syntax.
  expected <- if (!is.null(format)) format else switch(syntax, yaml = "spdx-yaml", tv = "spdx-tv")
  what <- if (is.null(expected)) {
    switch(syntax, json = "valid JSON", xml = "well-formed XML")
  } else {
    paste("valid", read_format_name(expected))
  }
  if (syntax == "yaml" && !has_yaml()) {
    read_abort(paste0("Reading SPDX YAML needs the yaml package, so ", file, " was not read."), call)
  }
  # The parsers take the bytes already read, or their text.
  input <- if (syntax == "xml") {
    bytes
  } else {
    read_parse(utf8_text(bytes, if (syntax == "json") "it" else "the file"), file, what, syntax, call)
  }
  rm(bytes)
  parsed <- read_parse(
    switch(syntax,
      json = json_parse_strict(input),
      xml = xml2::read_xml(input, options = c("NOBLANKS", "NONET")),
      yaml = spdx_yaml_parse(input, file),
      tv = spdx_tv_parse(input)
    ),
    file, what, syntax, call
  )
  rm(input)

  found <- read_family(parsed, syntax)
  if (is.null(found)) {
    if (is.null(format)) {
      read_abort(paste0(file, " is not an SBOM in a format sbom reads."), call)
    }
    read_abort(paste0(file, " is not ", read_format_name(format), "."), call)
  }
  name <- read_format_name(found$format)
  if (!is.null(format) && found$format != format) {
    read_abort(paste0(file, " is ", name, ", not ", read_format_name(format), "."), call)
  }
  if (found$format != "swid" && !(is_string(found$version) && grepl(read_version_pattern, found$version))) {
    read_abort(paste0(file, " is not valid ", name, ": its version is not one sbom recognises."), call)
  }

  doc <- read_parse(
    switch(found$format,
      `cyclonedx-xml` = cdx_xml_model(xml2::xml_root(parsed)),
      swid = swid_model(xml2::xml_root(parsed)),
      `spdx-xml` = spdx_xml_node(xml2::xml_root(parsed)),
      parsed
    ),
    file, paste("valid", name), "model", call
  )
  if (found$format %in% read_json_models) {
    problem <- json_model_problem(doc)
    if (!is.na(problem)) {
      read_abort(paste0(file, " is not valid ", name, ": ", problem, "."), call)
    }
  }
  if (found$format == "spdx3-jsonld") {
    graph <- doc[["@graph"]]
    if (!is.list(graph) || !is.null(names(graph))) {
      read_abort(paste0(file, " is not valid ", name, ": it has no @graph array."), call)
    }
  }
  list(format = found$format, version = found$version, doc = doc, path = path)
}
