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

# YAML types that the yaml package turns into numbers or NA. Their text is
# kept: `versionInfo: 1.10` is "1.10", not 1.1.
spdx_yaml_text_types <- c(
  "int#hex", "int#oct", "int#base60", "int#na", "float", "float#fix",
  "float#exp", "float#base60", "float#nan", "float#inf", "float#neginf",
  "float#na", "bool#na"
)

# Decimal integers and booleans keep their text too, carrying a mark until
# the enclosing map or sequence is built. There an integer under an integer
# key becomes an integer, and a boolean under a boolean key a logical;
# anywhere else they are plain text, so `name: no` is "no".
spdx_yaml_unmark <- function(x, key) {
  bool <- attr(x, "sbom_bool", exact = TRUE)
  if (!is.null(bool)) {
    return(if (key %in% spdx_json_booleans) bool else as.vector(x))
  }
  if (isTRUE(attr(x, "sbom_int", exact = TRUE))) {
    return(spdx_typed_value(as.vector(x), key))
  }
  x
}

spdx_yaml_handlers <- function() {
  text <- rep(list(function(x) x), length(spdx_yaml_text_types))
  names(text) <- spdx_yaml_text_types
  c(text, list(
    int = function(x) structure(x, sbom_int = TRUE),
    `bool#yes` = function(x) structure(x, sbom_bool = TRUE),
    `bool#no` = function(x) structure(x, sbom_bool = FALSE),
    # Keep every sequence a list, so a one-element array stays an array.
    seq = function(x) lapply(unname(as.list(x)), spdx_yaml_unmark, key = ""),
    map = function(x) {
      for (i in seq_along(x)) {
        x[i] <- list(spdx_yaml_unmark(x[[i]], names(x)[i]))
      }
      x
    }
  ))
}

# The names a YAML text uses both as an anchor (&name) and as an alias
# (*name), found in the text before it is parsed. A name is a run of
# libyaml's anchor characters, [A-Za-z0-9_-], which is where libyaml itself
# ends it: `&a:x` anchors ":x" as `a`.
yaml_alias_names <- function(txt) {
  names_after <- function(mark) {
    found <- regmatches(txt, gregexpr(paste0(mark, "[A-Za-z0-9_-]+"), txt, perl = TRUE))[[1]]
    substring(found, 2L)
  }
  aliases <- names_after("\\*")
  aliases[aliases %in% names_after("&")]
}

# Reads an SPDX YAML file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. Needs the yaml package. The bytes are read
# as UTF-8, whatever the native locale. A `!expr` tag is read as text and
# never evaluated, whatever the yaml.eval.expr option says. A document that
# uses aliases is refused unparsed, with an error of class `sbom_yaml_alias`:
# SPDX never needs them, and a few hundred bytes of aliases can expand to
# gigabytes.
spdx_yaml_read <- function(path) {
  spdx_yaml_parse(read_utf8_text(path), basename(path))
}

# The same, for the text of the file named `file`.
spdx_yaml_parse <- function(txt, file) {
  aliases <- yaml_alias_names(txt)
  if (length(aliases) > 0L) {
    name <- substr(aliases[1], 1L, 40L)
    cli::cli_abort(
      "{file} uses YAML aliases (*{name}), which sbom does not expand.",
      class = "sbom_yaml_alias", call = NULL
    )
  }
  doc <- yaml::yaml.load(txt, eval.expr = FALSE, handlers = spdx_yaml_handlers())
  spdx_yaml_unmark(doc, "")
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

# Splits tag-value lines into list(tag, value), two character vectors. A
# `<text>` value may span lines; blank lines and `#` comments between pairs
# are skipped. Vectorised over the lines: only the multi-line text values
# are walked one by one, since each starts after the one before has closed.
spdx_tv_pairs <- function(lines) {
  n <- length(lines)
  ok <- grepl("^[A-Za-z][A-Za-z0-9]*:", lines)
  tag <- sub(":.*$", "", lines)
  value <- sub("^[A-Za-z][A-Za-z0-9]*: ?", "", lines)
  is_text <- ok & startsWith(value, "<text>")
  value[is_text] <- substring(value[is_text], 7L)

  opens <- which(is_text & !grepl("</text>", value, fixed = TRUE))
  closes <- which(grepl("</text>", lines, fixed = TRUE))
  inside <- logical(n)
  ends <- integer(length(opens))
  # The first line after each opening line that holds a closing tag.
  first_close <- findInterval(opens, closes) + 1L
  unclosed <- NA_integer_
  next_free <- 1L
  for (k in seq_along(opens)) {
    open <- opens[k]
    if (open < next_free) next
    if (first_close[k] > length(closes)) {
      unclosed <- open
      inside[seq_len(n) > open] <- TRUE
      break
    }
    ends[k] <- closes[first_close[k]]
    inside[(open + 1L):ends[k]] <- TRUE
    next_free <- ends[k] + 1L
  }

  skip <- inside | !nzchar(trimws(lines)) | startsWith(lines, "#")
  bad <- which(!skip & !ok)
  if (length(bad) > 0L && (is.na(unclosed) || bad[1] < unclosed)) {
    i <- bad[1]
    cli::cli_abort("line {i} is not a {.code Tag: value} pair", call = NULL)
  }
  if (!is.na(unclosed)) {
    cli::cli_abort("the {.code <text>} value starting on line {unclosed} is never closed", call = NULL)
  }
  used <- which(ends > 0L)
  value[opens[used]] <- vapply(used, function(k) {
    paste(c(value[opens[k]], lines[(opens[k] + 1L):ends[k]]), collapse = "\n")
  }, "")
  value[is_text] <- sub("</text>.*$", "", value[is_text])
  keep <- !skip
  list(tag = tag[keep], value = value[keep])
}

# The tags that start each kind of section of a tag-value file. A section
# runs to the next one. ExternalDocumentRef is a single line of the creation
# section, so the creation section's tags are read again after it. Reviews
# (SPDX 2.3 clause 13, deprecated) are not read.
spdx_tv_sections <- c(
  PackageName = "package", FileName = "file", SnippetSPDXID = "snippet",
  LicenseID = "license", Annotator = "annotation",
  Relationship = "relationship", Reviewer = "review",
  ExternalDocumentRef = "document"
)

spdx_tv_doc_tags <- c(
  SPDXVersion = "spdxVersion", DataLicense = "dataLicense", SPDXID = "SPDXID",
  DocumentName = "name", DocumentNamespace = "documentNamespace",
  DocumentComment = "comment"
)
spdx_tv_info_tags <- c(
  Created = "created", CreatorComment = "comment",
  LicenseListVersion = "licenseListVersion"
)

# For each kind of section, the tags that set a text field (`text`) and those
# that add an item to an array (`list`). Tags with a structured value are in
# spdx_tv_special(). The deprecated ArtifactOfProject* tags are not read:
# the JSON model's artifactOfs has no defined fields. A single-valued tag
# that is repeated keeps its first value; the repeat is not read.
spdx_tv_fields <- list(
  package = list(
    text = c(
      SPDXID = "SPDXID", PackageVersion = "versionInfo",
      PackageFileName = "packageFileName", PackageSupplier = "supplier",
      PackageOriginator = "originator",
      PackageDownloadLocation = "downloadLocation",
      PackageHomePage = "homepage", PackageSourceInfo = "sourceInfo",
      PackageLicenseConcluded = "licenseConcluded",
      PackageLicenseDeclared = "licenseDeclared",
      PackageLicenseComments = "licenseComments",
      PackageCopyrightText = "copyrightText", PackageSummary = "summary",
      PackageDescription = "description", PackageComment = "comment",
      PrimaryPackagePurpose = "primaryPackagePurpose",
      ReleaseDate = "releaseDate", BuiltDate = "builtDate",
      ValidUntilDate = "validUntilDate"
    ),
    list = c(
      PackageLicenseInfoFromFiles = "licenseInfoFromFiles",
      PackageAttributionText = "attributionTexts"
    )
  ),
  file = list(
    text = c(
      SPDXID = "SPDXID", LicenseConcluded = "licenseConcluded",
      LicenseComments = "licenseComments", FileCopyrightText = "copyrightText",
      FileComment = "comment", FileNotice = "noticeText"
    ),
    list = c(
      FileType = "fileTypes", LicenseInfoInFile = "licenseInfoInFiles",
      FileContributor = "fileContributors",
      FileAttributionText = "attributionTexts",
      FileDependency = "fileDependencies"
    )
  ),
  snippet = list(
    text = c(
      SnippetFromFileSPDXID = "snippetFromFile",
      SnippetLicenseConcluded = "licenseConcluded",
      SnippetLicenseComments = "licenseComments",
      SnippetCopyrightText = "copyrightText", SnippetComment = "comment",
      SnippetName = "name"
    ),
    list = c(
      LicenseInfoInSnippet = "licenseInfoInSnippets",
      SnippetAttributionText = "attributionTexts"
    )
  ),
  license = list(
    text = c(ExtractedText = "extractedText", LicenseName = "name", LicenseComment = "comment"),
    list = character()
  ),
  annotation = list(
    text = c(
      AnnotationDate = "annotationDate", AnnotationType = "annotationType",
      AnnotationComment = "comment"
    ),
    list = character()
  ),
  relationship = list(text = c(RelationshipComment = "comment"), list = character())
)

# Splits `value` on its first `n` spaces; the last piece keeps any others.
spdx_tv_split <- function(value, n) {
  out <- character()
  for (k in seq_len(n)) {
    pos <- regexpr(" ", value, fixed = TRUE)
    if (pos < 0L) break
    out <- c(out, substr(value, 1L, pos - 1L))
    value <- substr(value, pos + 1L, nchar(value))
  }
  c(out, value)
}

# "SHA1: abc" as an SPDX checksum.
spdx_tv_checksum <- function(value) {
  list(
    algorithm = trimws(sub(":.*$", "", value)),
    checksumValue = trimws(sub("^[^:]*:", "", value))
  )
}

# "<code> (excludes: a, b)" as a packageVerificationCode. The "excludes:" is
# optional, and so is the space before the parenthesis.
spdx_tv_verification_code <- function(value) {
  m <- regmatches(value, regexec(
    "^[[:space:]]*([^([:space:]]*)[[:space:]]*(\\((.*)\\))?[[:space:]]*$", value
  ))[[1]]
  if (length(m) == 0L) {
    return(list(packageVerificationCodeValue = trimws(value)))
  }
  code <- list(packageVerificationCodeValue = m[2])
  excluded <- trimws(strsplit(sub("^[[:space:]]*excludes:", "", m[4]), ",", fixed = TRUE)[[1]])
  excluded <- excluded[nzchar(excluded)]
  if (length(excluded) > 0L) {
    code$packageVerificationCodeExcludedFiles <- as.list(excluded)
  }
  code
}

# "<id> <document URI> SHA1: <value>" as an externalDocumentRefs item.
spdx_tv_external_document <- function(value) {
  parts <- spdx_tv_split(value, 2L)
  if (length(parts) != 3L) {
    cli::cli_abort("an external document reference does not have three parts", call = NULL)
  }
  list(
    externalDocumentId = parts[1], spdxDocument = parts[2],
    checksum = spdx_tv_checksum(parts[3])
  )
}

spdx_tv_external_ref <- function(value, version) {
  parts <- spdx_tv_split(value, 2L)
  if (length(parts) != 3L) {
    cli::cli_abort("an external reference does not have three parts", call = NULL)
  }
  # SPDX 2.2 tag-value writes PACKAGE-MANAGER; its JSON model has PACKAGE_MANAGER.
  if (identical(version, "SPDX-2.2") && parts[1] == "PACKAGE-MANAGER") {
    parts[1] <- "PACKAGE_MANAGER"
  }
  list(referenceCategory = parts[1], referenceType = parts[2], referenceLocator = parts[3])
}

# A snippet's "310:420" as a range of `field` ("offset" or "lineNumber")
# pointers. The file they point into is added once the section is read.
spdx_tv_range <- function(value, field) {
  m <- regmatches(value, regexec(
    "^[[:space:]]*([0-9]+)[[:space:]]*:[[:space:]]*([0-9]+)[[:space:]]*$", value
  ))[[1]]
  start <- spdx_integer_value(m[2])
  end <- spdx_integer_value(m[3])
  if (is.na(start) || is.na(end)) {
    cli::cli_abort("a snippet range is not two numbers separated by a colon", call = NULL)
  }
  pointer <- function(at) stats::setNames(list(at), field)
  list(startPointer = pointer(start), endPointer = pointer(end))
}

# The element a section's first tag starts.
spdx_tv_open <- function(kind, value) {
  switch(kind,
    package = list(name = value),
    file = list(fileName = value),
    snippet = list(SPDXID = value),
    license = list(licenseId = value),
    annotation = list(annotator = value),
    relationship = {
      parts <- spdx_tv_split(value, 2L)
      if (length(parts) != 3L) {
        cli::cli_abort("a relationship does not have three parts", call = NULL)
      }
      list(spdxElementId = parts[1], relationshipType = parts[2], relatedSpdxElement = parts[3])
    }
  )
}

# Applies a tag with a structured value to `el`, or returns NULL when the tag
# does not belong to this kind of section. An annotation keeps the element
# its SPDXREF names in the attribute "target".
spdx_tv_special <- function(el, kind, tag, value, version) {
  switch(paste0(kind, ":", tag),
    "package:FilesAnalyzed" = {
      if (!is.null(el$filesAnalyzed)) {
        return(NULL)
      }
      el$filesAnalyzed <- spdx_typed_value(value, "filesAnalyzed")
    },
    "package:PackageChecksum" = ,
    "file:FileChecksum" = el$checksums <- c(el$checksums, list(spdx_tv_checksum(value))),
    "package:PackageVerificationCode" = {
      if (!is.null(el$packageVerificationCode)) {
        return(NULL)
      }
      el$packageVerificationCode <- spdx_tv_verification_code(value)
    },
    "package:ExternalRef" = el$externalRefs <- c(el$externalRefs, list(spdx_tv_external_ref(value, version))),
    "package:ExternalRefComment" = {
      k <- length(el$externalRefs)
      if (k == 0L || !is.null(el$externalRefs[[k]]$comment)) {
        return(NULL)
      }
      el$externalRefs[[k]]$comment <- value
    },
    "snippet:SnippetByteRange" = el$ranges <- c(el$ranges, list(spdx_tv_range(value, "offset"))),
    "snippet:SnippetLineRange" = el$ranges <- c(el$ranges, list(spdx_tv_range(value, "lineNumber"))),
    "license:LicenseCrossReference" = {
      urls <- trimws(strsplit(value, ",", fixed = TRUE)[[1]])
      el$seeAlsos <- c(el$seeAlsos, as.list(urls[nzchar(urls)]))
    },
    "annotation:SPDXREF" = {
      if (!is.null(attr(el, "target", exact = TRUE))) {
        return(NULL)
      }
      attr(el, "target") <- trimws(value)
    },
    return(NULL)
  )
  el
}

# Builds the element of one section from its tags. Returns list(value, used),
# where `used` says which tags were read.
spdx_tv_element <- function(kind, tags, values, version) {
  used <- logical(length(tags))
  if (kind == "review") {
    return(list(value = NULL, used = used))
  }
  el <- spdx_tv_open(kind, values[1])
  used[1] <- TRUE
  fields <- spdx_tv_fields[[kind]]
  for (i in seq_along(tags)[-1L]) {
    tag <- tags[i]
    value <- values[i]
    key <- fields$text[tag]
    if (!is.na(key)) {
      if (!is.null(el[[key]])) next
      el[[key]] <- value
    } else if (!is.na(key <- fields$list[tag])) {
      el[[key]] <- c(el[[key]], list(value))
    } else {
      new <- spdx_tv_special(el, kind, tag, value, version)
      if (is.null(new)) next
      el <- new
    }
    used[i] <- TRUE
  }
  if (kind == "snippet" && !is.null(el$snippetFromFile)) {
    el$ranges <- lapply(el$ranges, lapply, function(pointer) {
      pointer$reference <- el$snippetFromFile
      pointer
    })
  }
  list(value = el, used = used)
}

# Builds the document's own fields from the tags of its creation sections.
spdx_tv_document <- function(tags, values) {
  doc <- list()
  used <- logical(length(tags))
  for (i in seq_along(tags)) {
    tag <- tags[i]
    value <- values[i]
    if (!is.na(key <- spdx_tv_doc_tags[tag])) {
      if (!is.null(doc[[key]])) next
      doc[[key]] <- value
    } else if (tag == "Creator") {
      doc$creationInfo$creators <- c(doc$creationInfo$creators, list(value))
    } else if (!is.na(key <- spdx_tv_info_tags[tag])) {
      if (!is.null(doc$creationInfo[[key]])) next
      if (is.null(doc$creationInfo)) doc$creationInfo <- list()
      doc$creationInfo[[key]] <- value
    } else if (tag == "ExternalDocumentRef") {
      doc$externalDocumentRefs <- c(doc$externalDocumentRefs, list(spdx_tv_external_document(value)))
    } else {
      next
    }
    used[i] <- TRUE
  }
  list(value = doc, used = used)
}

spdx_tv_ids <- function(items) {
  vapply(items, function(x) {
    if (is.character(x$SPDXID) && length(x$SPDXID) == 1L) x$SPDXID else NA_character_
  }, "")
}

# Puts the sections' elements together into the document. A file belongs to
# the package whose section came last before it, if any. An annotation goes
# to the package, file or snippet its SPDXREF names, and to the document
# when it names the document or nothing. An annotation of any other element
# is left out. Returns list(doc, dropped), where `dropped` holds the
# sections of the annotations left out.
spdx_tv_assemble <- function(doc, kinds, elements) {
  pkg_sections <- which(kinds == "package")
  file_sections <- which(kinds == "file")
  packages <- elements[pkg_sections]
  files <- elements[file_sections]
  snippets <- elements[kinds == "snippet"]
  annotations <- elements[kinds == "annotation"]

  last_package <- cummax(replace(integer(length(kinds)), pkg_sections, pkg_sections))
  owner <- match(last_package[file_sections], pkg_sections)
  file_ids <- spdx_tv_ids(files)
  keep <- !is.na(owner) & !is.na(file_ids)
  has_files <- split(unname(file_ids[keep]), owner[keep])
  for (k in names(has_files)) {
    packages[[as.integer(k)]]$hasFiles <- as.list(has_files[[k]])
  }

  targets <- vapply(annotations, function(a) {
    target <- attr(a, "target", exact = TRUE)
    if (is.null(target)) NA_character_ else target
  }, "")
  annotations <- lapply(annotations, `attr<-`, which = "target", value = NULL)
  groups <- list(packages = packages, files = files, snippets = snippets)
  placed <- rep(FALSE, length(annotations))
  for (g in names(groups)) {
    pos <- match(targets, spdx_tv_ids(groups[[g]]))
    pos[placed] <- NA_integer_
    for (j in which(!is.na(pos))) {
      groups[[g]][[pos[j]]]$annotations <- c(groups[[g]][[pos[j]]]$annotations, list(annotations[[j]]))
    }
    placed <- placed | !is.na(pos)
  }
  to_doc <- !placed & (is.na(targets) | targets %in% c("SPDXRef-DOCUMENT", doc$SPDXID))

  parts <- c(
    groups,
    list(
      hasExtractedLicensingInfos = elements[kinds == "license"],
      relationships = elements[kinds == "relationship"],
      annotations = annotations[to_doc]
    )
  )
  for (key in names(parts)) {
    if (length(parts[[key]]) > 0L) doc[[key]] <- parts[[key]]
  }
  list(doc = doc, dropped = which(kinds == "annotation")[!placed & !to_doc])
}

# Reads an SPDX tag-value file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives, mapping each tag of SPDX 2.3 clauses 6 to 12
# that has a counterpart in the JSON model. The names of the tags it did not
# read (reviews, the ArtifactOfProject* tags and unknown tags) are kept in the
# attribute "skipped_tags" when there are any. The bytes are read as UTF-8,
# whatever the native locale, and a byte-order mark is dropped.
spdx_tv_read <- function(path) {
  spdx_tv_parse(read_utf8_text(path))
}

# The same, for the text of a file.
spdx_tv_parse <- function(txt) {
  pairs <- spdx_tv_pairs(strsplit(txt, "\r?\n")[[1]])
  tags <- pairs$tag
  values <- pairs$value
  if (length(tags) == 0L || tags[1] != "SPDXVersion") {
    cli::cli_abort("the first tag is not {.code SPDXVersion}", call = NULL)
  }

  # Each tag's section, numbered from 1 for the opening creation section.
  starts <- unname(spdx_tv_sections[tags])
  section <- cumsum(!is.na(starts)) + 1L
  kinds <- c("document", starts[!is.na(starts)])
  rows <- split(seq_along(tags), section)

  used <- logical(length(tags))
  in_doc <- which(kinds[section] == "document")
  res <- spdx_tv_document(tags[in_doc], values[in_doc])
  doc <- res$value
  used[in_doc] <- res$used
  elements <- vector("list", length(kinds))
  for (s in which(kinds != "document")) {
    i <- rows[[s]]
    res <- spdx_tv_element(kinds[s], tags[i], values[i], values[1])
    elements[s] <- list(res$value)
    used[i] <- res$used
  }
  res <- spdx_tv_assemble(doc, kinds, elements)
  doc <- res$doc
  for (s in res$dropped) {
    i <- rows[[s]]
    used[i[tags[i] == "SPDXREF"][1]] <- FALSE
  }
  if (!all(used)) attr(doc, "skipped_tags") <- unique(tags[!used])
  doc
}
