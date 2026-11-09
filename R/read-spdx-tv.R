# Reading SPDX tag-value into the shape of the SPDX JSON model, so that
# every SPDX 2 format is read and checked the same way.

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
# that add an item to an array (`list`). Tags with a structured value are read
# by spdx_tv_element(). The deprecated ArtifactOfProject* tags are not read:
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

# The external reference in the tag-value `value` as a list of
# referenceCategory, referenceType and referenceLocator; aborts unless it has
# three parts.
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

# Builds the element of one section from its tags. Returns list(value, used),
# where `used` says which tags were read. A text tag keeps its first value.
# The values of each tag that adds to an array are gathered in one step, not
# appended one by one, so that a tag repeated many times takes linear time.
# The element's keys come in the order their tags first appear.
spdx_tv_element <- function(kind, tags, values, version) {
  n <- length(tags)
  used <- logical(n)
  if (kind == "review") {
    return(list(value = NULL, used = used))
  }
  el <- spdx_tv_open(kind, values[1])
  used[1] <- TRUE
  fields <- spdx_tv_fields[[kind]]
  rest <- seq_len(n) > 1L
  text_key <- unname(fields$text[tags])
  list_key <- unname(fields$list[tags])
  is_text <- rest & !is.na(text_key)
  is_list <- rest & !is_text & !is.na(list_key)
  # The first value of each text key that the element does not have yet.
  first_text <- is_text
  first_text[is_text] <- !duplicated(text_key[is_text]) & !text_key[is_text] %in% names(el)
  used[first_text | is_list] <- TRUE

  # The tags with a structured value, in order. Each row that adds to an
  # array keeps its item in `items` and the array's key in `item_key`; each
  # single value, its row in `single_row`.
  items <- vector("list", n)
  item_key <- rep(NA_character_, n)
  single <- list()
  single_row <- integer()
  target <- NULL
  last_ref <- NA_integer_
  for (i in which(rest & !is_text & !is_list)) {
    value <- values[i]
    key <- switch(paste0(kind, ":", tags[i]),
      "package:FilesAnalyzed" = "filesAnalyzed",
      "package:PackageVerificationCode" = "packageVerificationCode",
      "package:PackageChecksum" = ,
      "file:FileChecksum" = "checksums",
      "package:ExternalRef" = "externalRefs",
      "package:ExternalRefComment" = "comment",
      "snippet:SnippetByteRange" = ,
      "snippet:SnippetLineRange" = "ranges",
      "license:LicenseCrossReference" = "seeAlsos",
      "annotation:SPDXREF" = "target",
      NA_character_
    )
    if (is.na(key)) next
    if (key %in% c("filesAnalyzed", "packageVerificationCode")) {
      if (key %in% names(single)) next
      single[[key]] <- if (key == "filesAnalyzed") {
        spdx_typed_value(value, "filesAnalyzed")
      } else {
        spdx_tv_verification_code(value)
      }
      single_row[[key]] <- i
    } else if (key == "comment") {
      if (is.na(last_ref) || !is.null(items[[last_ref]]$comment)) next
      items[[last_ref]]$comment <- value
    } else if (key == "target") {
      if (!is.null(target)) next
      target <- trimws(value)
    } else {
      items[[i]] <- switch(key,
        checksums = spdx_tv_checksum(value),
        externalRefs = spdx_tv_external_ref(value, version),
        ranges = spdx_tv_range(value, if (tags[i] == "SnippetByteRange") "offset" else "lineNumber"),
        seeAlsos = {
          urls <- trimws(strsplit(value, ",", fixed = TRUE)[[1]])
          as.list(urls[nzchar(urls)])
        }
      )
      item_key[i] <- key
      if (key == "externalRefs") last_ref <- i
    }
    used[i] <- TRUE
  }

  # Every key the tags set, with the row of its first tag and its value.
  lists <- which(is_list)
  list_keys <- unique(list_key[lists])
  arrays <- which(!is.na(item_key))
  array_keys <- unique(item_key[arrays])
  keys <- c(text_key[first_text], list_keys, array_keys, names(single))
  rows <- c(
    which(first_text), lists[match(list_keys, list_key[lists])],
    arrays[match(array_keys, item_key[arrays])], unname(single_row)
  )
  set <- c(
    as.list(values[first_text]),
    lapply(list_keys, function(k) as.list(values[lists[list_key[lists] == k]])),
    lapply(array_keys, function(k) {
      gathered <- items[arrays[item_key[arrays] == k]]
      if (k == "seeAlsos") do.call(c, c(list(list()), gathered)) else gathered
    }),
    unname(single)
  )
  o <- order(rows)
  el[keys[o]] <- set[o]
  if (!is.null(target)) {
    attr(el, "target") <- target
  }
  if (kind == "snippet" && !is.null(el$snippetFromFile)) {
    el$ranges <- lapply(el$ranges, lapply, function(pointer) {
      pointer$reference <- el$snippetFromFile
      pointer
    })
  }
  list(value = el, used = used)
}

# Builds the document's own fields from the tags of its creation sections,
# gathering the repeated ones (Creator, ExternalDocumentRef) in one step.
spdx_tv_document <- function(tags, values) {
  doc_key <- unname(spdx_tv_doc_tags[tags])
  info_key <- unname(spdx_tv_info_tags[tags])
  is_doc <- !is.na(doc_key)
  first_doc <- is_doc
  first_doc[is_doc] <- !duplicated(doc_key[is_doc])
  creators <- which(!is_doc & tags == "Creator")
  is_info <- !is_doc & !is.na(info_key)
  first_info <- is_info
  first_info[is_info] <- !duplicated(info_key[is_info])
  external <- which(!is_doc & tags == "ExternalDocumentRef")
  used <- first_doc | first_info
  used[c(creators, external)] <- TRUE

  # Each key, with the row of its first tag and its value.
  ordered <- function(keys, rows, set) {
    out <- list()
    o <- order(rows)
    out[keys[o]] <- set[o]
    out
  }
  ci <- ordered(
    c(if (length(creators) > 0L) "creators", info_key[first_info]),
    c(creators[1L][length(creators) > 0L], which(first_info)),
    c(if (length(creators) > 0L) list(as.list(values[creators])), as.list(values[first_info]))
  )
  ci_row <- min(c(creators, which(first_info), Inf))
  doc <- ordered(
    c(doc_key[first_doc], if (length(ci) > 0L) "creationInfo", if (length(external) > 0L) "externalDocumentRefs"),
    c(which(first_doc), if (length(ci) > 0L) ci_row, external[1L][length(external) > 0L]),
    c(
      as.list(values[first_doc]), if (length(ci) > 0L) list(ci),
      if (length(external) > 0L) list(lapply(values[external], spdx_tv_external_document))
    )
  )
  list(value = doc, used = used)
}

# The SPDXID of each of `items`; NA for an item with none.
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
  at <- as.integer(names(has_files))
  for (j in seq_along(has_files)) {
    packages[[at[j]]]$hasFiles <- as.list(has_files[[j]])
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
    # Each element gets all its annotations at once, in order. The groups
    # are taken by position: by name, each would be a search.
    hit <- which(!is.na(pos))
    by_element <- split(hit, pos[hit])
    at <- as.integer(names(by_element))
    group <- groups[[g]]
    for (j in seq_along(by_element)) {
      group[[at[j]]]$annotations <- c(group[[at[j]]]$annotations, annotations[by_element[[j]]])
    }
    groups[[g]] <- group
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
