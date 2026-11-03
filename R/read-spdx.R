# Reads an SPDX YAML file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. Needs the yaml package. The bytes are read
# as UTF-8, whatever the native locale.
spdx_yaml_read <- function(path) {
  bytes <- readBin(path, "raw", n = file.size(path))
  txt <- rawToChar(bytes)
  Encoding(txt) <- "UTF-8"
  yaml::yaml.load(
    txt,
    # Keep every sequence a list, so a one-element array stays an array.
    handlers = list(seq = function(x) unname(as.list(x)))
  )
}

# Element names that are always lists in the SPDX JSON model.
spdx_xml_arrays <- c(
  "creators", "packages", "relationships", "checksums", "externalRefs",
  "documentDescribes", "files", "snippets", "hasExtractedLicensingInfos",
  "annotations", "externalDocumentRefs", "licenseInfoFromFiles",
  "attributionTexts", "seeAlsos", "fileTypes", "fileContributors", "hasFiles",
  "ranges"
)

spdx_xml_node <- function(node) {
  kids <- xml2::xml_children(node)
  if (length(kids) == 0L) {
    return(xml2::xml_text(node))
  }
  tags <- xml2::xml_name(kids)
  out <- list()
  for (key in unique(tags)) {
    values <- lapply(kids[tags == key], spdx_xml_node)
    if (key == "filesAnalyzed") {
      values <- lapply(values, function(v) identical(v, "true"))
    }
    out[[key]] <- if (key %in% spdx_xml_arrays || length(values) > 1L) {
      values
    } else {
      values[[1L]]
    }
  }
  out
}

# Reads an SPDX XML file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. The bytes are decoded by the XML parser, not
# the native locale.
spdx_xml_read <- function(path) {
  doc <- xml2::read_xml(readBin(path, "raw", n = file.size(path)))
  spdx_xml_node(xml2::xml_root(doc))
}

# Splits tag-value text into list(tag, value) pairs. A `<text>` value may span
# lines; blank lines and `#` comments between pairs are skipped.
spdx_tv_pairs <- function(lines) {
  pairs <- list()
  i <- 1L
  n <- length(lines)
  while (i <= n) {
    line <- lines[i]
    if (!nzchar(trimws(line)) || startsWith(line, "#")) {
      i <- i + 1L
      next
    }
    m <- regmatches(line, regexec("^([A-Za-z][A-Za-z0-9]*): ?(.*)$", line))[[1]]
    if (length(m) == 0L) {
      cli::cli_abort("line {i} is not a {.code Tag: value} pair", call = NULL)
    }
    tag <- m[2]
    value <- m[3]
    if (startsWith(value, "<text>")) {
      start <- i
      value <- substring(value, 7L)
      while (!grepl("</text>", value, fixed = TRUE)) {
        i <- i + 1L
        if (i > n) {
          cli::cli_abort("the {.code <text>} value starting on line {start} is never closed", call = NULL)
        }
        value <- paste0(value, "\n", lines[i])
      }
      value <- sub("</text>.*$", "", value)
    }
    pairs[[length(pairs) + 1L]] <- list(tag = tag, value = value)
    i <- i + 1L
  }
  pairs
}

spdx_tv_doc_tags <- c(
  SPDXVersion = "spdxVersion", DataLicense = "dataLicense", SPDXID = "SPDXID",
  DocumentName = "name", DocumentNamespace = "documentNamespace",
  DocumentComment = "comment"
)

spdx_tv_package_tags <- c(
  SPDXID = "SPDXID", PackageVersion = "versionInfo",
  PackageFileName = "packageFileName", PackageSupplier = "supplier",
  PackageOriginator = "originator", PackageDownloadLocation = "downloadLocation",
  PackageHomePage = "homepage", PackageSourceInfo = "sourceInfo",
  PackageLicenseConcluded = "licenseConcluded",
  PackageLicenseDeclared = "licenseDeclared",
  PackageLicenseComments = "licenseComments",
  PackageCopyrightText = "copyrightText", PackageComment = "comment",
  PrimaryPackagePurpose = "primaryPackagePurpose"
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

# Reads an SPDX tag-value file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. It inverts the tags the writer emits and
# ignores any others. The bytes are read as UTF-8, whatever the native locale.
spdx_tv_read <- function(path) {
  txt <- rawToChar(readBin(path, "raw", n = file.size(path)))
  Encoding(txt) <- "UTF-8"
  txt <- sub("^﻿", "", txt)
  pairs <- spdx_tv_pairs(strsplit(txt, "\r?\n")[[1]])
  if (length(pairs) == 0L || pairs[[1]]$tag != "SPDXVersion") {
    cli::cli_abort("the first tag is not {.code SPDXVersion}", call = NULL)
  }

  doc <- list()
  pkg <- NULL
  rel <- NULL
  flush_package <- function() {
    if (!is.null(pkg)) doc$packages <<- c(doc$packages, list(pkg))
    pkg <<- NULL
  }
  flush_relationship <- function() {
    if (!is.null(rel)) doc$relationships <<- c(doc$relationships, list(rel))
    rel <<- NULL
  }
  for (pair in pairs) {
    tag <- pair$tag
    value <- pair$value
    if (tag == "PackageName") {
      flush_relationship()
      flush_package()
      pkg <- list(name = value)
    } else if (tag == "Relationship") {
      flush_relationship()
      flush_package()
      parts <- spdx_tv_split(value, 2L)
      if (length(parts) != 3L) {
        cli::cli_abort("the relationship {.val {value}} does not have three parts", call = NULL)
      }
      rel <- list(
        spdxElementId = parts[1], relationshipType = parts[2],
        relatedSpdxElement = parts[3]
      )
    } else if (tag == "RelationshipComment") {
      if (!is.null(rel)) rel$comment <- value
    } else if (!is.null(pkg)) {
      if (tag == "FilesAnalyzed") {
        pkg$filesAnalyzed <- tolower(trimws(value)) == "true"
      } else if (tag == "PackageChecksum") {
        alg <- sub(":.*$", "", value)
        pkg$checksums <- c(pkg$checksums, list(list(
          algorithm = alg, checksumValue = trimws(sub("^[^:]*:", "", value))
        )))
      } else if (tag == "ExternalRef") {
        parts <- spdx_tv_split(value, 2L)
        if (length(parts) != 3L) {
          cli::cli_abort("the external reference {.val {value}} does not have three parts", call = NULL)
        }
        pkg$externalRefs <- c(pkg$externalRefs, list(list(
          referenceCategory = parts[1], referenceType = parts[2],
          referenceLocator = parts[3]
        )))
      } else if (tag == "ExternalRefComment") {
        k <- length(pkg$externalRefs)
        if (k > 0L) pkg$externalRefs[[k]]$comment <- value
      } else if (tag %in% names(spdx_tv_package_tags)) {
        pkg[[spdx_tv_package_tags[[tag]]]] <- value
      }
    } else if (is.null(rel)) {
      if (tag == "Creator") {
        doc$creationInfo$creators <- c(doc$creationInfo$creators, list(value))
      } else if (tag == "Created") {
        doc$creationInfo$created <- value
      } else if (tag == "CreatorComment") {
        doc$creationInfo$comment <- value
      } else if (tag %in% names(spdx_tv_doc_tags)) {
        doc[[spdx_tv_doc_tags[[tag]]]] <- value
      }
    }
  }
  flush_relationship()
  flush_package()
  doc
}
