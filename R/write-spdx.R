# SPDX 2.3 JSON writer, following R Observatory's layout.

spdx_prefixes <- c(
  cran = "cran", bioconductor = "bioc", github = "github",
  repository = "repository", local = "local", unknown = "unknown"
)

spdx_sanitize <- function(x) {
  gsub("[^A-Za-z0-9.-]", "-", x)
}

# One unique SPDXID per row of `components`, in row order.
spdx_ids <- function(components) {
  eco <- components$ecosystem
  name <- spdx_sanitize(components$name)
  prefix <- unname(spdx_prefixes[eco])
  prefix[is.na(prefix)] <- "unknown"
  ids <- paste0("SPDXRef-", prefix, "-", name)
  ids[eco == "r"] <- "SPDXRef-R"
  ids[eco == "base-r"] <- paste0("SPDXRef-R-", name[eco == "base-r"])
  ids[eco == "library"] <- "SPDXRef-library"

  dup <- ids %in% ids[duplicated(ids)]
  if (any(dup)) {
    ver <- spdx_sanitize(components$version)
    add <- dup & !is.na(ver)
    ids[add] <- paste0(ids[add], "-", ver[add])
  }
  # Last resort for ids still colliding: number the later ones.
  while (anyDuplicated(ids) > 0L) {
    d <- which(duplicated(ids))
    ids[d] <- paste0(ids[d], "-", seq_along(d) + 1L)
  }
  ids
}

spdx_is_set <- function(v) {
  length(v) == 1L && !is.na(v) && nzchar(v)
}

spdx_package <- function(row, id) {
  is_r <- row$ecosystem == "r"
  is_base <- !is.na(row$parent_ref)
  p <- list(name = row$name, SPDXID = id)
  if (spdx_is_set(row$version)) p$versionInfo <- row$version
  if (spdx_is_set(row$package_file_name)) {
    p$packageFileName <- row$package_file_name
  }
  if (!is_r && !is_base) {
    p$supplier <- if (spdx_is_set(row$supplier_name)) {
      paste0("Organization: ", row$supplier_name)
    } else {
      "NOASSERTION"
    }
  }
  if (spdx_is_set(row$maintainer)) {
    p$originator <- paste0("Person: ", row$maintainer)
  }
  p$downloadLocation <- if (is_base) {
    "NONE"
  } else if (spdx_is_set(row$download_location)) {
    row$download_location
  } else {
    "NOASSERTION"
  }
  p$filesAnalyzed <- FALSE

  hashes <- row$hashes[[1]]
  if (!is.null(hashes) && nrow(hashes) > 0L) {
    p$checksums <- unname(lapply(seq_len(nrow(hashes)), function(i) {
      list(
        algorithm = sub("^SHA-", "SHA", hashes$alg[i]),
        checksumValue = hashes$content[i]
      )
    }))
  }
  if (spdx_is_set(row$homepage)) p$homepage <- row$homepage
  if (spdx_is_set(row$vcs_url)) {
    p$sourceInfo <- paste0("Source repository ", row$vcs_url)
  }
  p$licenseConcluded <- "NOASSERTION"
  p$licenseDeclared <- if (spdx_is_set(row$license_spdx)) {
    row$license_spdx
  } else {
    "NOASSERTION"
  }
  if (spdx_is_set(row$license_comment)) {
    p$licenseComments <- row$license_comment
  }
  p$copyrightText <- "NOASSERTION"

  parts <- character()
  if (is_r || is_base) {
    if (spdx_is_set(row$description)) parts <- row$description
  } else {
    if (spdx_is_set(row$maintainer)) {
      parts <- c(parts, paste0("Maintainer ", row$maintainer, "."))
    }
    if (spdx_is_set(row$published)) {
      parts <- c(parts, paste0("Published ", row$published, "."))
    }
  }
  asserted <- row$asserted[[1]]
  if (!is.null(asserted) && nrow(asserted) > 0L) {
    parts <- c(parts, sprintf(
      "Asserted by %s: %s is %s (%s).",
      asserted$asserted_by, asserted$field, asserted$value, asserted$reason
    ))
  }
  if (length(parts) > 0L) p$comment <- paste(parts, collapse = " ")

  refs <- list()
  add_ref <- function(category, type, locator) {
    refs[[length(refs) + 1L]] <<- list(
      referenceCategory = category, referenceType = type,
      referenceLocator = locator
    )
  }
  if (spdx_is_set(row$purl)) add_ref("PACKAGE-MANAGER", "purl", row$purl)
  if (spdx_is_set(row$vcs_url)) add_ref("OTHER", "vcs", row$vcs_url)
  if (spdx_is_set(row$doi)) add_ref("OTHER", "doi", row$doi)
  if (length(refs) > 0L) p$externalRefs <- refs

  p$primaryPackagePurpose <-
    if (is_r || row$type == "application") "APPLICATION" else "LIBRARY"
  p
}

spdx_relationships <- function(x, ids) {
  rel <- x$relationships
  id_of <- function(ref) unname(ids[match(ref, x$components$ref)])
  root_row <- x$components$ref == x$metadata$root
  describes <- list(
    spdxElementId = "SPDXRef-DOCUMENT", relationshipType = "DESCRIBES",
    relatedSpdxElement = ids[root_row][1]
  )
  if (nrow(rel) == 0L) return(list(describes))

  from <- id_of(rel$from)
  to <- id_of(rel$to)
  type <- ifelse(
    rel$field == "contains", "CONTAINS",
    ifelse(rel$field == "Suggests", "OPTIONAL_DEPENDENCY_OF", "DEPENDS_ON")
  )
  comment <- ifelse(is.na(rel$spec), NA_character_,
                    paste0(rel$field, ": ", rel$spec))
  comment[rel$field == "contains" & rel$from == "R"] <- "Part of R"
  # Suggests: written from the suggested package to its dependent.
  swap <- type == "OPTIONAL_DEPENDENCY_OF"
  tmp <- from[swap]
  from[swap] <- to[swap]
  to[swap] <- tmp

  ord <- order(from, type, to, method = "radix")
  rows <- lapply(ord, function(i) {
    r <- list(
      spdxElementId = from[i], relationshipType = type[i],
      relatedSpdxElement = to[i]
    )
    if (!is.na(comment[i])) r$comment <- comment[i]
    r
  })
  c(list(describes), rows)
}

spdx_document <- function(x) {
  comps <- x$components
  ids <- spdx_ids(comps)
  ord <- order(ids, method = "radix")
  packages <- lapply(ord, function(i) {
    spdx_package(comps[i, , drop = FALSE], ids[i])
  })

  tool <- if (spdx_is_set(x$metadata$tool_version)) {
    paste0("Tool: sbom-", x$metadata$tool_version)
  } else {
    "Tool: sbom"
  }
  authors <- x$metadata$author[!is.na(x$metadata$author) & nzchar(x$metadata$author)]
  creators <- c(
    if (spdx_is_set(x$metadata$organization)) {
      paste0("Organization: ", x$metadata$organization)
    },
    if (length(authors) > 0L) paste0("Person: ", authors),
    tool
  )
  root <- comps[comps$ref == x$metadata$root, , drop = FALSE][1, ]
  name <- if (spdx_is_set(root$version)) {
    paste0(root$name, "-", root$version)
  } else {
    root$name
  }
  list(
    spdxVersion = "SPDX-2.3",
    dataLicense = "CC0-1.0",
    SPDXID = "SPDXRef-DOCUMENT",
    name = name,
    documentNamespace = spdx_namespace(x),
    comment = paste(document_notes(x), collapse = " "),
    creationInfo = list(
      created = format_timestamp(x$metadata$timestamp),
      creators = as.list(creators)
    ),
    packages = packages,
    relationships = spdx_relationships(x, ids)
  )
}

spdx_json <- function(x) {
  json <- jsonlite::toJSON(
    spdx_document(x), auto_unbox = TRUE, pretty = TRUE, null = "null"
  )
  enc2utf8(paste0(json, "\n"))
}
