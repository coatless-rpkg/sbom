# SPDX 3 JSON-LD writer, following R Observatory's sbom_spdx3(). The document
# is an @graph of typed elements whose ids live under the document namespace.
# The version is a parameter throughout, so SPDX 3.1 can be added later.

spdx3_versions <- "3.0.1"

spdx3_creation_info <- "_:creationinfo"

# The first 12 hex digits of the SHA-1 of a string's UTF-8 bytes.
spdx3_hash12 <- function(x) {
  substr(cli::hash_raw_sha1(charToRaw(enc2utf8(x))), 1L, 12L)
}

# `local`, or `local-2`, `local-3`, ... when it is already taken.
spdx3_unique_local <- function(local, taken) {
  out <- local
  n <- 1L
  while (out %in% taken) {
    n <- n + 1L
    out <- paste0(local, "-", n)
  }
  out
}

# The comment text of the SPDX 3 package for the component row `row`: its
# maintainer, description and license note, joined into one string.
spdx3_package_comment <- function(row) {
  is_r <- identical(row$ecosystem, "r")
  is_base <- identical(row$parent_ref, "R")
  parts <- character()
  if (spdx_is_set(row$maintainer)) {
    parts <- paste0("Maintainer ", row$maintainer, ".")
  }
  if ((is_r || is_base || is_embedded_ref(row$ref) || row$ecosystem %in% system_ecosystems) &&
        spdx_is_set(row$description)) {
    parts <- c(parts, row$description)
  }
  # license_comment reads "Declared in DESCRIPTION as ..., which has no SPDX
  # expression ..."; R Observatory words it "License declared in ...".
  if (!spdx_is_set(row$license_spdx) && spdx_is_set(row$license_as_written) &&
        spdx_is_set(row$license_comment)) {
    parts <- c(parts, paste0("License d", substring(row$license_comment, 2L)))
  }
  parts <- c(parts, spdx_asserted_sentences(row), spdx_system_requirements(row))
  if (length(parts) > 0L) paste(parts, collapse = " ")
}

# A checksum algorithm in SPDX 3's vocabulary: SHA-256 is sha256, SHA3-256
# sha3_256.
spdx3_hash_algorithm <- function(alg) {
  alg <- tolower(alg)
  ifelse(startsWith(alg, "sha3-"), sub("-", "_", alg, fixed = TRUE), gsub("-", "", alg, fixed = TRUE))
}

# The SPDX 3 `software_Package` element of the component row `row` with SPDX
# id `id`, linked to the ids `supplier` and `person` (`person` may be NULL).
spdx3_package <- function(row, id, supplier, person) {
  p <- list(
    type = "software_Package", spdxId = id,
    creationInfo = spdx3_creation_info, name = row$name
  )
  p$suppliedBy <- supplier
  if (!is.null(person)) p$originatedBy <- list(person)
  p$summary <- spdx_package_summary(row)
  p$comment <- spdx3_package_comment(row)

  hashes <- row$hashes[[1]]
  if (!is.null(hashes) && nrow(hashes) > 0L) {
    p$verifiedUsing <- unname(lapply(seq_len(nrow(hashes)), function(i) {
      list(
        type = "Hash",
        algorithm = spdx3_hash_algorithm(hashes$alg[i]),
        hashValue = hashes$content[i]
      )
    }))
  }
  if (spdx_is_set(row$vcs_url)) {
    p$externalRef <- list(list(
      type = "ExternalRef", externalRefType = "vcs", locator = list(row$vcs_url)
    ))
  }
  if (spdx_is_set(row$doi)) {
    p$externalIdentifier <- list(list(
      type = "ExternalIdentifier", externalIdentifierType = "other",
      identifier = row$doi,
      identifierLocator = list(paste0("https://doi.org/", row$doi)),
      comment = "DOI"
    ))
  }
  if (spdx_is_set(row$published) && grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", row$published)) {
    p$releaseTime <- paste0(row$published, "T00:00:00Z")
  }
  # R, and a library root (a platform in CycloneDX too), are platforms.
  p$software_primaryPurpose <- if (identical(row$ecosystem, "r") ||
                                     (isTRUE(row$is_root) && row$type == "platform")) {
    "platform"
  } else if (row$type == "application") {
    "application"
  } else if (row$type == "file") {
    "file"
  } else {
    "library"
  }
  if (spdx_is_set(row$download_location)) {
    p$software_downloadLocation <- row$download_location
  }
  info <- spdx_nix_info(row)
  if (!is.null(info)) p$software_sourceInfo <- info
  if (spdx_is_set(row$homepage)) p$software_homePage <- row$homepage
  if (spdx_is_set(row$purl)) p$software_packageUrl <- row$purl
  if (spdx_is_set(row$version)) p$software_packageVersion <- row$version
  p
}

# The organization, then one person per author; a software agent named sbom
# when there are neither, since createdBy needs at least one agent.
spdx3_creators <- function(metadata, id) {
  el <- function(type, local, name) {
    list(type = type, spdxId = id(local), creationInfo = spdx3_creation_info, name = name)
  }
  out <- list()
  if (spdx_is_set(metadata$organization)) {
    out <- list(el("Organization", "creator-organization", metadata$organization))
  }
  authors <- metadata$author[!is.na(metadata$author) & nzchar(metadata$author)]
  for (i in seq_along(authors)) {
    out[[length(out) + 1L]] <- el("Person", paste0("creator-person-", i), authors[i])
  }
  if (length(out) == 0L) {
    out <- list(el("SoftwareAgent", "creator-sbom", "sbom"))
  }
  out
}

# For each component in ref order: its supplier and maintainer, the first time
# each is seen; the package; its license expression, the first time it is
# seen; and its hasDeclaredLicense relationship. Ids are made unique.
spdx3_components <- function(comps, pkg_ids, local_ids, id) {
  ci <- spdx3_creation_info
  elements <- list()
  taken <- character()
  seen <- list(org = character(), person = character(), license = character())
  first_time <- function(kind, key, local) {
    hit <- match(key, names(seen[[kind]]))
    if (!is.na(hit)) return(list(id = unname(seen[[kind]][hit]), new = FALSE))
    local <- spdx3_unique_local(local, taken)
    taken <<- c(taken, local)
    seen[[kind]][key] <<- id(local)
    list(id = id(local), new = TRUE)
  }

  for (k in order(comps$ref, method = "radix")) {
    row <- comps[k, , drop = FALSE]
    supplier <- NULL
    if (spdx_is_set(row$supplier_name)) {
      url <- if (spdx_is_set(row$supplier_url)) row$supplier_url else ""
      org <- first_time(
        "org", paste(row$supplier_name, url, sep = "\n"),
        paste0("supplier-", spdx_sanitize(row$supplier_name))
      )
      supplier <- org$id
      if (org$new) {
        o <- list(
          type = "Organization", spdxId = org$id, creationInfo = ci,
          name = row$supplier_name
        )
        if (nzchar(url)) {
          o$externalIdentifier <- list(list(
            type = "ExternalIdentifier", externalIdentifierType = "urlScheme", identifier = url
          ))
        }
        elements[[length(elements) + 1L]] <- o
      }
    }
    person <- NULL
    if (spdx_is_set(row$maintainer)) {
      who <- first_time(
        "person", row$maintainer, paste0("person-", spdx3_hash12(row$maintainer))
      )
      person <- who$id
      if (who$new) {
        elements[[length(elements) + 1L]] <- list(
          type = "Person", spdxId = who$id, creationInfo = ci, name = row$maintainer
        )
      }
    }

    elements[[length(elements) + 1L]] <- spdx3_package(row, pkg_ids[k], supplier, person)

    lic_to <- NULL
    if (spdx_is_set(row$license_spdx)) {
      lic <- first_time(
        "license", row$license_spdx, paste0("license-", spdx3_hash12(row$license_spdx))
      )
      if (lic$new) {
        elements[[length(elements) + 1L]] <- list(
          type = "simplelicensing_LicenseExpression", spdxId = lic$id,
          creationInfo = ci, simplelicensing_licenseExpression = row$license_spdx
        )
      }
      lic_to <- lic$id
    } else if (!identical(row$parent_ref, "R")) {
      lic_to <- "expandedlicensing_NoAssertionLicense"
    }
    if (!is.null(lic_to)) {
      elements[[length(elements) + 1L]] <- list(
        type = "Relationship", spdxId = id(paste0("rel-lic-", local_ids[k])),
        creationInfo = ci, from = pkg_ids[k], relationshipType = "hasDeclaredLicense",
        to = list(lic_to)
      )
    }
  }

  elements
}

# Depends and Imports are dependsOn; LinkingTo, and a system requirement on a
# build tool, are build-scoped dependsOn, and any other system requirement is
# a runtime-scoped one; Suggests is hasOptionalDependency; a dynamic link is
# hasDynamicLink, which the bundled 3.0.1 schema lists. Numbered in sorted
# order.
spdx3_dependencies <- function(x, pkg_ids, id) {
  rel <- x$relationships
  rel <- rel[rel$field != "contains", , drop = FALSE]
  if (nrow(rel) == 0L) return(list())
  from <- unname(pkg_ids[match(rel$from, x$components$ref)])
  to <- unname(pkg_ids[match(rel$to, x$components$ref)])
  # An optional dependency of a read SBOM is written as Suggests is, with no
  # comment.
  rtype <- ifelse(
    rel$field %in% c("Suggests", "optional"), "hasOptionalDependency",
    ifelse(rel$field == "dynamic_link", "hasDynamicLink", "dependsOn")
  )
  etype <- ifelse(
    rel$field %in% c("LinkingTo", "system_requirement"),
    "LifecycleScopedRelationship", "Relationship"
  )
  comment <- relationship_comment(rel)
  comment[rel$field == "optional"] <- NA_character_
  build <- rel$field == "LinkingTo" | (rel$field == "system_requirement" &
    is_build_tool(x$components$name[match(rel$to, x$components$ref)]))
  ord <- order(from, rtype, to, etype, rel$field, method = "radix")
  lapply(seq_along(ord), function(n) {
    i <- ord[n]
    r <- list(
      type = etype[i], spdxId = id(paste0("rel-dep-", n)),
      creationInfo = spdx3_creation_info
    )
    if (!is.na(comment[i])) r$comment <- comment[i]
    r$from <- from[i]
    r$relationshipType <- rtype[i]
    r$to <- list(to[i])
    if (etype[i] == "LifecycleScopedRelationship") {
      r$scope <- if (build[i]) "build" else "runtime"
    }
    r
  })
}

# One contains relationship per container: R holds its base packages
# (rel-part-of-R), a library root holds its packages (rel-contains-library),
# and a package holds the packages compiled into it.
spdx3_contains <- function(x, pkg_ids, local_ids, id) {
  rel <- x$relationships
  rel <- rel[rel$field == "contains", , drop = FALSE]
  if (nrow(rel) == 0L) return(list())
  comps <- x$components
  from_row <- match(rel$from, comps$ref)
  to_id <- unname(pkg_ids[match(rel$to, comps$ref)])
  rows <- unique(from_row)
  rows <- rows[order(pkg_ids[rows], method = "radix")]
  lapply(rows, function(k) {
    is_r <- identical(comps$ecosystem[k], "r")
    local <- if (is_r) {
      "rel-part-of-R"
    } else {
      paste0("rel-contains-", sub("^SPDXRef-", "", local_ids[k]))
    }
    r <- list(type = "Relationship", spdxId = id(local), creationInfo = spdx3_creation_info)
    if (is_r) r$comment <- "R's own packages are part of R"
    r$from <- unname(pkg_ids[k])
    r$relationshipType <- "contains"
    r$to <- as.list(sort(unique(to_id[from_row == k]), method = "radix"))
    r
  })
}

# One security_Vulnerability per advisory, each followed by a
# hasAssociatedVulnerability relationship from each package it affects, as R
# Observatory writes them. The local ids hold the OSV id as it is, as in
# sbom.php: osv_id_ok() lets through only letters, digits and . _ : -, which
# an IRI fragment may hold. Any other id, which only an <sbom> built by hand
# or from a document could hold, is sanitized. A local id already in
# `taken`, the local ids in the graph, is made unique.
spdx3_advisories <- function(x, pkg_ids, taken, id) {
  ci <- spdx3_creation_info
  comps <- x$components
  adv <- written_advisories(x)
  out <- list()
  for (i in seq_len(nrow(adv))) {
    advisory <- adv$id[[i]]
    key <- if (osv_id_ok(advisory)) advisory else spdx_sanitize(advisory)
    local <- spdx3_unique_local(paste0("advisory-", key), taken)
    taken <- c(taken, local)
    v <- list(type = "security_Vulnerability", spdxId = id(local), creationInfo = ci, name = advisory)
    if (spdx_is_set(adv$summary[[i]])) v$summary <- adv$summary[[i]]
    v$externalIdentifier <- c(
      list(list(
        type = "ExternalIdentifier", externalIdentifierType = "securityOther", identifier = advisory,
        identifierLocator = list(osv_vulnerability_url(advisory))
      )),
      lapply(cve_ids(adv$upstream[[i]]), function(cve) {
        list(
          type = "ExternalIdentifier", externalIdentifierType = "cve", identifier = cve,
          identifierLocator = list(cve_record_url(cve))
        )
      })
    )
    if (spdx_is_set(adv$source_url[[i]])) {
      v$externalRef <- list(list(
        type = "ExternalRef", externalRefType = "securityAdvisory", locator = list(adv$source_url[[i]])
      ))
    }
    if (spdx_is_set(adv$published[[i]])) {
      v$security_publishedTime <- paste0(adv$published[[i]], "T00:00:00Z")
    }
    out[[length(out) + 1L]] <- v

    hits <- adv$affects[[i]]
    for (j in seq_len(nrow(hits))) {
      k <- match(hits$ref[[j]], comps$ref)
      local <- spdx3_unique_local(paste0("rel-advisory-", key, "-", j), taken)
      taken <- c(taken, local)
      out[[length(out) + 1L]] <- list(
        type = "Relationship", spdxId = id(local), creationInfo = ci,
        comment = paste0(
          "OSV lists ", comps$name[[k]], " ", hits$version[[j]], " among the versions ", advisory, " affects."
        ),
        from = unname(pkg_ids[k]), relationshipType = "hasAssociatedVulnerability", to = list(v$spdxId)
      )
    }
  }
  out
}

# The SPDX 3 JSON-LD graph of `x` at spec `version` as a list for jsonlite.
# Aborts when `version` is not supported.
spdx3_document <- function(x, version = "3.0.1") {
  if (!is.character(version) || length(version) != 1L || !version %in% spdx3_versions) {
    cli::cli_abort(
      "{.arg version} must be one of {.val {spdx3_versions}} for SPDX 3, not {.val {version}}."
    )
  }
  ns <- spdx_namespace(x)
  id <- function(local) paste0(ns, "#", local)
  ci <- spdx3_creation_info
  comps <- x$components
  local_ids <- spdx_ids(comps)
  pkg_ids <- id(local_ids)

  creators <- spdx3_creators(x$metadata, id)
  tool_name <- if (spdx_is_set(x$metadata$tool_version)) {
    paste("sbom", x$metadata$tool_version)
  } else {
    "sbom"
  }
  tool <- list(type = "Tool", spdxId = id("tool-sbom"), creationInfo = ci, name = tool_name)
  elements <- c(
    creators,
    list(tool),
    spdx3_components(comps, pkg_ids, local_ids, id),
    spdx3_dependencies(x, pkg_ids, id),
    spdx3_contains(x, pkg_ids, local_ids, id)
  )
  taken <- substring(vapply(elements, function(e) e$spdxId, character(1)), nchar(ns) + 2L)
  advisories <- spdx3_advisories(x, pkg_ids, taken, id)
  elements <- c(elements, advisories)
  element_ids <- vapply(elements, function(e) e$spdxId, character(1))

  root <- comps[comps$ref == x$metadata$root, , drop = FALSE][1, ]
  name <- if (spdx_is_set(root$version)) paste0(root$name, "-", root$version) else root$name
  sbom_id <- id("sbom")
  sbom <- list(
    type = "software_Sbom", spdxId = sbom_id, creationInfo = ci, name = name,
    rootElement = list(unname(pkg_ids[match(x$metadata$root, comps$ref)])),
    element = as.list(element_ids)
  )
  doc <- list(type = "SpdxDocument", spdxId = id("document"), creationInfo = ci, name = name)
  notes <- paste(document_notes(x), collapse = " ")
  if (nzchar(notes)) doc$comment <- notes
  doc$dataLicense <- "https://spdx.org/licenses/CC0-1.0"
  doc$profileConformance <- list("core", "software", "simpleLicensing")
  # Vulnerabilities are elements of the security profile.
  if (length(advisories) > 0L) doc$profileConformance <- c(doc$profileConformance, list("security"))
  doc$rootElement <- list(sbom_id)
  doc$element <- as.list(c(element_ids, sbom_id))

  creation <- list(
    type = "CreationInfo", `@id` = ci, specVersion = version,
    created = format_timestamp(x$metadata$timestamp),
    createdBy = lapply(creators, function(e) e$spdxId),
    createdUsing = list(tool$spdxId)
  )
  list(
    `@context` = paste0("https://spdx.org/rdf/", version, "/spdx-context.jsonld"),
    `@graph` = c(list(creation), elements, list(sbom, doc))
  )
}

# The SPDX 3 JSON-LD text of `x` at spec `version`, pretty-printed and
# ending in a newline.
spdx3_jsonld <- function(x, version = "3.0.1") {
  json <- jsonlite::toJSON(
    spdx3_document(x, version), auto_unbox = TRUE, pretty = TRUE, null = "null"
  )
  enc2utf8(paste0(json, "\n"))
}
