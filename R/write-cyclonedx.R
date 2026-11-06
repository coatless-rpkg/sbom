# CycloneDX writer. `cdx_document()` returns a nested list whose keys follow
# the XSD sequence, so the XML writer can walk the same list in order.

cdx_versions <- c("1.4", "1.5", "1.6", "1.7")

cdx_is_set <- function(v) {
  length(v) == 1L && !is.na(v) && nzchar(v)
}

# Appends `value` to `lst` under `name`, only when it is set.
cdx_put <- function(lst, name, value) {
  if (cdx_is_set(value)) {
    lst[[name]] <- as.character(value)
  }
  lst
}

cdx_property <- function(name, value) {
  list(name = name, value = as.character(value))
}

cdx_component <- function(row, version, children = NULL) {
  type <- row$type
  if (type == "platform" && version == "1.4") {
    type <- "application"
  }
  out <- list(type = type, `bom-ref` = row$ref)
  if (cdx_is_set(row$supplier_name)) {
    out$supplier <- list(name = row$supplier_name)
    if (cdx_is_set(row$supplier_url)) {
      out$supplier$url <- list(row$supplier_url)
    }
  }
  out <- cdx_put(out, "publisher", row$maintainer)
  out <- cdx_put(out, "name", row$name)
  out <- cdx_put(out, "version", row$version)
  out <- cdx_put(out, "description", row$description)
  if (cdx_is_set(row$scope) && row$scope == "optional") {
    out$scope <- "optional"
  }

  hashes <- row$hashes[[1]]
  if (!is.null(hashes) && nrow(hashes) > 0L) {
    out$hashes <- unname(lapply(seq_len(nrow(hashes)), function(i) {
      list(alg = hashes$alg[i], content = hashes$content[i])
    }))
  }

  spdx <- row$license_spdx
  written <- row$license_as_written
  if (cdx_is_set(spdx)) {
    out$licenses <- list(list(expression = spdx))
  } else if (cdx_is_set(written)) {
    out$licenses <- list(list(license = list(name = written)))
  }
  out <- cdx_put(out, "purl", row$purl)

  refs <- list()
  add_ref <- function(url, type, comment = NULL) {
    ref <- list(url = url, type = type)
    ref$comment <- comment
    refs[[length(refs) + 1L]] <<- ref
  }
  if (cdx_is_set(row$homepage)) add_ref(row$homepage, "website")
  if (cdx_is_set(row$download_location)) {
    add_ref(row$download_location, "distribution")
  }
  if (cdx_is_set(row$vcs_url)) add_ref(row$vcs_url, "vcs")
  if (cdx_is_set(row$doi)) {
    add_ref(paste0("https://doi.org/", row$doi), "other", "DOI")
  }
  if (length(refs) > 0L) out$externalReferences <- refs

  props <- list()
  add_prop <- function(name, value) {
    props[[length(props) + 1L]] <<- cdx_property(paste0("sbom:", name), value)
  }
  if (cdx_is_set(row$maintainer)) add_prop("maintainer", row$maintainer)
  if (cdx_is_set(spdx) && cdx_is_set(written) && written != spdx) {
    add_prop("license-as-written", written)
  }
  if (cdx_is_set(row$published)) add_prop("published", row$published)
  deps <- row$deps[[1]]
  if (!is.null(deps) && nrow(deps) > 0L) {
    for (i in seq_len(nrow(deps))) {
      add_prop(tolower(deps$field[i]), deps$spec[i])
    }
  }
  if (cdx_is_set(row$system_requirements)) {
    add_prop("system-requirements", row$system_requirements)
  }
  if (row$ref == "R" || identical(row$parent_ref, "R")) add_prop("part-of", "R")
  if (cdx_is_set(row$version_is) && row$version_is == "minimum" &&
        cdx_is_set(row$version)) {
    add_prop("version-is", "minimum")
  }
  if (cdx_is_set(row$bioc_release)) {
    add_prop("bioconductor-release", row$bioc_release)
  }
  if (cdx_is_set(row$doi)) add_prop("doi", row$doi)
  if (cdx_is_set(row$evidence)) add_prop("evidence", row$evidence)
  asserted <- row$asserted[[1]]
  if (!is.null(asserted) && nrow(asserted) > 0L) {
    for (i in seq_len(nrow(asserted))) {
      add_prop("asserted", sprintf(
        "%s: %s, asserted by %s, %s", asserted$field[i], asserted$value[i],
        asserted$asserted_by[i], asserted$reason[i]
      ))
    }
  }
  if (length(props) > 0L) out$properties <- props
  if (length(children) > 0L) out$components <- children
  out
}

# One entry per component whose own dependencies were read. Unknown
# components, app files, packages reached only through Suggests and those
# whose source does not record their dependencies (`deps_known` FALSE) get
# none, since an empty dependsOn would claim they have no dependencies, and
# so does a root whose dependencies are unknown. A component inside another,
# R, an app file or an unknown component is listed only when it has
# dependencies of its own, which only one in a document sbom read can have.
cdx_dependencies <- function(x) {
  comps <- x$components
  rel <- x$relationships
  rel <- rel[rel$field != "contains", , drop = FALSE]
  suggests_only <- comps$scope %in% "optional" &
    !comps$ref %in% rel$to[rel$field != "Suggests"]
  own <- comps$ref %in% rel$from |
    (comps$ref != "R" & is.na(comps$parent_ref) & comps$evidence != "unknown" & comps$type != "file")
  listed <- !comps$deps_known %in% FALSE & (comps$is_root | (own & !suggests_only))
  refs <- sort(comps$ref[listed], method = "radix")
  unname(lapply(refs, function(ref) {
    targets <- sort(unique(rel$to[rel$from == ref]), method = "radix")
    list(ref = ref, dependsOn = as.list(targets))
  }))
}

# The rating methods each CycloneDX version lists: 1.4 has no CVSSv4 or SSVC.
cdx_rating_methods <- function(version) {
  methods <- c("CVSSv2", "CVSSv3", "CVSSv31", "CVSSv4", "OWASP", "SSVC", "other")
  if (version == "1.4") setdiff(methods, c("CVSSv4", "SSVC")) else methods
}

# The CycloneDX ratings of one advisory, from those of its upstream ratings
# that have a score, as R Observatory's sbom_cdx_rating() writes them: the
# severity only when CycloneDX names it, and the vector when there is one.
# The method is the rating's own, or the vector's when it has none, and a
# method the version does not list is "other".
cdx_ratings <- function(ratings, version) {
  if (!is.data.frame(ratings) || nrow(ratings) == 0L) {
    return(list())
  }
  ratings <- ratings[is.finite(ratings$score), , drop = FALSE]
  lapply(seq_len(nrow(ratings)), function(i) {
    r <- ratings[i, , drop = FALSE]
    out <- list(score = as.numeric(r$score))
    severity <- tolower(r$severity)
    if (severity %in% c("critical", "high", "medium", "low", "info", "none")) {
      out$severity <- severity
    }
    method <- if (cdx_is_set(r$method)) r$method else cvss_method(r$vector)
    out$method <- if (method %in% cdx_rating_methods(version)) method else "other"
    cdx_put(out, "vector", r$vector)
  })
}

# One vulnerability per advisory, as R Observatory writes them, with each
# field only when it has a value. The keys follow the XSD sequence.
cdx_vulnerabilities <- function(x, version) {
  adv <- written_advisories(x)
  lapply(seq_len(nrow(adv)), function(i) {
    id <- adv$id[[i]]
    out <- list(
      `bom-ref` = paste0("advisory/", id), id = id,
      source = list(name = "OSV", url = osv_vulnerability_url(id))
    )
    cves <- cve_ids(adv$upstream[[i]])
    if (length(cves) > 0L) {
      out$references <- lapply(cves, function(cve) {
        list(id = cve, source = list(name = "CVE", url = cve_record_url(cve)))
      })
    }
    ratings <- cdx_ratings(adv$ratings[[i]], version)
    if (length(ratings) > 0L) out$ratings <- ratings
    out <- cdx_put(out, "description", adv$summary[[i]])
    if (cdx_is_set(adv$source_url[[i]])) {
      out$advisories <- list(list(url = adv$source_url[[i]]))
    }
    if (cdx_is_set(adv$published[[i]])) {
      out$published <- paste0(adv$published[[i]], "T00:00:00Z")
    }
    out$affects <- lapply(adv$affects[[i]]$ref, function(ref) list(ref = ref))
    out
  })
}

cdx_document <- function(x, version = "1.6") {
  if (!is.character(version) || length(version) != 1L ||
        !version %in% cdx_versions) {
    cli::cli_abort(
      "{.arg version} must be one of {.val {cdx_versions}}, not {.val {version}}."
    )
  }
  comps <- x$components
  comps <- comps[order(comps$ref, method = "radix"), , drop = FALSE]
  rownames(comps) <- NULL
  build <- function(i, children = NULL) {
    cdx_component(comps[i, , drop = FALSE], version, children)
  }

  # Every component with a parent nests under it, wherever the parent is.
  # A component whose parent is not in the document goes to the top level.
  nested <- !is.na(comps$parent_ref) & comps$parent_ref %in% comps$ref
  is_root <- comps$ref == x$metadata$root
  nest <- function(i) {
    kids <- which(nested & comps$parent_ref == comps$ref[i])
    build(i, if (length(kids) > 0L) lapply(kids, nest))
  }
  components <- lapply(which(!is_root & !nested), nest)

  tool <- list(type = "application", name = "sbom")
  tool <- cdx_put(tool, "version", x$metadata$tool_version)
  meta <- list(timestamp = format_timestamp(x$metadata$timestamp))
  meta$tools <- if (version == "1.4") {
    tool$type <- NULL
    list(tool)
  } else {
    list(components = list(tool))
  }
  authors <- x$metadata$author[!is.na(x$metadata$author) & nzchar(x$metadata$author)]
  if (length(authors) > 0L) {
    meta$authors <- unname(lapply(authors, function(a) list(name = a)))
  }
  meta$component <- nest(which(is_root))
  # In 1.4 and 1.5, `manufacture` is the maker of the described component, so
  # the SBOM's organization goes in a property there instead.
  props <- list()
  if (cdx_is_set(x$metadata$organization)) {
    if (version %in% c("1.4", "1.5")) {
      props <- list(cdx_property("sbom:organization", x$metadata$organization))
    } else {
      meta$manufacturer <- list(name = x$metadata$organization)
    }
  }
  props <- c(props, lapply(document_notes(x), function(n) {
    cdx_property("sbom:note", n)
  }))
  if (length(props) > 0L) {
    meta$properties <- unname(props)
  }

  doc <- list(
    `$schema` = sprintf("http://cyclonedx.org/schema/bom-%s.schema.json", version),
    bomFormat = "CycloneDX",
    specVersion = version,
    serialNumber = paste0("urn:uuid:", sbom_uuid(x)),
    version = 1L,
    metadata = meta,
    components = components,
    dependencies = cdx_dependencies(x)
  )
  vulnerabilities <- cdx_vulnerabilities(x, version)
  if (length(vulnerabilities) > 0L) doc$vulnerabilities <- vulnerabilities
  doc
}

cdx_json <- function(x, version = "1.6") {
  doc <- cdx_document(x, version)
  json <- jsonlite::toJSON(
    doc, auto_unbox = TRUE, pretty = TRUE, null = "null"
  )
  enc2utf8(paste0(json, "\n"))
}
