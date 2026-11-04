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
  if (row$ref == "R" || cdx_is_set(row$parent_ref)) add_prop("part-of", "R")
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
# none, since an empty dependsOn would claim they have no dependencies.
cdx_dependencies <- function(x) {
  comps <- x$components
  rel <- x$relationships
  rel <- rel[rel$field != "contains", , drop = FALSE]
  suggests_only <- comps$scope %in% "optional" &
    !comps$ref %in% rel$to[rel$field != "Suggests"]
  listed <- comps$is_root |
    (comps$ref != "R" & is.na(comps$parent_ref) & comps$evidence != "unknown" &
      comps$type != "file" & !suggests_only & !comps$deps_known %in% FALSE)
  refs <- sort(comps$ref[listed], method = "radix")
  unname(lapply(refs, function(ref) {
    targets <- sort(unique(rel$to[rel$from == ref]), method = "radix")
    list(ref = ref, dependsOn = as.list(targets))
  }))
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

  is_base <- !is.na(comps$parent_ref)
  is_root <- comps$ref == x$metadata$root
  base_comps <- lapply(which(is_base), build)
  top <- which(!is_root & !is_base)
  components <- lapply(top, function(i) {
    build(i, if (comps$ref[i] == "R") base_comps)
  })

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
  meta$component <- build(which(is_root))
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

  list(
    `$schema` = sprintf("http://cyclonedx.org/schema/bom-%s.schema.json", version),
    bomFormat = "CycloneDX",
    specVersion = version,
    serialNumber = paste0("urn:uuid:", sbom_uuid(x)),
    version = 1L,
    metadata = meta,
    components = components,
    dependencies = cdx_dependencies(x)
  )
}

cdx_json <- function(x, version = "1.6") {
  doc <- cdx_document(x, version)
  json <- jsonlite::toJSON(
    doc, auto_unbox = TRUE, pretty = TRUE, null = "null"
  )
  enc2utf8(paste0(json, "\n"))
}
