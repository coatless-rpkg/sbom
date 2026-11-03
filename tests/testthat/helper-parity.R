# Normalizers for the parity test against R Observatory's dplyr 1.2.1 sample.
# Each keeps only what both tools should agree on, and sorts where order
# carries no meaning. What they drop is spec §6a's list of intentional
# differences (hashes, DOIs, evidence, notes, tool and author metadata, ids,
# timestamps, repository URL fragments) plus the download locations that an
# offline build cannot know.

# Spec §6a: sbom writes the repository URL without a `#fragment`.
parity_strip_fragment <- function(url) sub("#.*$", "", url)

parity_sort_by <- function(items, ...) {
  keys <- lapply(list(...), function(field) {
    vapply(items, function(x) {
      if (is.null(x[[field]])) "" else as.character(x[[field]])
    }, "")
  })
  items[do.call(order, c(unname(keys), list(method = "radix")))]
}

parity_cdx_component <- function(comp) {
  keep <- c(
    "type", "bom-ref", "supplier", "publisher", "name", "version",
    "description", "licenses", "purl"
  )
  out <- comp[intersect(keep, names(comp))]

  refs <- Filter(
    function(r) !r$type %in% c("distribution", "other"),
    comp$externalReferences
  )
  refs <- lapply(refs, function(r) {
    if (identical(r$type, "vcs")) r$url <- parity_strip_fragment(r$url)
    r
  })
  if (length(refs) > 0L) out$externalReferences <- refs

  props <- lapply(comp$properties, function(p) {
    list(name = sub("^(r-observatory|sbom):", "ns:", p$name), value = p$value)
  })
  dropped <- paste0("ns:", c("note", "evidence", "doi", "asserted"))
  props <- Filter(function(p) !p$name %in% dropped, props)
  if (length(props) > 0L) out$properties <- parity_sort_by(props, "name", "value")

  if (length(comp$components) > 0L) {
    out$components <- parity_cdx_components(comp$components)
  }
  out
}

parity_cdx_components <- function(comps) {
  parity_sort_by(lapply(comps, parity_cdx_component), "bom-ref")
}

normalize_cdx <- function(doc) {
  deps <- lapply(doc$dependencies, function(d) {
    list(ref = d$ref, dependsOn = sort(as.character(unlist(d$dependsOn)), method = "radix"))
  })
  deps <- Filter(function(d) length(d$dependsOn) > 0L, deps)
  list(
    component = parity_cdx_component(doc$metadata$component),
    components = parity_cdx_components(doc$components),
    dependencies = parity_sort_by(deps, "ref")
  )
}

parity_spdx_package <- function(pkg) {
  keep <- c(
    "name", "SPDXID", "versionInfo", "packageFileName", "supplier",
    "originator", "downloadLocation", "filesAnalyzed", "homepage",
    "sourceInfo", "licenseConcluded", "licenseDeclared", "licenseComments",
    "copyrightText", "comment", "externalRefs", "primaryPackagePurpose"
  )
  out <- pkg[intersect(keep, names(pkg))]
  if (!identical(out$downloadLocation, "NONE")) out$downloadLocation <- NULL
  if (!is.null(out$sourceInfo)) out$sourceInfo <- parity_strip_fragment(out$sourceInfo)
  refs <- Filter(function(r) !identical(r$referenceType, "doi"), out$externalRefs)
  refs <- lapply(refs, function(r) {
    if (identical(r$referenceType, "vcs")) {
      r$referenceLocator <- parity_strip_fragment(r$referenceLocator)
    }
    r
  })
  out$externalRefs <- if (length(refs) > 0L) refs
  out
}

normalize_spdx <- function(doc) {
  list(
    packages = parity_sort_by(lapply(doc$packages, parity_spdx_package), "SPDXID"),
    relationships = parity_sort_by(
      doc$relationships,
      "spdxElementId", "relationshipType", "relatedSpdxElement", "comment"
    )
  )
}
