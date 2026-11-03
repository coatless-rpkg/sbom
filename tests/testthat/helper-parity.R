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

# R Observatory writes "licence" in the comments it shares with sbom, which
# writes the US "license"; the comparison treats the two spellings as one.
us_spelling <- function(x) {
  rapply(x, function(s) gsub("(?<![A-Za-z])([Ll])icence", "\\1icense", s, perl = TRUE),
         classes = "character", how = "replace")
}

normalize_spdx <- function(doc) {
  us_spelling(list(
    packages = parity_sort_by(lapply(doc$packages, parity_spdx_package), "SPDXID"),
    relationships = parity_sort_by(
      doc$relationships,
      "spdxElementId", "relationshipType", "relatedSpdxElement", "comment"
    )
  ))
}

# SPDX 3: element ids differ between the two tools, so every reference is
# replaced by a key both share: pkg:<name>, person:<name>, org:<name> and
# lic:<expression>; expandedlicensing_NoAssertionLicense stays as it is. Drops
# CreationInfo, the creators, the tool, verifiedUsing,
# software_downloadLocation, externalIdentifier, the Sbom and the SpdxDocument.
normalize_spdx3 <- function(doc) {
  g <- doc[["@graph"]]
  named <- Filter(function(e) !is.null(e$spdxId), g)
  ids <- vapply(named, function(e) e$spdxId, "")
  keys <- vapply(named, function(e) {
    switch(e$type,
      software_Package = paste0("pkg:", e$name),
      Person = paste0("person:", e$name),
      Organization = paste0("org:", e$name),
      simplelicensing_LicenseExpression = paste0("lic:", e$simplelicensing_licenseExpression),
      NA_character_
    )
  }, "")
  names_of <- vapply(named, function(e) if (is.null(e$name)) NA_character_ else e$name, "")
  key <- function(ref) {
    ref <- as.character(unlist(ref))
    out <- keys[match(ref, ids)]
    out[is.na(out)] <- ref[is.na(out)]
    out
  }
  name <- function(ref) names_of[match(as.character(unlist(ref)), ids)]

  fields <- c(
    "comment", "software_primaryPurpose", "software_homePage",
    "software_packageUrl", "software_packageVersion", "releaseTime"
  )
  packages <- lapply(Filter(function(e) e$type == "software_Package", g), function(e) {
    out <- list(name = e$name)
    if (!is.null(e$suppliedBy)) out$suppliedBy <- name(e$suppliedBy)
    if (!is.null(e$originatedBy)) out$originatedBy <- name(e$originatedBy)
    for (f in fields) out[[f]] <- e[[f]]
    vcs <- Filter(function(r) identical(r$externalRefType, "vcs"), e$externalRef)
    if (length(vcs) > 0L) {
      out$vcs <- parity_strip_fragment(unlist(lapply(vcs, function(r) r$locator)))
    }
    out
  })

  rels <- lapply(Filter(function(e) grepl("Relationship$", e$type), g), function(e) {
    out <- list(
      type = e$type, from = key(e$from), relationshipType = e$relationshipType,
      to = sort(key(e$to), method = "radix")
    )
    out$comment <- e$comment
    out$scope <- e$scope
    out
  })
  rel_key <- function(field) {
    vapply(rels, function(r) paste(r[[field]], collapse = "\n"), "")
  }
  rels <- rels[order(
    rel_key("from"), rel_key("relationshipType"), rel_key("to"),
    rel_key("type"), rel_key("comment"), rel_key("scope"),
    method = "radix"
  )]

  licenses <- Filter(function(e) e$type == "simplelicensing_LicenseExpression", g)
  us_spelling(list(
    packages = parity_sort_by(packages, "name", "software_packageVersion"),
    relationships = rels,
    licenses = sort(vapply(licenses, function(e) e$simplelicensing_licenseExpression, ""), method = "radix")
  ))
}

parity_sbom <- function() {
  lib <- test_path("fixtures/lib-dplyr-1.2.1")
  sbom_package(file.path(lib, "dplyr"), dependencies = c("Depends", "Imports", "LinkingTo"), lib = lib,
               author = "Parity", organization = "Parity")
}

# Sorts the names of every nested named list, so two documents compare equal
# whatever order their keys came in.
sort_keys <- function(x) {
  if (!is.list(x)) return(x)
  x <- lapply(x, sort_keys)
  if (!is.null(names(x))) x <- x[order(names(x), method = "radix")]
  x
}

# SWID: keeps what both tools should agree on. Drops tagId, tagVersion, the
# tagCreator, installationmedia, the requires hrefs, generator, description and
# R Observatory's `ro:dependency*` / `ro:dataRelease` attributes. Extension
# attributes are matched by local name, whatever their namespace prefix.
normalize_swid <- function(doc) {
  root <- xml2::xml_root(doc)
  by_local <- function(path) xml2::xml_find_all(root, path)
  attr_of <- function(node, name) {
    a <- xml2::xml_attrs(node)
    a <- a[sub("^.*:", "", names(a)) == name]
    if (length(a) == 0L) NA_character_ else unname(a[[1]])
  }
  rel_href <- function(rel) {
    node <- by_local(sprintf("/*/*[local-name()='Link'][@rel='%s']", rel))
    if (length(node) == 0L) NA_character_ else xml2::xml_attr(node[[1]], "href")
  }
  entities <- by_local("/*/*[local-name()='Entity'][@role!='tagCreator']")
  meta <- by_local("/*/*[local-name()='Meta']")[[1]]
  requires <- lapply(
    by_local("/*/*[local-name()='Link'][@rel='requires']"),
    function(l) {
      list(
        name = attr_of(l, "name"), version = attr_of(l, "version"),
        versionIs = attr_of(l, "versionIs"), purl = attr_of(l, "purl"),
        partOf = attr_of(l, "partOf"), use = attr_of(l, "use")
      )
    }
  )
  requires <- requires[order(vapply(requires, function(r) r$name, ""), method = "radix")]
  list(
    name = xml2::xml_attr(root, "name"),
    version = xml2::xml_attr(root, "version"),
    versionScheme = xml2::xml_attr(root, "versionScheme"),
    entities = lapply(entities, function(e) {
      list(role = xml2::xml_attr(e, "role"), name = xml2::xml_attr(e, "name"),
           regid = xml2::xml_attr(e, "regid"))
    }),
    product = xml2::xml_attr(meta, "product"),
    purl = attr_of(meta, "purl"),
    license = attr_of(meta, "license"),
    describedby = rel_href("describedby"),
    related = parity_strip_fragment(rel_href("related")),
    requires = requires
  )
}
