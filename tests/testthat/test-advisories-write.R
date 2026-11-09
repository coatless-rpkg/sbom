# The vulnerabilities of a CycloneDX XML document, as the JSON writer's lists.
xml_vulnerabilities <- function(txt) {
  doc <- xml2::read_xml(txt)
  xml2::xml_ns_strip(doc)
  text <- function(node, path) xml2::xml_text(xml2::xml_find_first(node, path))
  lapply(xml2::xml_find_all(doc, "/bom/vulnerabilities/vulnerability"), function(n) {
    has <- function(path) length(xml2::xml_find_all(n, path)) > 0L
    out <- list(
      `bom-ref` = xml2::xml_attr(n, "bom-ref"), id = text(n, "id"),
      source = list(name = text(n, "source/name"), url = text(n, "source/url"))
    )
    if (has("references")) {
      out$references <- lapply(xml2::xml_find_all(n, "references/reference"), function(r) {
        list(id = text(r, "id"), source = list(name = text(r, "source/name"), url = text(r, "source/url")))
      })
    }
    if (has("ratings")) {
      out$ratings <- lapply(xml2::xml_find_all(n, "ratings/rating"), function(r) {
        list(
          score = as.numeric(text(r, "score")), severity = text(r, "severity"),
          method = text(r, "method"), vector = text(r, "vector")
        )
      })
    }
    if (has("description")) out$description <- text(n, "description")
    if (has("advisories")) out$advisories <- list(list(url = text(n, "advisories/advisory/url")))
    if (has("published")) out$published <- text(n, "published")
    out$affects <- lapply(xml2::xml_find_all(n, "affects/target"), function(t) list(ref = text(t, "ref")))
    out
  })
}

# The description in the Meta element of `x`'s SWID tag: its notes.
swid_description <- function(x) {
  doc <- xml2::read_xml(swid_tag(x))
  xml2::xml_attr(xml2::xml_find_first(doc, "//*[local-name()='Meta']"), "description")
}

# The element of an SPDX 3 graph with spdxId `id`.
graph_element <- function(graph, id) {
  Find(function(e) identical(e$spdxId, id), graph)
}

# SPDX 3 elements with their ids, and the ids they name, as local names: the
# part after the namespace's "#".
local_names <- function(elements) {
  strip <- function(x) sub("^.*#", "", x)
  lapply(elements, function(e) {
    for (key in intersect(c("spdxId", "from"), names(e))) e[[key]] <- strip(e[[key]])
    if (!is.null(e$to)) e$to <- lapply(e$to, strip)
    e
  })
}

# The advisory elements of an SPDX 3 graph: the vulnerabilities and the
# hasAssociatedVulnerability relationships.
advisory_elements <- function(graph) {
  Filter(function(e) {
    identical(e$type, "security_Vulnerability") || identical(e$relationshipType, "hasAssociatedVulnerability")
  }, graph)
}

test_that("an SBOM with two advisories is valid in every format and version", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  x <- two_advisory_sbom()
  expect_identical(x$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"))
  expect_identical(nrow(x$advisories$ratings[[1]]), 1L)
  expect_valid_in_every_format(x, "two advisories")
  expected <- c(
    `cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
    `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "partial"
  )
  for (fv in every_format_version()) {
    tf <- withr::local_tempfile(fileext = fv$extension)
    write_sbom(x, tf, format = fv$format, version = fv$version)
    res <- validate_sbom(tf)
    label <- paste(fv$format, fv$version)
    expect_identical(schema_validate(tf, fv$format, fv$version)$status, expected[[fv$format]], label = label)
    expect_false("dangling-relationship" %in% res$findings$check, label = label)
  }
})

test_that("CycloneDX lists each advisory with R Observatory's fields, in JSON and XML", {
  x <- two_advisory_sbom()
  vulns <- jsonlite::fromJSON(cdx_json(x, "1.6"), simplifyVector = FALSE)$vulnerabilities
  expect_identical(vulns, list(
    list(
      `bom-ref` = "advisory/RSEC-9000-1",
      id = "RSEC-9000-1",
      source = list(name = "OSV", url = "https://osv.dev/vulnerability/RSEC-9000-1"),
      references = list(list(
        id = "CVE-2099-0001",
        source = list(name = "CVE", url = "https://www.cve.org/CVERecord?id=CVE-2099-0001")
      )),
      ratings = list(list(score = 8.8, severity = "high", method = "CVSSv3", vector = cvss_vector)),
      description = "Synthetic flaw in fakepkg",
      advisories = list(list(url = "https://example.org/r-advisory-database/vulns/fakepkg/RSEC-9000-1.yaml")),
      published = "2099-01-02T00:00:00Z",
      affects = list(list(ref = "pkg:cran/fakepkg@1.0.0"))
    ),
    list(
      `bom-ref` = "advisory/RSEC-9000-2",
      id = "RSEC-9000-2",
      source = list(name = "OSV", url = "https://osv.dev/vulnerability/RSEC-9000-2"),
      description = "Synthetic flaw in openpkg with no fix",
      published = "2099-02-01T00:00:00Z",
      affects = list(list(ref = "pkg:cran/openpkg@2.0"))
    )
  ))

  txt <- cdx_xml(x, "1.6")
  expect_identical(xml_vulnerabilities(txt), vulns)
  doc <- xml2::read_xml(txt)
  xml2::xml_ns_strip(doc)
  first <- xml2::xml_find_first(doc, "/bom/vulnerabilities/vulnerability")
  expect_identical(
    xml2::xml_name(xml2::xml_children(first)),
    c("id", "source", "references", "ratings", "description", "advisories", "published", "affects")
  )
  expect_identical(
    xml2::xml_name(xml2::xml_children(xml2::xml_find_first(first, "ratings/rating"))),
    c("score", "severity", "method", "vector")
  )
  expect_identical(xml2::xml_name(xml2::xml_children(xml2::xml_root(doc)))[4], "vulnerabilities")
})

test_that("CycloneDX keeps rated scores only, and names a method each version knows", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  x <- two_advisory_sbom()
  x$advisories$ratings[[2]] <- data.frame(
    upstream = c("CVE-2099-0002", "CVE-2099-0002", "CVE-2099-0002"),
    method = c("CVSSv4", "CVSSv4", "CVSSv3"),
    vector = c("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:4.0/AV:N", NA),
    score = c(9.3, NA, 5),
    severity = c("critical", NA, "Moderate"),
    stringsAsFactors = FALSE
  )
  for (v in cdx_versions) {
    ratings <- jsonlite::fromJSON(cdx_json(x, v), simplifyVector = FALSE)$vulnerabilities[[2]]$ratings
    expect_identical(ratings, list(
      list(
        score = 9.3, severity = "critical", method = if (v == "1.4") "other" else "CVSSv4",
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      ),
      list(score = 5L, method = "CVSSv3")
    ), label = v)
    for (f in c("cyclonedx-json", "cyclonedx-xml")) {
      tf <- withr::local_tempfile(fileext = format_registry()[[f]]$extension)
      write_sbom(x, tf, format = f, version = v)
      expect_identical(schema_validate(tf, f, v)$status, "pass", label = paste(f, v))
    }
  }
  expect_identical(
    xml2::xml_text(xml2::xml_find_all(xml2::read_xml(cdx_xml(x, "1.4")), "//*[local-name()='method']")),
    c("CVSSv3", "other", "CVSSv3")
  )
})

test_that("SPDX 2 gives each affected package an advisory reference, SECURITY in 2.3 and OTHER in 2.2", {
  x <- two_advisory_sbom()
  fixed <- paste(
    "RSEC-9000-1, Synthetic flaw in fakepkg.",
    "OSV lists fakepkg 1.0.0 among the versions it affects, fixed in 1.1.0."
  )
  open <- paste(
    "RSEC-9000-2, Synthetic flaw in openpkg with no fix.",
    "OSV lists openpkg 2.0 among the versions it affects, with no fix."
  )
  # SPDX 2.2 lists no SECURITY type but CPEs, so there the reference is OTHER.
  category <- c(`2.2` = "OTHER", `2.3` = "SECURITY")
  for (v in spdx_versions) {
    doc <- jsonlite::fromJSON(spdx_json(x, v), simplifyVector = FALSE)
    pkg <- function(name) Find(function(p) p$name == name, doc$packages)
    advisory <- function(name) Filter(function(r) r$referenceType == "advisory", pkg(name)$externalRefs)
    expect_identical(advisory("fakepkg"), list(list(
      referenceCategory = category[[v]], referenceType = "advisory",
      referenceLocator = "https://osv.dev/vulnerability/RSEC-9000-1", comment = fixed
    )), label = v)
    expect_identical(advisory("openpkg"), list(list(
      referenceCategory = category[[v]], referenceType = "advisory",
      referenceLocator = "https://osv.dev/vulnerability/RSEC-9000-2", comment = open
    )), label = v)
    expect_length(advisory("rootpkg"), 0L)
    # After the package manager reference.
    expect_identical(pkg("fakepkg")$externalRefs[[1]]$referenceType, "purl")

    tv <- strsplit(spdx_tv(x, v), "\n", fixed = TRUE)[[1]]
    at <- match(paste0("ExternalRef: ", category[[v]], " advisory https://osv.dev/vulnerability/RSEC-9000-1"), tv)
    expect_false(is.na(at), label = v)
    expect_identical(tv[[at + 1L]], paste0("ExternalRefComment: <text>", fixed, "</text>"), label = v)
    expect_true(paste0("ExternalRefComment: <text>", open, "</text>") %in% tv, label = v)
    if (v == "2.2") expect_false(any(grepl("SECURITY", tv, fixed = TRUE)))

    yaml <- strsplit(spdx_yaml(x, v), "\n", fixed = TRUE)[[1]]
    expect_true(any(grepl(paste0("referenceCategory: \"", category[[v]], "\""), yaml, fixed = TRUE)), label = v)
    expect_true(any(grepl(fixed, yaml, fixed = TRUE)), label = v)

    sx <- xml2::read_xml(spdx_xml(x, v))
    refs <- xml2::xml_find_all(sx, "//externalRefs[referenceType = 'advisory']")
    expect_identical(unique(xml2::xml_text(xml2::xml_find_all(refs, "referenceCategory"))), category[[v]], label = v)
    expect_true(fixed %in% xml2::xml_text(xml2::xml_find_all(refs, "comment")), label = v)
  }
})

test_that("an SPDX 2 advisory comment leaves out what OSV does not say", {
  x <- two_advisory_sbom()
  x$advisories$summary[[2]] <- NA_character_
  x$advisories$affects[[1]]$fixed <- NA_character_
  doc <- spdx_document(x)
  comment <- function(name) {
    refs <- Find(function(p) p$name == name, doc$packages)$externalRefs
    Find(function(r) r$referenceCategory == "SECURITY", refs)$comment
  }
  expect_identical(
    comment("fakepkg"),
    "RSEC-9000-1, Synthetic flaw in fakepkg. OSV lists fakepkg 1.0.0 among the versions it affects."
  )
  expect_identical(comment("openpkg"), "RSEC-9000-2. OSV lists openpkg 2.0 among the versions it affects, with no fix.")

  # Nor do CycloneDX and SPDX 3 give the summary.
  vulns <- cdx_document(x)$vulnerabilities
  expect_false("description" %in% names(vulns[[2]]))
  expect_true("description" %in% names(vulns[[1]]))
  expect_false(grepl("<description>Synthetic flaw in openpkg", cdx_xml(x), fixed = TRUE))
  v <- Filter(function(e) identical(e$type, "security_Vulnerability"), spdx3_document(x)[["@graph"]])
  expect_identical(vapply(v, `[[`, "", "name"), c("RSEC-9000-1", "RSEC-9000-2"))
  expect_false("summary" %in% names(v[[2]]))
  expect_true("summary" %in% names(v[[1]]))
})

test_that("SPDX 3 holds a vulnerability per advisory and a relationship per affected package", {
  skip_on_cran()
  x <- two_advisory_sbom()
  d <- spdx3_document(x)
  g <- d[["@graph"]]
  ns <- spdx_namespace(x)
  id <- function(local) paste0(ns, "#", local)
  v1 <- graph_element(g, id("advisory-RSEC-9000-1"))
  expect_identical(v1, list(
    type = "security_Vulnerability", spdxId = id("advisory-RSEC-9000-1"), creationInfo = "_:creationinfo",
    name = "RSEC-9000-1", summary = "Synthetic flaw in fakepkg",
    externalIdentifier = list(
      list(
        type = "ExternalIdentifier", externalIdentifierType = "securityOther", identifier = "RSEC-9000-1",
        identifierLocator = list("https://osv.dev/vulnerability/RSEC-9000-1")
      ),
      list(
        type = "ExternalIdentifier", externalIdentifierType = "cve", identifier = "CVE-2099-0001",
        identifierLocator = list("https://www.cve.org/CVERecord?id=CVE-2099-0001")
      )
    ),
    externalRef = list(list(
      type = "ExternalRef", externalRefType = "securityAdvisory",
      locator = list("https://example.org/r-advisory-database/vulns/fakepkg/RSEC-9000-1.yaml")
    )),
    security_publishedTime = "2099-01-02T00:00:00Z"
  ))
  v2 <- graph_element(g, id("advisory-RSEC-9000-2"))
  expect_identical(
    names(v2),
    c("type", "spdxId", "creationInfo", "name", "summary", "externalIdentifier", "security_publishedTime")
  )
  expect_length(v2$externalIdentifier, 1L)

  r1 <- graph_element(g, id("rel-advisory-RSEC-9000-1-1"))
  expect_identical(r1, list(
    type = "Relationship", spdxId = id("rel-advisory-RSEC-9000-1-1"), creationInfo = "_:creationinfo",
    comment = "OSV lists fakepkg 1.0.0 among the versions RSEC-9000-1 affects.",
    from = id("SPDXRef-cran-fakepkg"), relationshipType = "hasAssociatedVulnerability",
    to = list(id("advisory-RSEC-9000-1"))
  ))
  r2 <- graph_element(g, id("rel-advisory-RSEC-9000-2-1"))
  expect_identical(r2$comment, "OSV lists openpkg 2.0 among the versions RSEC-9000-2 affects.")
  expect_identical(r2$from, id("SPDXRef-cran-openpkg"))

  # In the graph's order, after the dependencies, and in both collections.
  types <- vapply(g, `[[`, "", "type")
  expect_identical(utils::tail(types, 6L), c(
    "security_Vulnerability", "Relationship", "security_Vulnerability", "Relationship", "software_Sbom", "SpdxDocument"
  ))
  ids <- unlist(lapply(g, `[[`, "spdxId"))
  expect_false(anyDuplicated(ids) > 0L)
  sbom_el <- unlist(g[[length(g) - 1L]]$element)
  doc_el <- unlist(g[[length(g)]]$element)
  advisory_ids <- id(c(
    "advisory-RSEC-9000-1", "rel-advisory-RSEC-9000-1-1", "advisory-RSEC-9000-2", "rel-advisory-RSEC-9000-2-1"
  ))
  expect_true(all(advisory_ids %in% sbom_el))
  expect_true(all(advisory_ids %in% doc_el))
  expect_identical(g[[length(g)]]$profileConformance, list("core", "software", "simpleLicensing", "security"))

  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld")
  write_sbom(x, tf)
  res <- validate_sbom(tf)
  expect_false("dangling-relationship" %in% res$findings$check)
})

test_that("SPDX 3 advisory ids are the OSV ids, made unique only when they collide", {
  skip_on_cran()
  x <- widgetframe_sbom()
  second <- x$advisories
  second$id <- "RSEC:2026-0"
  x$advisories <- rbind(x$advisories, second)
  g <- spdx3_document(x)[["@graph"]]
  locals <- sub("^.*#", "", vapply(advisory_elements(g), `[[`, "", "spdxId"))
  expect_identical(locals, c(
    "advisory-RSEC-2026-0", "rel-advisory-RSEC-2026-0-1", "advisory-RSEC:2026-0", "rel-advisory-RSEC:2026-0-1"
  ))
  v <- advisory_elements(g)[[3]]
  expect_identical(v$name, "RSEC:2026-0")
  expect_identical(v$externalIdentifier[[1]]$identifierLocator, list("https://osv.dev/vulnerability/RSEC%3A2026-0"))
  expect_identical(advisory_elements(g)[[4]]$to, list(v$spdxId))
  vulns <- cdx_document(x)$vulnerabilities
  expect_identical(vapply(vulns, `[[`, "", "id"), c("RSEC-2026-0", "RSEC:2026-0"))
  expect_identical(vulns[[2]]$source$url, "https://osv.dev/vulnerability/RSEC%3A2026-0")

  # Two rows with one id, and an id that is not an OSV id, as a read document
  # could hold: unique, and only IRI-fragment characters.
  y <- widgetframe_sbom()
  odd <- y$advisories
  odd$id <- "bad id#1"
  y$advisories <- rbind(y$advisories, y$advisories, odd)
  g <- spdx3_document(y)[["@graph"]]
  locals <- sub("^[^#]*#", "", vapply(advisory_elements(g), `[[`, "", "spdxId"))
  expect_identical(locals, c(
    "advisory-RSEC-2026-0", "rel-advisory-RSEC-2026-0-1", "advisory-RSEC-2026-0-2", "rel-advisory-RSEC-2026-0-1-2",
    "advisory-bad-id-1", "rel-advisory-bad-id-1-1"
  ))
  ids <- unlist(lapply(g, `[[`, "spdxId"))
  expect_false(anyDuplicated(ids) > 0L)

  # An OSV id with a colon is valid in every format.
  skip_if_not_installed("jsonvalidate")
  expect_valid_in_every_format(x, "colon id")
  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld")
  write_sbom(x, tf)
  expect_false("dangling-relationship" %in% validate_sbom(tf)$findings$check)
})

test_that("SWID says it has no place for advisories instead of the notes that list them", {
  x <- two_advisory_sbom()
  description <- swid_description(x)
  expect_true(grepl(swid_note, description, fixed = TRUE))
  expect_false(grepl("Advisories are those OSV lists", description, fixed = TRUE))
  expect_false(grepl("Advisory data is OSV's CRAN export", description, fixed = TRUE))
  expect_false(grepl("RSEC-9000", swid_tag(x), fixed = TRUE))
  # In the place of the first note it replaces.
  notes <- x$metadata$notes
  kept <- notes[seq_len(match(listed_note, notes) - 1L)]
  expect_true(startsWith(description, paste(c(kept, swid_note), collapse = " ")))

  # So do the advisory issues, which speak of what the advisories list.
  w <- x
  w$issues <- add_issue(
    w$issues, w$metadata$root, "advisories", "advisories-not-compared",
    paste(
      "OSV's advisories could not all be compared with the version of 1 package (twopkg),",
      "so this file may not list every advisory for it."
    ),
    severity = "info"
  )
  w$issues <- add_issue(
    w$issues, w$metadata$root, "advisories", "advisories-ratings-unavailable",
    "The CVSS rating of 1 upstream record could not be looked up, so it is not listed (\"CVE-2099-0001\").",
    severity = "info"
  )
  w$issues <- add_issue(
    w$issues, w$metadata$root, "advisories", "advisories-no-exact-version",
    "1 package has no exact version, so OSV's advisories were not looked up for it (minpkg).",
    severity = "info"
  )
  for (text in c("could not all be compared", "could not be looked up", "no exact version")) {
    expect_true(grepl(text, spdx_document(w)$comment, fixed = TRUE), label = text)
    expect_false(grepl(text, swid_description(w), fixed = TRUE), label = text)
  }
  expect_true(grepl(swid_note, swid_description(w), fixed = TRUE))
  # The other issues stay.
  expect_true(grepl("rootpkg 0.1.0 names no maintainer.", swid_description(w), fixed = TRUE))

  # The Bioconductor note goes too.
  y <- x
  y$metadata$notes <- append(y$metadata$notes, "The advisory database does not cover Bioconductor packages yet.",
                             after = match(listed_note, y$metadata$notes))
  expect_false(grepl("Bioconductor", swid_description(y), fixed = TRUE))
  expect_identical(lengths(gregexpr(swid_note, swid_description(y), fixed = TRUE)), 1L)

  # Without listed advisories, the notes are as they were.
  z <- minimal_sbom()
  z$metadata$notes <- c("A note.", "No advisory data was on hand for this file, so it lists no advisories.")
  expect_identical(swid_description(z), paste(z$metadata$notes, collapse = " "))
  z$metadata$advisories$status <- "unavailable"
  expect_identical(swid_description(z), paste(z$metadata$notes, collapse = " "))
})

test_that("every document that says advisories are listed lists every advisory", {
  skip_on_cran()
  x <- two_advisory_sbom()
  ids <- x$advisories$id
  for (fv in every_format_version()) {
    txt <- written(x, fv$format, fv$version)
    label <- paste(fv$format, fv$version)
    if (fv$format == "swid") {
      expect_false(grepl(listed_note, txt, fixed = TRUE), label = label)
      expect_true(grepl(swid_note, txt, fixed = TRUE), label = label)
      next
    }
    expect_true(grepl(listed_note, txt, fixed = TRUE), label = label)
    for (id in ids) {
      expect_true(grepl(id, txt, fixed = TRUE), label = paste(label, id))
    }
  }
})

test_that("advisories are written in id order, each package in ref order", {
  skip_on_cran()
  x <- two_advisory_sbom()
  shuffled <- x
  shuffled$advisories <- x$advisories[2:1, ]
  for (fv in every_format_version()) {
    expect_identical(written(shuffled, fv$format, fv$version), written(x, fv$format, fv$version),
                     label = paste(fv$format, fv$version))
  }

  y <- widgetframe_sbom()
  y$components <- rbind(y$components, component_row(
    ref = "pkg:cran/abc@1.0", name = "abc", version = "1.0", version_is = "exact",
    type = "library", ecosystem = "cran", purl = "pkg:cran/abc@1.0"
  ))
  y$advisories$affects[[1]] <- rbind(
    y$advisories$affects[[1]],
    data.frame(ref = "pkg:cran/abc@1.0", version = "1.0", fixed = "1.1", no_fix = FALSE, stringsAsFactors = FALSE)
  )
  refs <- vapply(cdx_document(y)$vulnerabilities[[1]]$affects, `[[`, "", "ref")
  expect_identical(refs, c("pkg:cran/abc@1.0", "pkg:cran/widgetframe@0.3.1"))
  rels <- Filter(function(e) identical(e$relationshipType, "hasAssociatedVulnerability"), spdx3_document(y)[["@graph"]])
  expect_identical(vapply(rels, `[[`, "", "comment"), c(
    "OSV lists abc 1.0 among the versions RSEC-2026-0 affects.",
    "OSV lists widgetframe 0.3.1 among the versions RSEC-2026-0 affects."
  ))
})

test_that("advisories match R Observatory's RSEC-2026-0 on widgetframe 0.3.1", {
  x <- widgetframe_sbom()
  theirs <- jsonlite::read_json(test_path("fixtures", "r-observatory", "advisory-RSEC-2026-0.cdx.json"))
  ours <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)$vulnerabilities
  expect_identical(ours, theirs)
  expect_identical(xml_vulnerabilities(cdx_xml(x)), theirs)

  theirs <- jsonlite::read_json(test_path("fixtures", "r-observatory", "advisory-RSEC-2026-0.spdx3.json"))
  ours <- advisory_elements(jsonlite::fromJSON(spdx3_jsonld(x), simplifyVector = FALSE)[["@graph"]])
  expect_identical(local_names(ours), local_names(theirs))
})

test_that("an SBOM without advisories writes no advisory fields", {
  skip_on_cran()
  # As before advisories existed: no table and no status.
  for (x in list(fixture_sbom(), minimal_sbom())) {
    before <- x
    before$advisories <- NULL
    before$metadata$advisories <- NULL
    for (fv in every_format_version()) {
      expect_identical(written(x, fv$format, fv$version), written(before, fv$format, fv$version),
                       label = paste(fv$format, fv$version))
    }
  }

  # Listed, but none matched.
  x <- minimal_sbom()
  x$metadata$advisories$status <- "listed"
  expect_null(cdx_document(x)$vulnerabilities)
  expect_false(grepl("<vulnerabilities", cdx_xml(x), fixed = TRUE))
  expect_false(grepl("SECURITY", spdx_tv(x), fixed = TRUE))
  doc <- spdx3_document(x)[["@graph"]]
  expect_length(advisory_elements(doc), 0L)
  expect_identical(doc[[length(doc)]]$profileConformance, list("core", "software", "simpleLicensing"))
  # Without the notes that say so, the tag still says it has no place for them.
  expect_identical(swid_description(x), swid_note)
})

test_that("an advisory names only components the document holds", {
  x <- widgetframe_sbom()
  x$advisories$affects[[1]]$ref <- "pkg:cran/gone@1.0"
  expect_null(cdx_document(x)$vulnerabilities)
  expect_length(advisory_elements(spdx3_document(x)[["@graph"]]), 0L)
  expect_false(grepl("SECURITY", spdx_tv(x), fixed = TRUE))
})

test_that("a source URL that cannot be an IRI reference is left out", {
  skip_if_not_installed("jsonvalidate")
  x <- widgetframe_sbom()
  x$advisories$source_url <- "https://example.org/a b"
  expect_null(cdx_document(x)$vulnerabilities[[1]]$advisories)
  v <- Find(function(e) identical(e$type, "security_Vulnerability"), spdx3_document(x)[["@graph"]])
  expect_null(v$externalRef)
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf)
  expect_identical(schema_validate(tf, "cyclonedx-json")$status, "pass")
})

test_that("a publication date that is not a calendar date is left out of every format", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  # As OSV's export could give them: a record whose published time is not a
  # real date.
  osv <- osv_read_zip(test_path("fixtures", "osv", "all.zip"), "all.zip")
  bad <- c(`RSEC-9000-1` = "2026-13-45T00:00:00Z", `RSEC-9000-2` = "2026-02-30T00:00:00Z")
  osv$records$published[match(names(bad), osv$records$id)] <- unname(bad)
  local_mocked_bindings(osv_fetch = function(...) c(osv, list(fetched = as.POSIXct(NA, tz = "UTC"))))
  x <- two_package_sbom(advisories = test_path("fixtures", "osv", "all.zip"))
  expect_identical(x$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"))
  expect_identical(x$advisories$published, c(NA_character_, NA_character_))
  expect_identical(sbom_advisories(x)$published, c(NA_character_, NA_character_))

  vulns <- cdx_document(x)$vulnerabilities
  expect_false(any(vapply(vulns, function(v) "published" %in% names(v), logical(1))))
  v <- Filter(function(e) identical(e$type, "security_Vulnerability"), spdx3_document(x)[["@graph"]])
  expect_false(any(vapply(v, function(e) "security_publishedTime" %in% names(e), logical(1))))
  expect_valid_in_every_format(x, "bad dates")
  for (v in cdx_versions) {
    for (f in c("cyclonedx-json", "cyclonedx-xml")) {
      tf <- withr::local_tempfile(fileext = format_registry()[[f]]$extension)
      write_sbom(x, tf, format = f, version = v)
      expect_identical(schema_validate(tf, f, v)$status, "pass", label = paste(f, v))
    }
  }

  # The same dates written by hand are left out too, and real ones are kept.
  y <- widgetframe_sbom()
  for (date in c("2026-13-45", "2026-02-30", "2026-2-18", "2026-02-18x")) {
    y$advisories$published <- date
    expect_null(cdx_document(y)$vulnerabilities[[1]]$published, label = date)
  }
  y$advisories$published <- "2024-02-29"
  expect_identical(cdx_document(y)$vulnerabilities[[1]]$published, "2024-02-29T00:00:00Z")
})

test_that("the sentences sbom writes about advisories never imply that a package is safe", {
  x <- two_advisory_sbom()
  spdx2 <- unlist(lapply(spdx_document(x)$packages, function(p) {
    vapply(Filter(function(r) r$referenceCategory == "SECURITY", p$externalRefs), `[[`, "", "comment")
  }))
  spdx3 <- vapply(advisory_elements(spdx3_document(x)[["@graph"]]), function(e) {
    if (is.null(e$comment)) "" else e$comment
  }, "")
  sentences <- c(spdx2, spdx3, swid_note)
  expect_length(spdx2, 2L)
  expect_false(any(grepl(safety_words, sentences, perl = TRUE)))
})
