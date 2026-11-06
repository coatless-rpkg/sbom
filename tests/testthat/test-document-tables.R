tp <- function(...) test_path("fixtures", "third-party", ...)

# A data frame of the given character columns, as document_tables() builds
# its tables.
chr_frame <- function(...) data.frame(..., stringsAsFactors = FALSE)

# The tables without the raw column, which differs between the models of one
# document in different serializations.
without_raw <- function(tables) {
  tables$elements$raw <- NULL
  tables
}

# The tables of a document whose text is `text`, written to a file with the
# extension `fileext`.
tables_of <- function(text, fileext) {
  tf <- withr::local_tempfile(fileext = fileext, .local_envir = parent.frame())
  write_text(text, tf)
  document_tables(read_document(tf))
}

test_that("JSON pointers escape ~ and / in keys", {
  expect_identical(json_pointer("", "@graph", 12L), "/@graph/12")
  expect_identical(json_pointer("/x", c("a/b", "m~n", "~1")), c("/x/a~1b", "/x/m~0n", "/x/~01"))
  expect_identical(json_pointer("/p", "k", 0:1), c("/p/k/0", "/p/k/1"))
})

test_that("CycloneDX components nested three deep get their parents, and metadata.component is the root", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"timestamp":"2026-11-06T01:02:03Z",',
    '"component":{"type":"application","bom-ref":"app","name":"app","version":"1.0",',
    '"components":[{"type":"library","bom-ref":"inner","name":"inner","version":"0.1"}]}},',
    '"components":[',
    '{"type":"library","bom-ref":"a","name":"a","version":"1","components":[',
    '{"type":"library","bom-ref":"a1","name":"a1","version":"1","components":[',
    '{"type":"library","bom-ref":"a11","name":"a11","version":"1"}]},',
    '{"type":"framework","bom-ref":"a2","name":"a2","version":"1","scope":"optional"}]},',
    '{"type":"library","bom-ref":"b","name":"b","version":"2"}],',
    '"dependencies":[{"ref":"app","dependsOn":["a","b"]},{"ref":"b"},{"ref":"a","dependsOn":[],"provides":["a1"]}]}\n'
  ), ".cdx.json")
  el <- t$elements
  expect_identical(el$location, c(
    "/metadata/component", "/metadata/component/components/0", "/components/0",
    "/components/0/components/0", "/components/0/components/0/components/0",
    "/components/0/components/1", "/components/1"
  ))
  expect_identical(el$id, c("app", "inner", "a", "a1", "a11", "a2", "b"))
  # A parent is named by its location, since it may have no bom-ref.
  expect_identical(el$parent, c(
    NA, "/metadata/component", NA, "/components/0", "/components/0/components/0", "/components/0", NA
  ))
  expect_identical(el$is_root, c(TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE))
  expect_identical(el$kind, rep("component", 7))
  expect_identical(el$type, c("application", "library", "library", "library", "library", "framework", "library"))
  expect_identical(el$scope, c(NA, NA, NA, NA, NA, "optional", NA))
  expect_identical(el$raw[[4]]$name, "a1")
  expect_identical(t$document$root, "app")
  expect_identical(t$document$root_location, "/metadata/component")
  expect_identical(t$document$timestamp, "2026-11-06T01:02:03Z")
  expect_identical(t$document$timestamp_location, "/metadata/timestamp")
  # Nesting is "contains"; an entry that lists no dependency gives one row
  # with no target, so that the tables record that it was stated.
  expect_identical(t$relationships, chr_frame(
    location = c(
      "/metadata/component/components/0", "/components/0/components/0",
      "/components/0/components/0/components/0", "/components/0/components/1",
      "/dependencies/0/dependsOn/0", "/dependencies/0/dependsOn/1", "/dependencies/1",
      "/dependencies/2/provides/0"
    ),
    from = c("app", "a", "a1", "a", "app", "app", "b", "a"),
    to = c("inner", "a1", "a11", "a2", "a", "b", NA, "a1"),
    type = c("contains", "contains", "contains", "contains", "dependsOn", "dependsOn", "dependsOn", "provides")
  ))
})

test_that("a metadata.component without a bom-ref is still the root", {
  t <- document_tables(read_document(tp("cyclonedx", "valid-bom-1.6.json")))
  el <- t$elements
  expect_identical(el$location[el$is_root], "/metadata/component")
  expect_identical(el$id[el$is_root], NA_character_)
  expect_identical(el$name[el$is_root], "Acme Application")
  expect_identical(t$document$root, NA_character_)
  expect_identical(t$document$root_location, "/metadata/component")
  # The legacy author string is the originator; swid gives an identifier.
  expect_identical(el$originator[el$is_root], "Acme Super Heros")
  expect_identical(el$identifiers[el$is_root], list("swid:swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"))
  expect_identical(t$document$tools, chr_frame(name = "Awesome Tool", version = "9.1.2"))
  # The deprecated array of tools gives a tool author.
  expect_identical(t$document$authors$name, c("Samantha Wright", "Acme, Inc.", "Awesome Tool"))
  expect_identical(t$document$authors$kind, c("person", "organization", "tool"))
  expect_identical(t$document$authors$location, c("/metadata/authors/0", "/metadata/manufacturer", "/metadata/tools/0"))
})

test_that("CycloneDX licenses, purls, suppliers and originators are read", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,',
    '"metadata":{"tools":{"components":[{"type":"application","name":"maker","version":"2.0"}],',
    '"services":[{"name":"scanner","version":"1"}]},',
    '"properties":[{"name":"sbom:note","value":"First."},{"name":"other","value":"x"},{"name":"sbom:note","value":"Second."}]},',
    '"components":[',
    '{"type":"library","bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1","cpe":"cpe:2.3:a:x:a:1:*:*:*:*:*:*:*",',
    '"supplier":{"name":"Sup"},"manufacturer":{"name":"Maker"},"publisher":"Pub",',
    '"licenses":[{"license":{"id":"MIT"}},{"license":{"name":"Custom"}}]},',
    '{"type":"library","bom-ref":"b","name":"b","publisher":"Pub","authors":[{"name":"Ann"}],',
    '"licenses":[{"expression":"Apache-2.0 OR MIT"}]},',
    '{"type":"library","bom-ref":"c","name":"c","authors":[{"name":"Ann"}]}]}\n'
  ), ".cdx.json")
  el <- t$elements
  expect_identical(el$supplier, c("Sup", NA, NA))
  expect_identical(el$originator, c("Maker", "Pub", "Ann"))
  expect_identical(el$purl, c("pkg:npm/a@1", NA, NA))
  expect_identical(el$identifiers, list(
    c("purl:pkg:npm/a@1", "cpe:cpe:2.3:a:x:a:1:*:*:*:*:*:*:*"), character(), character()
  ))
  expect_identical(t$purls, chr_frame(location = "/components/0/purl", id = "a", purl = "pkg:npm/a@1"))
  expect_identical(t$licenses, chr_frame(
    location = c(
      "/components/0/licenses/0/license/id", "/components/0/licenses/1/license/name",
      "/components/1/licenses/0/expression"
    ),
    id = c("a", "a", "b"),
    expression = c("MIT", "Custom", "Apache-2.0 OR MIT"),
    kind = c("expression", "name", "expression"),
    field = "licenses"
  ))
  expect_identical(t$document$tools, chr_frame(name = c("maker", "scanner"), version = c("2.0", "1")))
  expect_identical(t$document$notes, c("First.", "Second."))
  expect_identical(t$document$root, character())
  expect_identical(t$document$root_location, character())
  expect_identical(t$document$timestamp, NA_character_)
  expect_identical(t$document$authors$kind, c("tool", "tool"))
})

test_that("CycloneDX tools are authors of kind tool, after the people and the organization", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{',
    '"authors":[{"name":"Ann"}],"manufacturer":{"name":"Acme"},',
    '"tools":{"components":[{"type":"application","name":"maker","version":"2.0"},{"type":"application"}],',
    '"services":[{"name":"scanner","version":"1"}]}}}\n'
  ), ".cdx.json")
  expect_identical(t$document$authors, chr_frame(
    name = c("Ann", "Acme", "maker", "scanner"), kind = c("person", "organization", "tool", "tool"),
    location = c("/metadata/authors/0", "/metadata/manufacturer", "/metadata/tools/components/0", "/metadata/tools/services/0")
  ))
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"metadata":{',
    '"tools":[{"vendor":"Acme","name":"maker","version":"2.0"},{"name":"other"}]}}\n'
  ), ".cdx.json")
  expect_identical(t$document$authors, chr_frame(
    name = c("maker", "other"), kind = "tool", location = c("/metadata/tools/0", "/metadata/tools/1")
  ))
})

test_that("CycloneDX XML gives the tables of its JSON twin", {
  for (stem in c("valid-bom-1.6", "valid-dependency-1.6", "valid-license-expression-1.6", "valid-metadata-tool-1.6")) {
    json <- document_tables(read_document(tp("cyclonedx", paste0(stem, ".json"))))
    xml <- document_tables(read_document(tp("cyclonedx", paste0(stem, ".xml"))))
    expect_identical(without_raw(xml), without_raw(json), label = stem)
  }
})

test_that("the SPDX 2.3 example gives its packages, files, snippets, licenses and relationships", {
  d <- read_document(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  t <- document_tables(d)
  el <- t$elements
  expect_identical(el$location, c(sprintf("/packages/%d", 0:3), sprintf("/files/%d", 0:4), "/snippets/0"))
  expect_identical(el$id, c(
    "SPDXRef-Package", "SPDXRef-fromDoap-1", "SPDXRef-fromDoap-0", "SPDXRef-Saxon",
    "SPDXRef-DoapSource", "SPDXRef-CommonsLangSrc", "SPDXRef-JenaLib", "SPDXRef-Specification",
    "SPDXRef-File", "SPDXRef-Snippet"
  ))
  expect_identical(el$kind, c(rep("component", 4), rep("file", 5), "snippet"))
  expect_identical(el$name, c(
    "glibc", "Apache Commons Lang", "Jena", "Saxon", "./src/org/spdx/parser/DOAPProject.java",
    "./lib-source/commons-lang3-3.1-sources.jar", "./lib-source/jena-2.6.3-sources.jar",
    "./docs/myspec.pdf", "./package/foo.c", "from linux kernel"
  ))
  expect_identical(el$version, c("2.11.1", NA, "3.12.0", "8.8", rep(NA, 6)))
  expect_identical(el$supplier, c("Jane Doe (jane.doe@example.com)", rep(NA, 9)))
  expect_identical(el$originator, c("ExampleCodeInspect (contact@example.com)", rep(NA, 9)))
  expect_identical(el$type, c("SOURCE", rep(NA, 9)))
  expect_identical(el$purl, c(NA, NA, "pkg:maven/org.apache.jena/apache-jena@3.12.0", rep(NA, 7)))
  expect_identical(el$identifiers, c(
    list("cpe:cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*"),
    list(character()), list("purl:pkg:maven/org.apache.jena/apache-jena@3.12.0"),
    rep(list(character()), 7)
  ))
  expect_identical(el$is_root, c(TRUE, rep(FALSE, 7), TRUE, FALSE))
  expect_identical(el$parent, rep(NA_character_, 10))
  expect_identical(t$purls, chr_frame(
    location = "/packages/2/externalRefs/0/referenceLocator", id = "SPDXRef-fromDoap-0",
    purl = "pkg:maven/org.apache.jena/apache-jena@3.12.0"
  ))
  expect_identical(t$licenses, chr_frame(
    location = c(
      "/packages/0/licenseConcluded", "/packages/0/licenseDeclared",
      sprintf("/packages/0/licenseInfoFromFiles/%d", 0:2),
      "/packages/1/licenseConcluded", "/packages/1/licenseDeclared",
      "/packages/3/licenseConcluded", "/packages/3/licenseDeclared",
      "/files/0/licenseConcluded", "/files/0/licenseInfoInFiles/0",
      "/files/1/licenseConcluded", "/files/1/licenseInfoInFiles/0",
      "/files/2/licenseConcluded", "/files/2/licenseInfoInFiles/0",
      "/files/4/licenseConcluded", "/files/4/licenseInfoInFiles/0", "/files/4/licenseInfoInFiles/1",
      "/snippets/0/licenseConcluded", "/snippets/0/licenseInfoInSnippets/0"
    ),
    id = c(
      rep("SPDXRef-Package", 5), rep("SPDXRef-fromDoap-1", 2), rep("SPDXRef-Saxon", 2),
      rep("SPDXRef-DoapSource", 2), rep("SPDXRef-CommonsLangSrc", 2), rep("SPDXRef-JenaLib", 2),
      rep("SPDXRef-File", 3), rep("SPDXRef-Snippet", 2)
    ),
    expression = c(
      "(LGPL-2.0-only OR LicenseRef-3)", "(LGPL-2.0-only AND LicenseRef-3)",
      "GPL-2.0-only", "LicenseRef-2", "LicenseRef-1", "NOASSERTION", "NOASSERTION",
      "MPL-1.0", "MPL-1.0", "Apache-2.0", "Apache-2.0", "Apache-2.0", "Apache-2.0",
      "LicenseRef-1", "LicenseRef-1", "(LGPL-2.0-only OR LicenseRef-2)", "GPL-2.0-only",
      "LicenseRef-2", "GPL-2.0-only", "GPL-2.0-only"
    ),
    kind = rep("expression", 20),
    field = c(
      "licenseConcluded", "licenseDeclared", rep("licenseInfoFromFiles", 3),
      rep(c("licenseConcluded", "licenseDeclared"), 2),
      rep(c("licenseConcluded", "licenseInfoInFiles"), 3),
      "licenseConcluded", "licenseInfoInFiles", "licenseInfoInFiles",
      "licenseConcluded", "licenseInfoInSnippets"
    )
  ))
  rel <- t$relationships
  expect_identical(rel[rel$type == "DESCRIBES", ], chr_frame(
    location = c("/documentDescribes/0", "/documentDescribes/1"),
    from = "SPDXRef-DOCUMENT", to = c("SPDXRef-File", "SPDXRef-Package"), type = "DESCRIBES"
  ))
  expect_identical(rel$location[startsWith(rel$location, "/relationships/")], sprintf("/relationships/%d", 0:6))
  expect_identical(
    rel[rel$location %in% c("/relationships/1", "/relationships/3"), c("from", "to", "type")],
    chr_frame(
      from = c("SPDXRef-DOCUMENT", "SPDXRef-CommonsLangSrc"),
      to = c("DocumentRef-spdx-tool-1.2:SPDXRef-ToolsElement", "NOASSERTION"),
      type = c("COPY_OF", "GENERATED_FROM")
    ),
    ignore_attr = "row.names"
  )
  has_files <- rel[startsWith(rel$location, "/packages/0/hasFiles/"), ]
  expect_identical(has_files$location, sprintf("/packages/0/hasFiles/%d", 0:13))
  expect_identical(unique(has_files$from), "SPDXRef-Package")
  expect_identical(unique(has_files$type), "CONTAINS")
  expect_identical(has_files$to, unlist(d$doc$packages[[1]]$hasFiles))
  expect_identical(nrow(rel), 2L + 7L + 14L)

  doc <- t$document
  expect_identical(doc$name, "SPDX-Tools-v2.0")
  expect_identical(doc$timestamp, "2010-01-29T18:30:22Z")
  expect_identical(doc$timestamp_location, "/creationInfo/created")
  expect_identical(doc$authors, chr_frame(
    name = c("LicenseFind-1.0", "ExampleCodeInspect", "Jane Doe"),
    kind = c("tool", "organization", "person"),
    location = sprintf("/creationInfo/creators/%d", 0:2)
  ))
  expect_identical(doc$tools, chr_frame(name = "LicenseFind", version = "1.0"))
  expect_identical(doc$root, c("SPDXRef-File", "SPDXRef-Package"))
  expect_identical(doc$root_location, c("/documentDescribes/0", "/documentDescribes/1"))
  expect_identical(doc$notes, "This document was created using SPDX 2.0 using licenses from the web site.")
  expect_identical(
    doc$defined_refs,
    c("LicenseRef-1", "LicenseRef-2", "LicenseRef-4", "LicenseRef-Beerware-4.2", "LicenseRef-3")
  )
  expect_identical(doc$external_ids, "DocumentRef-spdx-tool-1.2")
  expect_identical(doc$ids, c("SPDXRef-DOCUMENT", el$id))
})

test_that("SPDX 2 suppliers, purls and CPEs follow the field rules", {
  d <- read_document(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  d$doc$packages[[2]]$supplier <- "NOASSERTION"
  d$doc$packages[[2]]$originator <- "Organization: Apache"
  d$doc$packages[[4]]$supplier <- "Organization: Saxonica"
  ref <- function(category, type, locator) {
    list(referenceCategory = category, referenceType = type, referenceLocator = locator)
  }
  d$doc$packages[[4]]$externalRefs <- list(
    ref("SECURITY", "cpe22Type", "cpe:/a:saxonica:saxon:8.8"),
    ref("PACKAGE-MANAGER", "maven-central", "net.sf.saxon:saxon:8.8"),
    ref("PACKAGE_MANAGER", "purl", "pkg:maven/net.sf.saxon/saxon@8.8"),
    ref("SECURITY", "cpe23Type", "cpe:2.3:a:saxonica:saxon:8.8:*:*:*:*:*:*:*"),
    ref("PACKAGE-MANAGER", "purl", "pkg:generic/saxon@8.8"),
    ref("OTHER", "purl", "pkg:generic/not-a-package-manager-ref@1"),
    # SPDX 2.3 Annex F's swid locator is a swid: URI.
    ref("SECURITY", "swid", "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c")
  )
  t <- document_tables(d)
  el <- t$elements
  expect_identical(el$supplier[1:4], c("Jane Doe (jane.doe@example.com)", NA, NA, "Saxonica"))
  expect_identical(el$originator[1:4], c("ExampleCodeInspect (contact@example.com)", "Apache", NA, NA))
  expect_identical(el$purl[4], "pkg:maven/net.sf.saxon/saxon@8.8")
  expect_identical(el$identifiers[[4]], c(
    "cpe:cpe:/a:saxonica:saxon:8.8", "purl:pkg:maven/net.sf.saxon/saxon@8.8",
    "cpe:cpe:2.3:a:saxonica:saxon:8.8:*:*:*:*:*:*:*", "purl:pkg:generic/saxon@8.8",
    "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c"
  ))
  expect_identical(t$purls, chr_frame(
    location = c(
      "/packages/2/externalRefs/0/referenceLocator", "/packages/3/externalRefs/2/referenceLocator",
      "/packages/3/externalRefs/4/referenceLocator"
    ),
    id = c("SPDXRef-fromDoap-0", "SPDXRef-Saxon", "SPDXRef-Saxon"),
    purl = c(
      "pkg:maven/org.apache.jena/apache-jena@3.12.0", "pkg:maven/net.sf.saxon/saxon@8.8",
      "pkg:generic/saxon@8.8"
    )
  ))
})

test_that("an SPDX 2 root may be stated by DESCRIBED_BY", {
  d <- read_document(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  d$doc$documentDescribes <- NULL
  d$doc$relationships <- c(d$doc$relationships, list(list(
    spdxElementId = "SPDXRef-Saxon", relationshipType = "DESCRIBED_BY", relatedSpdxElement = "SPDXRef-DOCUMENT"
  )))
  t <- document_tables(d)
  expect_identical(t$document$root, "SPDXRef-Saxon")
  expect_identical(t$document$root_location, "/relationships/7")
  expect_identical(t$elements$id[t$elements$is_root], "SPDXRef-Saxon")
})

test_that("empty documents give empty tables of the documented shape", {
  shape <- function(t) {
    list(
      elements = vapply(t$elements, function(col) class(col)[1], ""),
      licenses = vapply(t$licenses, class, ""), purls = vapply(t$purls, class, ""),
      relationships = vapply(t$relationships, class, ""),
      rows = vapply(t[c("elements", "licenses", "purls", "relationships")], nrow, 0L),
      document = names(t$document), authors = vapply(t$document$authors, class, ""),
      tools = vapply(t$document$tools, class, "")
    )
  }
  chr <- function(...) stats::setNames(rep("character", length(c(...))), c(...))
  expected <- list(
    elements = c(
      chr("location", "id", "kind", "name", "version", "supplier", "originator", "purl"),
      identifiers = "list", chr("type", "scope"), is_root = "logical", parent = "character", raw = "list"
    ),
    licenses = chr("location", "id", "expression", "kind", "field"),
    purls = chr("location", "id", "purl"),
    relationships = chr("location", "from", "to", "type"),
    rows = c(elements = 0L, licenses = 0L, purls = 0L, relationships = 0L),
    document = c(
      "name", "timestamp", "timestamp_location", "authors", "tools", "root", "root_location",
      "notes", "defined_refs", "external_ids", "ids"
    ),
    authors = chr("name", "kind", "location"),
    tools = chr("name", "version")
  )
  docs <- list(
    cdx = tables_of('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}\n', ".cdx.json"),
    spdx = tables_of('{"spdxVersion":"SPDX-2.3"}\n', ".spdx.json"),
    spdx3 = tables_of('{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}\n', ".spdx3.json")
  )
  for (name in names(docs)) {
    expect_identical(shape(docs[[name]]), expected, label = name)
    expect_identical(docs[[name]]$document$root, character(), label = name)
  }
  expect_identical(docs$cdx$document$ids, character())
  expect_identical(docs$spdx$document$ids, "SPDXRef-DOCUMENT")
  expect_identical(docs$spdx3$document$ids, character())
  # A SWID tag is always its own element.
  swid <- tables_of(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="x" tagId="t"/>\n'
  ), ".swidtag")
  expect_identical(swid$elements$id, "t")
  expect_identical(swid$document$ids, "t")
  expect_identical(
    vapply(swid[c("licenses", "purls", "relationships")], nrow, 0L),
    c(licenses = 0L, purls = 0L, relationships = 0L)
  )
  expect_identical(nrow(swid$document$authors), 0L)
})

test_that("the four serializations of the SPDX 2.3 example give the same tables", {
  skip_if_not_installed("yaml")
  read <- function(file) without_raw(document_tables(read_document(tp("spdx-2.3", file))))
  json <- read("SPDXJSONExample-v2.3.spdx.json")
  expect_identical(read("SPDXYAMLExample-2.3.spdx.yaml"), json)
  expect_identical(read("SPDXXMLExample-v2.3.spdx.xml"), json)
  # The tag-value example lists its files in another order, and states its
  # roots and the package's files as relationships.
  tv <- read("SPDXTagExample-v2.3.spdx")
  sorted <- function(el) el[order(el$id, method = "radix"), setdiff(names(el), "location")]
  expect_identical(sorted(tv$elements), sorted(json$elements), ignore_attr = "row.names")
  expect_identical(tv$document$root, json$document$root)
  expect_identical(tv$document[c("name", "timestamp", "authors", "tools", "notes", "defined_refs", "external_ids")],
    json$document[c("name", "timestamp", "authors", "tools", "notes", "defined_refs", "external_ids")])
})

test_that("an SPDX 3 graph with a blank-node creationInfo is read", {
  t <- document_tables(read_document(tp("spdx-3", "package_sbom.json")))
  el <- t$elements
  expect_identical(el$location, c("/@graph/4", "/@graph/5"))
  expect_identical(el$id, c("http://spdx.example.com/Package1", "http://spdx.example.com/Package1/myprogram"))
  expect_identical(el$kind, c("component", "file"))
  expect_identical(el$name, c("my-package", "myprogram"))
  expect_identical(el$version, c("1.0", NA))
  expect_identical(el$originator, c("Joshua Watt", "Joshua Watt"))
  expect_identical(el$type, c(NA, "executable"))
  expect_identical(el$is_root, c(TRUE, FALSE))
  expect_identical(t$relationships, chr_frame(
    location = "/@graph/6/to/0", from = "http://spdx.example.com/Package1",
    to = "http://spdx.example.com/Package1/myprogram", type = "contains"
  ))
  doc <- t$document
  expect_identical(doc$timestamp, "2024-03-06T00:00:00Z")
  expect_identical(doc$timestamp_location, "/@graph/0/created")
  expect_identical(doc$authors, chr_frame(name = "Joshua Watt", kind = "person", location = "/@graph/0/createdBy/0"))
  # The document's root is the SBOM, whose root is the package.
  expect_identical(doc$root, "http://spdx.example.com/Package1")
  expect_identical(doc$root_location, "/@graph/3/rootElement/0")
  # Every node with an spdxId defines an id: the agent, the document, the
  # SBOM and the relationship as well as the elements.
  expect_identical(doc$ids, c(
    "http://spdx.example.com/Agent/JoshuaWatt", "http://spdx.example.com/Document1",
    "http://spdx.example.com/BOM1", "http://spdx.example.com/Package1",
    "http://spdx.example.com/Package1/myprogram", "http://spdx.example.com/Relationship/1"
  ))
})

test_that("SPDX 3 inline creationInfo, agents, licenses and imports are read", {
  t <- tables_of(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '{"type":"Person","spdxId":"urn:p","name":"Pat","creationInfo":"_:ci"},',
    '{"type":"Organization","spdxId":"urn:o","name":"Org"},',
    '{"type":"SoftwareAgent","spdxId":"urn:s","name":"Bot"},',
    '{"type":"Agent","spdxId":"urn:a","name":"Someone"},',
    '{"type":"Tool","spdxId":"urn:t","name":"maker 2.1"},',
    '{"type":"software_Package","spdxId":"urn:pkg","name":"one","software_packageVersion":"1.0",',
    '"software_packageUrl":"pkg:npm/one@1.0","suppliedBy":"urn:o","originatedBy":["urn:p"],',
    '"software_primaryPurpose":"library","externalIdentifier":[',
    '{"type":"ExternalIdentifier","externalIdentifierType":"cpe23","identifier":"cpe:2.3:a:x:one:1.0:*:*:*:*:*:*:*"},',
    '{"type":"ExternalIdentifier","externalIdentifierType":"packageUrl","identifier":"pkg:generic/one@1.0"}]},',
    '{"type":"software_File","spdxId":"urn:file","name":"one.js"},',
    '{"type":"software_Snippet","spdxId":"urn:snip","name":"part"},',
    '{"type":"simplelicensing_LicenseExpression","spdxId":"urn:lic1","simplelicensing_licenseExpression":"MIT"},',
    '{"type":"simplelicensing_LicenseExpression","spdxId":"urn:lic2","simplelicensing_licenseExpression":"Apache-2.0 OR MIT"},',
    '{"type":"Relationship","spdxId":"urn:r1","from":"urn:pkg","relationshipType":"hasDeclaredLicense","to":["urn:lic1"]},',
    '{"type":"Relationship","spdxId":"urn:r2","from":"urn:pkg","relationshipType":"hasConcludedLicense","to":["urn:lic2"]},',
    '{"type":"Relationship","spdxId":"urn:r3","from":"urn:file","relationshipType":"hasConcludedLicense",',
    '"to":["expandedlicensing_NoAssertionLicense"]},',
    '{"type":"LifecycleScopedRelationship","spdxId":"urn:r4","from":"urn:pkg","relationshipType":"contains",',
    '"to":["urn:file","urn:snip"],"scope":"build"},',
    '{"type":"software_Sbom","spdxId":"urn:sbom","rootElement":["urn:pkg"]},',
    '{"type":"SpdxDocument","spdxId":"urn:doc","name":"doc3","comment":"A note.","rootElement":["urn:sbom"],',
    '"import":[{"type":"ExternalMap","externalSpdxId":"urn:ext:x"}],',
    '"creationInfo":{"type":"CreationInfo","specVersion":"3.0.1","created":"2026-01-02T03:04:05Z",',
    '"createdBy":["urn:p","urn:o","urn:s","urn:a"],"createdUsing":["urn:t"]}},',
    '{"type":"Relationship","spdxId":"urn:r5","from":"urn:snip","relationshipType":"hasDeclaredLicense",',
    '"to":["https://spdx.org/licenses/MIT","expandedlicensing_NoneLicense","urn:unknown"]}',
    "]}\n"
  ), ".spdx3.json")
  el <- t$elements
  expect_identical(el$id, c("urn:pkg", "urn:file", "urn:snip"))
  expect_identical(el$location, c("/@graph/5", "/@graph/6", "/@graph/7"))
  expect_identical(el$kind, c("component", "file", "snippet"))
  expect_identical(el$supplier, c("Org", NA, NA))
  expect_identical(el$originator, c("Pat", NA, NA))
  expect_identical(el$purl, c("pkg:npm/one@1.0", NA, NA))
  expect_identical(el$identifiers[[1]], c(
    "purl:pkg:npm/one@1.0", "cpe:cpe:2.3:a:x:one:1.0:*:*:*:*:*:*:*", "purl:pkg:generic/one@1.0"
  ))
  expect_identical(t$purls, chr_frame(
    location = c("/@graph/5/software_packageUrl", "/@graph/5/externalIdentifier/1/identifier"),
    id = "urn:pkg", purl = c("pkg:npm/one@1.0", "pkg:generic/one@1.0")
  ))
  # An SPDX License List IRI and the NoAssertion and None individuals are
  # licenses too; an id the graph does not describe is not.
  expect_identical(t$licenses, chr_frame(
    location = c(
      "/@graph/8/simplelicensing_licenseExpression", "/@graph/9/simplelicensing_licenseExpression",
      "/@graph/12/to/0", "/@graph/16/to/0", "/@graph/16/to/1"
    ),
    id = c("urn:pkg", "urn:pkg", "urn:file", "urn:snip", "urn:snip"),
    expression = c("MIT", "Apache-2.0 OR MIT", "NOASSERTION", "MIT", "NONE"),
    kind = "expression",
    field = c(
      "hasDeclaredLicense", "hasConcludedLicense", "hasConcludedLicense", "hasDeclaredLicense",
      "hasDeclaredLicense"
    )
  ))
  # License relationships become license rows, not relationships.
  expect_identical(t$relationships, chr_frame(
    location = c("/@graph/13/to/0", "/@graph/13/to/1"),
    from = "urn:pkg", to = c("urn:file", "urn:snip"), type = "contains"
  ))
  doc <- t$document
  expect_identical(doc$name, "doc3")
  expect_identical(doc$timestamp, "2026-01-02T03:04:05Z")
  expect_identical(doc$timestamp_location, "/@graph/15/creationInfo/created")
  expect_identical(doc$authors, chr_frame(
    name = c("Pat", "Org", "Bot", "Someone"),
    kind = c("person", "organization", "tool", "organization"),
    location = sprintf("/@graph/15/creationInfo/createdBy/%d", 0:3)
  ))
  expect_identical(doc$tools, chr_frame(name = "maker", version = "2.1"))
  expect_identical(doc$root, "urn:pkg")
  expect_identical(doc$root_location, "/@graph/14/rootElement/0")
  expect_identical(doc$notes, "A note.")
  expect_identical(doc$external_ids, "urn:ext:x")
  expect_identical(doc$defined_refs, character())
})

test_that("a SWID tag gives its root, one element per link, and the tag creator as author", {
  t <- document_tables(read_document(tp("swid", "hand.swidtag")))
  el <- t$elements
  expect_identical(el$location, c("/tag", "/links/0", "/links/1"))
  expect_identical(el$id, c(
    "example.com-example-analyzer-2.1.0", "swid:example.com-example-runtime-3.0.0",
    "swid:example.org-example-parser-1.4.2"
  ))
  expect_identical(el$kind, rep("component", 3))
  expect_identical(el$name, c("Example Analyzer", NA, NA))
  expect_identical(el$version, c("2.1.0", NA, NA))
  expect_identical(el$originator, c("Example Software Inc.", NA, NA))
  expect_identical(el$is_root, c(TRUE, FALSE, FALSE))
  expect_identical(el$identifiers, list(
    "swid:example.com-example-analyzer-2.1.0", "swid:example.com-example-runtime-3.0.0",
    "swid:example.org-example-parser-1.4.2"
  ))
  expect_identical(t$relationships, chr_frame(
    location = c("/links/0", "/links/1"), from = "example.com-example-analyzer-2.1.0",
    to = el$id[2:3], type = "requires"
  ))
  doc <- t$document
  expect_identical(doc$name, "Example Analyzer")
  expect_identical(
    doc$authors,
    chr_frame(name = "Example Tag Authority", kind = "organization", location = "/entities/0")
  )
  expect_identical(doc$root, "example.com-example-analyzer-2.1.0")
  expect_identical(doc$root_location, "/tag")
  expect_identical(doc$ids, "example.com-example-analyzer-2.1.0")
  expect_identical(doc$timestamp, NA_character_)
  expect_identical(doc$timestamp_location, NA_character_)
})

test_that("a SWID tag creator is an organization with a real regid, and otherwise a person or sbom the tool", {
  t <- tables_of(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="x" tagId="t">\n',
    '  <Entity name="sbom" regid="http://invalid.unavailable" role="tagCreator"/>\n',
    '  <Entity name="Ann Author" regid="http://invalid.unavailable" role="tagCreator softwareCreator"/>\n',
    '  <Entity name="Bea Builder" role="tagCreator"/>\n',
    '  <Entity name="sbom" regid="example.org" role="tagCreator"/>\n',
    '  <Entity name="Acme" regid="acme.example" role="tagCreator distributor"/>\n',
    '  <Entity name="Not a creator" regid="other.example" role="distributor"/>\n',
    "</SoftwareIdentity>\n"
  ), ".swidtag")
  expect_identical(t$document$authors, chr_frame(
    name = c("sbom", "Ann Author", "Bea Builder", "sbom", "Acme"),
    kind = c("tool", "person", "person", "organization", "organization"),
    location = sprintf("/entities/%d", 0:4)
  ))
})

test_that("our own SWID tag gives its links' names, versions, purls and use", {
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_sbom(fixture_sbom(), tf)
  t <- document_tables(read_document(tf))
  el <- t$elements
  links <- el[!el$is_root, ]
  expect_true(all(startsWith(links$location, "/links/")))
  expect_setequal(links$name, c("R", "methods", "utils", "localpkg", "cranpkg", "suggestpkg"))
  expect_identical(links$purl[links$name == "cranpkg"], "pkg:cran/cranpkg@1.2.0")
  expect_identical(links$version[links$name == "localpkg"], "0.0.1")
  expect_identical(links$scope[links$name == "suggestpkg"], "optional")
  expect_identical(el$supplier[el$is_root], NA_character_)
  expect_identical(el$originator[el$is_root], "Ada Lovelace")
  expect_identical(t$document$tools, chr_frame(name = "sbom", version = as.character(utils::packageVersion("sbom"))))
  expect_length(t$document$notes, 1L)
  # sbom's own license attribute is free text.
  expect_identical(t$licenses, chr_frame(
    location = "/meta/0/sbom:license", id = "local/srcpkg", expression = "MIT + file LICENSE",
    kind = "name", field = "license"
  ))
})

test_that("our own CycloneDX and SPDX output give the object's refs and root", {
  x <- fixture_sbom()
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf, format = "cyclonedx-json", version = "1.6")
  t <- document_tables(read_document(tf))
  expect_identical(sort(t$elements$id, method = "radix"), sort(x$components$ref, method = "radix"))
  expect_identical(t$document$root, x$metadata$root)
  expect_identical(t$document$tools, chr_frame(name = "sbom", version = x$metadata$tool_version))

  tf <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(x, tf, format = "spdx-json", version = "2.3")
  t <- document_tables(read_document(tf))
  root_id <- spdx_ids(x$components)[x$components$is_root]
  describes <- t$relationships[t$relationships$type == "DESCRIBES", ]
  expect_identical(describes$from, "SPDXRef-DOCUMENT")
  expect_identical(describes$to, root_id)
  expect_identical(t$document$root, root_id)
  expect_identical(t$document$tools, chr_frame(name = "sbom", version = x$metadata$tool_version))
})

test_that("CycloneDX values of the wrong JSON type give NA, not an error", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"timestamp":5,"authors":[{"name":["x"]},"y"],"tools":"z","manufacturer":[1],',
    '"component":{"bom-ref":7,"name":{"a":1}},"properties":"p"},',
    '"components":[',
    '{"type":"library","bom-ref":"a","name":5,"version":{"major":1},"purl":["pkg:npm/a@1"],"cpe":3,',
    '"supplier":"acme","manufacturer":["m"],"licenses":[{"license":{"id":3}},{"expression":["MIT"]},"MIT",null],',
    '"components":"x","scope":true,"swid":"s"},',
    '"junk",null,3,[1],',
    '{"bom-ref":"b","licenses":{"expression":"MIT"},"publisher":["p"],"authors":"q","components":[5,{"bom-ref":"c"}]}],',
    '"dependencies":[{"ref":"a","dependsOn":"b"},{"ref":["b"],"dependsOn":["a"]},',
    '{"ref":"b","dependsOn":[1,null,"a"],"provides":{"x":"y"}},"junk"]}\n'
  ), ".cdx.json")
  el <- t$elements
  expect_identical(
    el$location,
    c("/metadata/component", "/components/0", "/components/5", "/components/5/components/1")
  )
  expect_identical(el$id, c(NA, "a", "b", "c"))
  expect_identical(el$name, rep(NA_character_, 4))
  expect_identical(el$version, rep(NA_character_, 4))
  expect_identical(el$purl, rep(NA_character_, 4))
  expect_identical(el$supplier, rep(NA_character_, 4))
  expect_identical(el$originator, rep(NA_character_, 4))
  expect_identical(el$scope, rep(NA_character_, 4))
  expect_identical(el$identifiers, rep(list(character()), 4))
  expect_identical(el$parent, c(NA, NA, NA, "/components/5"))
  expect_identical(nrow(t$licenses), 0L)
  expect_identical(nrow(t$purls), 0L)
  expect_identical(t$relationships, chr_frame(
    location = c("/components/5/components/1", "/dependencies/0", "/dependencies/2/dependsOn/2"),
    from = c("b", "a", "b"), to = c("c", NA, "a"), type = c("contains", "dependsOn", "dependsOn")
  ))
  expect_identical(t$document$timestamp, NA_character_)
  expect_identical(nrow(t$document$authors), 0L)
  expect_identical(nrow(t$document$tools), 0L)
  expect_identical(t$document$root, NA_character_)
  expect_identical(t$document$notes, character())
})

test_that("SPDX 2 values of the wrong JSON type give NA, not an error", {
  t <- tables_of(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":3,"comment":["c"],',
    '"creationInfo":{"created":["2020"],"creators":"Person: X"},',
    '"documentDescribes":"SPDXRef-a",',
    '"packages":[{"SPDXID":"SPDXRef-a","name":5,"versionInfo":{"v":1},"supplier":7,',
    '"originator":["Person: Y"],"licenseConcluded":{"x":1},"licenseDeclared":["MIT"],',
    '"licenseInfoFromFiles":"MIT","primaryPackagePurpose":1,"hasFiles":{"a":"b"},',
    '"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",',
    '"referenceLocator":["pkg:npm/a@1"]},"junk",',
    '{"referenceCategory":3,"referenceType":"purl","referenceLocator":"pkg:npm/b@1"}]},',
    '"junk",{"SPDXID":["SPDXRef-b"],"name":"b","externalRefs":"x","licenseConcluded":"MIT"}],',
    '"files":{"SPDXID":"SPDXRef-f"},',
    '"snippets":[{"SPDXID":"SPDXRef-s","name":null,"licenseInfoInSnippets":[1,"MIT"]}],',
    '"relationships":[',
    '{"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":["SPDXRef-b"]},',
    '{"spdxElementId":"SPDXRef-a","relationshipType":5,"relatedSpdxElement":"SPDXRef-b"},"junk",',
    '{"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-s"}],',
    '"hasExtractedLicensingInfos":[{"licenseId":4},"x",{"licenseId":"LicenseRef-x"}],',
    '"externalDocumentRefs":{"externalDocumentId":"DocumentRef-x"}}\n'
  ), ".spdx.json")
  el <- t$elements
  expect_identical(el$location, c("/packages/0", "/packages/2", "/snippets/0"))
  expect_identical(el$id, c("SPDXRef-a", NA, "SPDXRef-s"))
  expect_identical(el$kind, c("component", "component", "snippet"))
  expect_identical(el$name, c(NA, "b", NA))
  expect_identical(el$version, rep(NA_character_, 3))
  expect_identical(el$supplier, rep(NA_character_, 3))
  expect_identical(el$originator, rep(NA_character_, 3))
  expect_identical(el$purl, rep(NA_character_, 3))
  expect_identical(el$type, rep(NA_character_, 3))
  expect_identical(el$identifiers, rep(list(character()), 3))
  expect_identical(el$is_root, rep(FALSE, 3))
  expect_identical(t$licenses, chr_frame(
    location = c("/packages/2/licenseConcluded", "/snippets/0/licenseInfoInSnippets/1"),
    id = c(NA, "SPDXRef-s"), expression = "MIT", kind = "expression",
    field = c("licenseConcluded", "licenseInfoInSnippets")
  ))
  expect_identical(nrow(t$purls), 0L)
  expect_identical(t$relationships, chr_frame(
    location = "/relationships/3", from = "SPDXRef-a", to = "SPDXRef-s", type = "DEPENDS_ON"
  ))
  doc <- t$document
  expect_identical(doc$name, NA_character_)
  expect_identical(doc$timestamp, NA_character_)
  expect_identical(nrow(doc$authors), 0L)
  expect_identical(nrow(doc$tools), 0L)
  expect_identical(doc$root, character())
  expect_identical(doc$notes, character())
  expect_identical(doc$defined_refs, "LicenseRef-x")
  expect_identical(doc$external_ids, character())
})

test_that("SPDX 3 values of the wrong JSON type give NA, not an error", {
  t <- tables_of(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '"junk",5,null,',
    '{"type":"SpdxDocument","spdxId":"urn:doc","creationInfo":7,"rootElement":"urn:p","name":["d"],"import":"x"},',
    '{"type":"software_Package","spdxId":"urn:p","name":5,"software_packageVersion":{"a":1},',
    '"software_packageUrl":["pkg:npm/p@1"],"suppliedBy":["urn:o"],"originatedBy":"urn:o","externalIdentifier":"x"},',
    '{"type":["software_Package"],"spdxId":"urn:q"},',
    '{"type":"Relationship","spdxId":"urn:r1","from":["urn:p"],"relationshipType":"dependsOn","to":["urn:q"]},',
    '{"type":"Relationship","spdxId":"urn:r2","from":"urn:p","relationshipType":"dependsOn","to":"urn:q"},',
    '{"type":"Relationship","spdxId":"urn:r3","from":"urn:p","relationshipType":"hasDeclaredLicense","to":[5,"urn:nope","urn:p"]},',
    '{"type":"Relationship","spdxId":"urn:r4","from":"urn:p","relationshipType":"contains","to":[3,"urn:q"]}',
    "]}\n"
  ), ".spdx3.json")
  el <- t$elements
  expect_identical(el$location, "/@graph/4")
  expect_identical(el$id, "urn:p")
  expect_identical(
    unlist(el[c("name", "version", "supplier", "originator", "purl")], use.names = FALSE),
    rep(NA_character_, 5)
  )
  expect_identical(el$identifiers, list(character()))
  expect_identical(nrow(t$licenses), 0L)
  expect_identical(nrow(t$purls), 0L)
  expect_identical(
    t$relationships,
    chr_frame(location = "/@graph/9/to/1", from = "urn:p", to = "urn:q", type = "contains")
  )
  expect_identical(t$document$name, NA_character_)
  expect_identical(t$document$timestamp, NA_character_)
  expect_identical(t$document$root, character())
  expect_identical(t$document$external_ids, character())
})

test_that("every bom-ref is an id the document defines, services' too", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[{"type":"library","bom-ref":"a","name":"a",',
    '"licenses":[{"license":{"id":"MIT","bom-ref":"lic"}}],"components":[{"type":"library","bom-ref":"a1","name":"a1"}]}],',
    '"services":[{"bom-ref":"svc","name":"s","services":[{"bom-ref":"svc2","name":"t"}]},{"bom-ref":5,"name":"u"}],',
    '"dependencies":[{"ref":"app","dependsOn":["a","svc"]}]}\n'
  ), ".cdx.json")
  expect_identical(t$document$ids, c("app", "a", "lic", "a1", "svc", "svc2"))
  expect_identical(t$elements$id, c("app", "a", "a1"))
})

test_that("SPDX 3 license rows say whether they are declared or concluded, element by element", {
  t <- tables_of(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '{"type":"software_Package","spdxId":"urn:a","name":"a"},',
    '{"type":"software_Package","spdxId":"urn:b","name":"b"},',
    '{"type":"simplelicensing_LicenseExpression","spdxId":"urn:e1","simplelicensing_licenseExpression":"MIT AND BSD-3-Clause"},',
    '{"type":"simplelicensing_LicenseExpression","spdxId":"urn:e2","simplelicensing_licenseExpression":"MIT"},',
    '{"type":"expandedlicensing_ListedLicense","spdxId":"https://spdx.org/licenses/Apache-2.0"},',
    '{"type":"Relationship","spdxId":"urn:r1","from":"urn:b","relationshipType":"hasDeclaredLicense",',
    '"to":["https://spdx.org/licenses/Apache-2.0"]},',
    '{"type":"Relationship","spdxId":"urn:r2","from":"urn:a","relationshipType":"hasConcludedLicense","to":["urn:e1"]},',
    '{"type":"Relationship","spdxId":"urn:r3","from":"urn:a","relationshipType":"hasDeclaredLicense","to":["urn:e2"]}',
    "]}\n"
  ), ".spdx3.json")
  # A listed license that the graph describes is still a license.
  expect_identical(t$licenses, chr_frame(
    location = c(
      "/@graph/2/simplelicensing_licenseExpression", "/@graph/3/simplelicensing_licenseExpression",
      "/@graph/5/to/0"
    ),
    id = c("urn:a", "urn:a", "urn:b"),
    expression = c("MIT AND BSD-3-Clause", "MIT", "Apache-2.0"),
    kind = "expression",
    field = c("hasConcludedLicense", "hasDeclaredLicense", "hasDeclaredLicense")
  ))
})

test_that("an SPDX 3 document without rootElement falls back to its SBOM's, and creationInfo may be inline elsewhere", {
  t <- tables_of(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '{"type":"Person","spdxId":"urn:p","name":"Pat","creationInfo":{"@id":"_:ci","type":"CreationInfo",',
    '"specVersion":"3.0.1","created":"2026-02-03T04:05:06Z","createdBy":["urn:p"]}},',
    '{"type":"software_Package","spdxId":"urn:pkg","name":"one","creationInfo":"_:ci"},',
    '{"type":"software_Sbom","spdxId":"urn:sbom","creationInfo":"_:ci","rootElement":["urn:pkg"]},',
    '{"type":"SpdxDocument","spdxId":"urn:doc","name":"d","creationInfo":"_:ci"}',
    "]}\n"
  ), ".spdx3.json")
  expect_identical(t$document$root, "urn:pkg")
  expect_identical(t$document$root_location, "/@graph/2/rootElement/0")
  expect_identical(t$elements$is_root, TRUE)
  expect_identical(t$document$name, "d")
  expect_identical(t$document$timestamp, "2026-02-03T04:05:06Z")
  expect_identical(t$document$timestamp_location, "/@graph/0/creationInfo/created")
  expect_identical(t$document$authors, chr_frame(name = "Pat", kind = "person", location = "/@graph/0/creationInfo/createdBy/0"))
})

test_that("a long chain of SPDX 3 collections is walked in linear time", {
  skip_on_cran()
  n <- 30000L
  i <- seq_len(n)
  sboms <- sprintf(
    '{"type":"software_Sbom","spdxId":"urn:s%d","rootElement":["%s"]}',
    i, c(sprintf("urn:s%d", i[-1]), "urn:pkg")
  )
  t <- NULL
  path <- withr::local_tempfile(fileext = ".spdx3.json")
  write_text(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '{"type":"SpdxDocument","spdxId":"urn:doc","rootElement":["urn:s1"]},',
    paste(sboms, collapse = ","), ',{"type":"software_Package","spdxId":"urn:pkg","name":"p"}]}\n'
  ), path)
  d <- read_document(path)
  time <- system.time(t <- document_tables(d))[["elapsed"]]
  expect_identical(t$document$root, "urn:pkg")
  expect_identical(t$document$root_location, sprintf("/@graph/%d/rootElement/0", n))
  skip_unless_timing()
  expect_lt(time, 10)
})

test_that("an SPDX 2 swid locator without the swid: scheme is prefixed once", {
  d <- read_document(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  d$doc$packages[[4]]$externalRefs <- list(
    list(referenceCategory = "SECURITY", referenceType = "swid", referenceLocator = "plain-tag-id")
  )
  expect_identical(document_tables(d)$elements$identifiers[[4]], "swid:plain-tag-id")
})

test_that("results do not depend on the locale's idea of a space", {
  text <- paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Organization: Org","Person:\u2003Em (e@x)",',
    '"Tool: maker\u20031.0"]},',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","supplier":"Organization:\u2003Sup",',
    '"originator":"Person: Ann"}]}\n'
  )
  swid <- paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="x" tagId="t">',
    '<Entity name="E" role="tagCreator\u2003softwareCreator"/><Entity name="F" role="softwareCreator tagCreator"/>',
    "</SoftwareIdentity>\n"
  )
  utf8 <- list(tables_of(text, ".spdx.json"), tables_of(swid, ".swidtag"))
  expect_identical(utf8[[1]]$document$authors$name, c("Org", "\u2003Em", "maker\u20031.0"))
  expect_identical(utf8[[1]]$elements$supplier, "\u2003Sup")
  expect_identical(utf8[[1]]$elements$originator, "Ann")
  expect_identical(utf8[[2]]$document$authors$name, "F")
  local_c_ctype()
  expect_identical(list(tables_of(text, ".spdx.json"), tables_of(swid, ".swidtag")), utf8)
})

test_that("empty strings are absent parties and notes", {
  tf <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(minimal_sbom(), tf, format = "spdx-json", version = "2.3")
  expect_identical(document_tables(read_document(tf))$document$notes, character())
  t <- tables_of(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","comment":" ",',
    '"creationInfo":{"creators":["Organization: ","Tool: ","Person:   "]},',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","supplier":"Organization: ","originator":""}]}\n'
  ), ".spdx.json")
  expect_identical(t$elements$supplier, NA_character_)
  expect_identical(t$elements$originator, NA_character_)
  expect_identical(nrow(t$document$authors), 0L)
  expect_identical(nrow(t$document$tools), 0L)
  expect_identical(t$document$notes, character())
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"tools":{"components":[{"name":"","version":"1"}]},"authors":[{"name":""}],',
    '"properties":[{"name":"sbom:note","value":""}]},',
    '"components":[{"type":"library","bom-ref":"a","name":"a","supplier":{"name":""},"publisher":""}]}\n'
  ), ".cdx.json")
  expect_identical(t$elements$supplier, NA_character_)
  expect_identical(t$elements$originator, NA_character_)
  expect_identical(nrow(t$document$authors), 0L)
  expect_identical(nrow(t$document$tools), 0L)
  expect_identical(t$document$notes, character())
})

test_that("coalescing recycles a single fallback", {
  expect_identical(tables_coalesce(c(NA, "a", NA), ""), c("", "a", ""))
  expect_identical(tables_coalesce(c(NA, NA), c("x", "y"), "z"), c("x", "y"))
})

test_that("a JSON array item that is an array is not an element, but an empty XML element is", {
  t <- tables_of('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{},[],[{}]]}\n', ".cdx.json")
  expect_identical(t$elements$location, "/components/0")
  t <- tables_of('{"spdxVersion":"SPDX-2.3","packages":[[],{}],"files":[[]]}\n', ".spdx.json")
  expect_identical(t$elements$location, "/packages/1")
  t <- tables_of(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><metadata><component type="application"/></metadata>',
    '<components><component/></components></bom>\n'
  ), ".cdx.xml")
  expect_identical(t$elements$location, c("/metadata/component", "/components/0"))
  expect_identical(t$document$root, NA_character_)
})

test_that("CycloneDX metadata.supplier and metadata.manufacture stand in for the root's own", {
  t <- tables_of(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,',
    '"metadata":{"manufacture":{"name":"Maker"},"supplier":{"name":"Sup"},',
    '"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[{"type":"library","bom-ref":"a","name":"a"}]}\n'
  ), ".cdx.json")
  expect_identical(t$elements$supplier, c("Sup", NA))
  expect_identical(t$elements$originator, c("Maker", NA))
  expect_identical(nrow(t$document$authors), 0L)
  # The root's own values win.
  t <- document_tables(read_document(tp("cyclonedx", "valid-bom-1.4.json")))
  root <- t$elements[t$elements$is_root, ]
  expect_identical(root$supplier, "Acme, Inc.")
  expect_identical(root$originator, "Acme Super Heros")
  expect_identical(t$document$authors$name[t$document$authors$kind != "tool"], "Samantha Wright")
})

test_that("the tables of 20,000 components are built in seconds", {
  skip_on_cran()
  times <- numeric()
  for (generate in list(generate_cdx, generate_spdx)) {
    path <- generate(20000)
    times[[path]] <- system.time(tables <- document_tables(read_document(path)))[["elapsed"]]
    expect_identical(nrow(tables$elements), 20001L)
    expect_identical(nrow(tables$purls), 20000L)
  }
  skip_unless_timing()
  expect_lt(max(times), 25)
})
