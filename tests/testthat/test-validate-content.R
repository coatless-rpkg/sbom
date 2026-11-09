tp <- function(...) test_path("fixtures", "third-party", ...)

# A data frame of findings, as content_findings() returns them.
findings_frame <- function(check = character(), severity = character(), location = character(),
                           message = character()) {
  data.frame(
    check = check, severity = severity, location = location, message = message,
    stringsAsFactors = FALSE
  )
}

# The findings of check `check`, with fresh row names.
only <- function(f, check) {
  out <- f[f$check == check, , drop = FALSE]
  rownames(out) <- NULL
  out
}

# The findings of the document whose text is `text`.
findings_of <- function(text, fileext, profile = "ntia-2021", format = NULL) {
  tf <- withr::local_tempfile(fileext = fileext)
  write_text(text, tf)
  d <- read_document(tf)
  content_findings(document_tables(d), if (is.null(format)) d$format else format, profile)
}

# The findings of a document given as a list, written as JSON.
json_findings <- function(doc, fileext, ...) {
  findings_of(paste0(jsonlite::toJSON(doc, auto_unbox = TRUE, null = "null"), "\n"), fileext, ...)
}

cdx_findings <- function(doc, ...) json_findings(doc, ".cdx.json", ...)
spdx_findings <- function(doc, ...) json_findings(doc, ".spdx.json", ...)
spdx3_findings <- function(doc, ...) json_findings(doc, ".spdx3.json", ...)

# A CycloneDX document with nothing to find: an application that depends on
# one CRAN package.
cdx <- function() {
  list(
    bomFormat = "CycloneDX", specVersion = "1.6", version = 1L,
    metadata = list(
      timestamp = "2026-11-06T00:00:00Z",
      authors = list(list(name = "Ann Author")),
      component = list(
        type = "application", `bom-ref` = "app", name = "app", version = "1.0",
        supplier = list(name = "Acme"), purl = "pkg:generic/app@1.0"
      )
    ),
    components = list(cdx_component("alpha", "1.0")),
    dependencies = list(
      list(ref = "app", dependsOn = list("pkg:cran/alpha@1.0")),
      list(ref = "pkg:cran/alpha@1.0")
    )
  )
}

cdx_component <- function(name, version, purl = paste0("pkg:cran/", name, "@", version),
                          license = "MIT") {
  list(
    type = "library", `bom-ref` = purl, name = name, version = version,
    supplier = list(name = "CRAN"), purl = purl,
    licenses = list(list(expression = license))
  )
}

# An SPDX 2.3 document with nothing to find.
spdx <- function() {
  package <- function(id, name, purl, license) {
    list(
      SPDXID = id, name = name, versionInfo = "1.0", supplier = "Organization: Acme",
      downloadLocation = "NOASSERTION", filesAnalyzed = FALSE,
      licenseConcluded = "NOASSERTION", licenseDeclared = license, copyrightText = "NOASSERTION",
      externalRefs = list(list(
        referenceCategory = "PACKAGE-MANAGER", referenceType = "purl", referenceLocator = purl
      ))
    )
  }
  list(
    spdxVersion = "SPDX-2.3", dataLicense = "CC0-1.0", SPDXID = "SPDXRef-DOCUMENT",
    name = "doc", documentNamespace = "https://example.org/doc",
    creationInfo = list(
      created = "2026-11-06T00:00:00Z", creators = list("Organization: Acme", "Tool: maker-1.0")
    ),
    packages = list(
      package("SPDXRef-app", "app", "pkg:generic/app@1.0", "MIT"),
      package("SPDXRef-alpha", "alpha", "pkg:cran/alpha@1.0", "LicenseRef-mine")
    ),
    hasExtractedLicensingInfos = list(list(licenseId = "LicenseRef-mine", extractedText = "Mine.")),
    relationships = list(
      spdx_rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-app"),
      spdx_rel("SPDXRef-app", "DEPENDS_ON", "SPDXRef-alpha")
    )
  )
}

spdx_rel <- function(from, type, to) {
  list(spdxElementId = from, relationshipType = type, relatedSpdxElement = to)
}

# An SPDX 3 document with nothing to find. It imports one element of another
# document.
spdx3 <- function() {
  ex <- function(x) paste0("https://example.org/", x)
  package <- function(x, purl) {
    list(
      type = "software_Package", spdxId = ex(x), creationInfo = "_:ci", name = x,
      software_packageVersion = "1.0", suppliedBy = ex("acme"), software_packageUrl = purl
    )
  }
  list(
    `@context` = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    `@graph` = list(
      list(
        type = "CreationInfo", `@id` = "_:ci", specVersion = "3.0.1",
        created = "2026-11-06T00:00:00Z", createdBy = list(ex("acme"))
      ),
      list(type = "Organization", spdxId = ex("acme"), creationInfo = "_:ci", name = "Acme"),
      list(
        type = "SpdxDocument", spdxId = ex("doc"), creationInfo = "_:ci",
        rootElement = list(ex("app")),
        import = list(list(type = "ExternalMap", externalSpdxId = "https://other.example/x"))
      ),
      package("app", "pkg:generic/app@1.0"),
      package("alpha", "pkg:cran/alpha@1.0"),
      list(
        type = "Relationship", spdxId = ex("rel"), creationInfo = "_:ci", from = ex("app"),
        relationshipType = "dependsOn", to = list(ex("alpha"))
      )
    )
  )
}

swid_text <- function(links = character(), entity_roles = "tagCreator softwareCreator distributor") {
  paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'name="app" version="1.0" tagId="app-1.0">\n',
    '  <Entity name="Acme" regid="example.org" role="', entity_roles, '"/>\n',
    paste0("  ", links, "\n", collapse = ""),
    "</SoftwareIdentity>\n"
  )
}

test_that("documents with nothing to find give no findings, in the documented shape", {
  expect_identical(cdx_findings(cdx()), findings_frame())
  expect_identical(spdx_findings(spdx()), findings_frame())
  expect_identical(spdx3_findings(spdx3()), findings_frame())
})

# Integrity --------------------------------------------------------------------

test_that("duplicate-id: each element that shares its id gets an error", {
  doc <- cdx()
  doc$components <- list(cdx_component("alpha", "1.0"), cdx_component("alpha", "1.0"), cdx_component("beta", "2.0"))
  expect_identical(only(cdx_findings(doc), "duplicate-id"), findings_frame(
    check = "duplicate-id", severity = "error", location = c("/components/0", "/components/1"),
    message = "The id pkg:cran/alpha@1.0 is used by 2 elements; each element needs its own id."
  ))
  # Elements without an id share nothing.
  doc$components <- lapply(list(cdx_component("alpha", "1.0"), cdx_component("beta", "2.0")), function(x) {
    x$`bom-ref` <- NULL
    x
  })
  expect_identical(only(cdx_findings(doc), "duplicate-id"), findings_frame())
})

test_that("dangling-relationship: a relationship to an id the document does not define is an error", {
  dangling <- function(id) paste0("The relationship refers to ", id, ", which is not an element of this document.")
  # A dangling target is reported at its edge; a dangling source once, at
  # its entry, however many targets the entry lists.
  doc <- cdx()
  doc$dependencies[[1]]$dependsOn <- list("pkg:cran/alpha@1.0", "ghost")
  doc$dependencies[[3]] <- list(ref = "phantom", dependsOn = list("app", "pkg:cran/alpha@1.0", "spectre"))
  doc$dependencies[[4]] <- list(ref = "wraith")
  expect_identical(only(cdx_findings(doc), "dangling-relationship"), findings_frame(
    check = "dangling-relationship", severity = "error",
    location = c("/dependencies/0/dependsOn/1", "/dependencies/2", "/dependencies/2/dependsOn/2", "/dependencies/3"),
    message = dangling(c("ghost", "phantom", "spectre", "wraith"))
  ))
  doc <- spdx()
  doc$relationships[[3]] <- spdx_rel("SPDXRef-ghost", "DEPENDS_ON", "SPDXRef-spectre")
  expect_identical(only(spdx_findings(doc), "dangling-relationship"), findings_frame(
    check = "dangling-relationship", severity = "error", location = c("/relationships/2", "/relationships/2"),
    message = dangling(c("SPDXRef-ghost", "SPDXRef-spectre"))
  ))
  doc <- spdx3()
  doc$`@graph`[[6]]$from <- "https://example.org/ghost"
  doc$`@graph`[[6]]$to <- list("https://example.org/alpha", "https://example.org/app", "https://example.org/spectre")
  expect_identical(only(spdx3_findings(doc), "dangling-relationship"), findings_frame(
    check = "dangling-relationship", severity = "error", location = c("/@graph/5", "/@graph/5/to/2"),
    message = dangling(c("https://example.org/ghost", "https://example.org/spectre"))
  ))
  # SPDX 3's individuals in compact form mean nothing in another format.
  doc <- cdx()
  doc$dependencies[[2]]$dependsOn <- list("NoneElement")
  expect_identical(only(cdx_findings(doc), "dangling-relationship")$message, dangling("NoneElement"))
})

test_that("dangling-relationship: other documents' elements, NONE, a service and an empty dependsOn are not dangling", {
  skip_on_cran()
  # A service's bom-ref is an id of the document; an empty dependsOn has no
  # target.
  doc <- cdx()
  doc$services <- list(list(`bom-ref` = "svc", name = "svc"))
  doc$dependencies <- list(
    list(ref = "app", dependsOn = list("pkg:cran/alpha@1.0", "svc")),
    list(ref = "pkg:cran/alpha@1.0", dependsOn = list())
  )
  expect_identical(only(cdx_findings(doc), "dangling-relationship"), findings_frame())

  doc <- spdx()
  doc$relationships <- c(doc$relationships, list(
    spdx_rel("SPDXRef-app", "DEPENDS_ON", "DocumentRef-ext:SPDXRef-x"),
    spdx_rel("SPDXRef-alpha", "DEPENDS_ON", "NONE"),
    spdx_rel("SPDXRef-alpha", "GENERATED_FROM", "NOASSERTION"),
    spdx_rel("SPDXRef-DOCUMENT", "COPY_OF", "DocumentRef-ext:SPDXRef-DOCUMENT")
  ))
  expect_identical(only(spdx_findings(doc), "dangling-relationship"), findings_frame())

  # An SPDX 3 import, and SPDX 3's individuals, in full and in the compact
  # form that its JSON-LD context gives them.
  doc <- spdx3()
  doc$`@graph`[[6]]$to <- list(
    "https://example.org/alpha", "https://other.example/x",
    "https://spdx.org/rdf/3.0.1/terms/Core/NoneElement", "NoneElement", "NoAssertionElement"
  )
  doc$`@graph`[[7]] <- list(
    type = "Relationship", spdxId = "https://example.org/rel2", creationInfo = "_:ci",
    from = "https://example.org/alpha", relationshipType = "dependsOn", to = list("NoneElement"),
    completeness = "complete"
  )
  expect_identical(only(spdx3_findings(doc), "dangling-relationship"), findings_frame())

  # Nor does sbom's own output, whose SPDX 3 relationships also name agents
  # and licenses.
  x <- fixture_sbom()
  ext <- c(`cyclonedx-json` = ".cdx.json", `spdx-json` = ".spdx.json", `spdx3-jsonld` = ".spdx3.jsonld")
  for (f in names(ext)) {
    tf <- withr::local_tempfile(fileext = ext[[f]])
    write_sbom(x, tf, format = f)
    d <- read_document(tf)
    expect_identical(only(content_findings(document_tables(d), d$format), "dangling-relationship"),
      findings_frame(), label = f)
  }
})

test_that("license-invalid: an expression that does not parse is an error; a license name is not checked", {
  doc <- cdx()
  doc$components <- list(cdx_component("alpha", "1.0", license = "MIT AND"))
  doc$components[[1]]$licenses[[2]] <- list(license = list(name = "Our own license (see LICENSE)"))
  expect_identical(only(cdx_findings(doc), "license-invalid"), findings_frame(
    check = "license-invalid", severity = "error", location = "/components/0/licenses/0/expression",
    message = "The license expression MIT AND is not a valid SPDX expression: it ends where a license was expected."
  ))
  doc$components[[1]]$licenses[[1]]$expression <- "(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0"
  expect_identical(only(cdx_findings(doc), "license-invalid"), findings_frame())
})

test_that("license-invalid: an empty expression, and NONE or NOASSERTION in CycloneDX", {
  doc <- cdx()
  doc$components <- list(
    cdx_component("alpha", "1.0", license = ""), cdx_component("beta", "1.0", license = "NOASSERTION"),
    cdx_component("gamma", "1.0", license = " ")
  )
  doc$components[[2]]$licenses[[2]] <- list(expression = "NONE")
  expect_identical(only(cdx_findings(doc), "license-invalid"), findings_frame(
    check = "license-invalid", severity = "error",
    location = c(
      "/components/0/licenses/0/expression", "/components/1/licenses/0/expression",
      "/components/1/licenses/1/expression", "/components/2/licenses/0/expression"
    ),
    message = c(
      "An empty license expression is not a valid SPDX expression.",
      "The license expression NOASSERTION is not a valid SPDX expression: it uses NOASSERTION, which is not a license.",
      "The license expression NONE is not a valid SPDX expression: it uses NONE, which is not a license.",
      "An empty license expression is not a valid SPDX expression."
    )
  ))
  # SPDX allows them as a whole license.
  doc <- spdx()
  doc$packages[[1]]$licenseDeclared <- "NONE"
  expect_identical(only(spdx_findings(doc), "license-invalid"), findings_frame())
})

test_that("license-invalid: a license used after WITH, or an exception used as a license", {
  doc <- cdx()
  doc$components <- list(
    cdx_component("alpha", "1.0", license = "MIT WITH Apache-2.0"),
    cdx_component("beta", "1.0", license = "classpath-exception-2.0 OR Foo-1.0")
  )
  doc$dependencies[[1]]$dependsOn <- list("pkg:cran/alpha@1.0", "pkg:cran/beta@1.0")
  f <- cdx_findings(doc)
  expect_identical(only(f, "license-invalid"), findings_frame(
    check = "license-invalid", severity = "error",
    location = c("/components/0/licenses/0/expression", "/components/1/licenses/0/expression"),
    message = c(
      "The license expression MIT WITH Apache-2.0 is not a valid SPDX expression: it uses Apache-2.0 after WITH, but Apache-2.0 is a license, not an exception.",
      "The license expression classpath-exception-2.0 OR Foo-1.0 is not a valid SPDX expression: it uses the exception classpath-exception-2.0 as a license."
    )
  ))
  # Only an id on neither list is unknown.
  expect_identical(only(f, "license-unknown"), findings_frame(
    check = "license-unknown", severity = "error", location = "/components/1/licenses/0/expression",
    message = "The license expression classpath-exception-2.0 OR Foo-1.0 uses Foo-1.0, which is not on the SPDX License List 3.29.0."
  ))
})

test_that("license-unknown: ids that are not on the SPDX License List are an error", {
  doc <- cdx()
  doc$components <- list(
    cdx_component("alpha", "1.0", license = "MIT AND Foo-1.0"),
    cdx_component("beta", "1.0", license = "Foo-1.0 OR Bar")
  )
  doc$dependencies[[1]]$dependsOn <- list("pkg:cran/alpha@1.0", "pkg:cran/beta@1.0")
  expect_identical(only(cdx_findings(doc), "license-unknown"), findings_frame(
    check = "license-unknown", severity = "error",
    location = c("/components/0/licenses/0/expression", "/components/1/licenses/0/expression"),
    message = c(
      "The license expression MIT AND Foo-1.0 uses Foo-1.0, which is not on the SPDX License List 3.29.0.",
      "The license expression Foo-1.0 OR Bar uses Foo-1.0 and Bar, which are not on the SPDX License List 3.29.0."
    )
  ))
  # References are not ids of the list.
  doc$components[[1]]$licenses[[1]]$expression <- "MIT OR LicenseRef-mine"
  doc$components[[2]]$licenses[[1]]$expression <- "mit"
  expect_identical(only(cdx_findings(doc), "license-unknown"), findings_frame())
})

test_that("license-deprecated: a deprecated id is a warning", {
  doc <- cdx()
  doc$components <- list(
    cdx_component("alpha", "1.0", license = "GPL-2.0+"),
    cdx_component("beta", "1.0", license = "GPL-2.0 OR LGPL-2.1")
  )
  doc$dependencies[[1]]$dependsOn <- list("pkg:cran/alpha@1.0", "pkg:cran/beta@1.0")
  expect_identical(only(cdx_findings(doc), "license-deprecated"), findings_frame(
    check = "license-deprecated", severity = "warning",
    location = c("/components/0/licenses/0/expression", "/components/1/licenses/0/expression"),
    message = c(
      "The license expression GPL-2.0+ uses the deprecated SPDX license id GPL-2.0.",
      "The license expression GPL-2.0 OR LGPL-2.1 uses the deprecated SPDX license ids GPL-2.0 and LGPL-2.1."
    )
  ))
  doc$components[[1]]$licenses[[1]]$expression <- "GPL-2.0-or-later"
  doc$components[[2]]$licenses[[1]]$expression <- "GPL-2.0-only OR LGPL-2.1-only"
  expect_identical(only(cdx_findings(doc), "license-deprecated"), findings_frame())
})

test_that("license-ref-undefined: SPDX 2 must define each LicenseRef it uses", {
  doc <- spdx()
  doc$packages[[1]]$licenseDeclared <- "MIT OR LicenseRef-x OR DocumentRef-ext:LicenseRef-y"
  doc$packages[[2]]$licenseConcluded <- "LicenseRef-mine AND LicenseRef-x AND LicenseRef-z"
  expect_identical(only(spdx_findings(doc), "license-ref-undefined"), findings_frame(
    check = "license-ref-undefined", severity = "error",
    location = c("/packages/0/licenseDeclared", "/packages/1/licenseConcluded", "/packages/1/licenseConcluded"),
    message = c(
      "The license expression MIT OR LicenseRef-x OR DocumentRef-ext:LicenseRef-y uses LicenseRef-x, which the document does not define in hasExtractedLicensingInfos.",
      "The license expression LicenseRef-mine AND LicenseRef-x AND LicenseRef-z uses LicenseRef-x, which the document does not define in hasExtractedLicensingInfos.",
      "The license expression LicenseRef-mine AND LicenseRef-x AND LicenseRef-z uses LicenseRef-z, which the document does not define in hasExtractedLicensingInfos."
    )
  ))
  # Defined, in another document, or not SPDX 2.
  doc <- spdx()
  doc$packages[[1]]$licenseDeclared <- "LicenseRef-mine OR DocumentRef-ext:LicenseRef-y"
  expect_identical(only(spdx_findings(doc), "license-ref-undefined"), findings_frame())
  doc$hasExtractedLicensingInfos <- NULL
  expect_identical(only(spdx_findings(doc, format = NA_character_), "license-ref-undefined"), findings_frame())
  cdx_doc <- cdx()
  cdx_doc$components[[1]]$licenses[[1]]$expression <- "LicenseRef-mine"
  expect_identical(only(cdx_findings(cdx_doc), "license-ref-undefined"), findings_frame())
})

test_that("purl-invalid: a purl that does not parse is an error", {
  doc <- cdx()
  doc$components[[1]]$purl <- "cran/a@1.0"
  expect_identical(only(cdx_findings(doc), "purl-invalid"), findings_frame(
    check = "purl-invalid", severity = "error", location = "/components/0/purl",
    message = "The purl cran/a@1.0 is not valid: it does not start with pkg:."
  ))
  doc$components[[1]]$purl <- ""
  expect_identical(only(cdx_findings(doc), "purl-invalid"), findings_frame(
    check = "purl-invalid", severity = "error", location = "/components/0/purl",
    message = "An empty purl is not valid."
  ))
  doc$components[[1]]$purl <- "pkg:maven/org.example/a@1.0?type=jar"
  expect_identical(only(cdx_findings(doc), "purl-invalid"), findings_frame())
})

test_that("r-package-name: a CRAN purl on a component whose name R does not allow is an error", {
  doc <- cdx()
  doc$components <- list(cdx_component("a_b", "1.0"))
  doc$dependencies <- list(list(ref = "app", dependsOn = list("pkg:cran/a_b@1.0")))
  expect_identical(only(cdx_findings(doc), "r-package-name"), findings_frame(
    check = "r-package-name", severity = "error", location = "/components/0",
    message = "a_b is not a valid R package name, although its purl says it is a CRAN package."
  ))
  doc$components <- list(cdx_component("data.table", "1.0"), cdx_component("a_b", "1.0", "pkg:pypi/a_b@1.0"))
  expect_identical(only(cdx_findings(doc), "r-package-name"), findings_frame())
})

test_that("r-version: a CRAN purl on a component whose version is not an R version is a warning", {
  doc <- cdx()
  doc$components <- list(cdx_component("alpha", "1.0-beta", "pkg:cran/alpha@1.0"))
  expect_identical(only(cdx_findings(doc), "r-version"), findings_frame(
    check = "r-version", severity = "warning", location = "/components/0",
    message = "alpha 1.0-beta has a version that is not an R package version."
  ))
  doc$components <- list(
    cdx_component("alpha", "1.0-3"), cdx_component("beta", "0.1.2"),
    cdx_component("gamma", "1.0-beta", "pkg:npm/gamma@1.0-beta")
  )
  expect_identical(only(cdx_findings(doc), "r-version"), findings_frame())
})

test_that("r-purl-name: a CRAN purl that names another package is a warning", {
  doc <- cdx()
  doc$components <- list(cdx_component("beta", "1.0", "pkg:cran/alpha@1.0"))
  expect_identical(only(cdx_findings(doc), "r-purl-name"), findings_frame(
    check = "r-purl-name", severity = "warning", location = "/components/0",
    message = "The purl pkg:cran/alpha@1.0 names alpha, not beta."
  ))
  doc$components <- list(cdx_component("alpha", "1.0"), cdx_component("beta", "1.0", "pkg:npm/gamma@1.0"))
  expect_identical(only(cdx_findings(doc), "r-purl-name"), findings_frame())
})

# NTIA 2021 --------------------------------------------------------------------

test_that("ntia-author: no author is an error, and only tools a warning", {
  doc <- cdx()
  doc$metadata$authors <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-author"), findings_frame(
    check = "ntia-author", severity = "error", location = "", message = "The document names no author."
  ))
  doc <- spdx()
  doc$creationInfo$creators <- list("Tool: maker-1.0")
  expect_identical(only(spdx_findings(doc), "ntia-author"), findings_frame(
    check = "ntia-author", severity = "warning", location = "/creationInfo/creators/0",
    message = "The document names only a tool (maker-1.0) as its author; NTIA asks for the person or organization that made the SBOM data."
  ))
  doc$creationInfo$creators <- list("Tool: maker-1.0", "Tool: helper-2")
  expect_identical(only(spdx_findings(doc), "ntia-author")$message,
    "The document names only tools (maker-1.0 and helper-2) as its authors; NTIA asks for the person or organization that made the SBOM data.")
  doc$creationInfo$creators <- list("Tool: maker-1.0", "Person: Ann")
  expect_identical(only(spdx_findings(doc), "ntia-author"), findings_frame())
})

test_that("ntia-author: CycloneDX tools are tool authors, in every way CycloneDX lists them", {
  warning <- function(location, tools = "maker") {
    findings_frame(
      check = "ntia-author", severity = "warning", location = location,
      message = paste0(
        "The document names only ", if (length(tools) == 1L) "a tool" else "tools", " (", and_list(tools),
        ") as its ", if (length(tools) == 1L) "author" else "authors",
        "; NTIA asks for the person or organization that made the SBOM data."
      )
    )
  }
  doc <- cdx()
  doc$metadata$authors <- NULL
  doc$metadata$tools <- list(components = list(list(type = "application", name = "maker", version = "1.0")))
  expect_identical(only(cdx_findings(doc), "ntia-author"), warning("/metadata/tools/components/0"))
  doc$metadata$tools$services <- list(list(name = "signer"))
  expect_identical(
    only(cdx_findings(doc), "ntia-author"),
    warning("/metadata/tools/components/0", c("maker", "signer"))
  )
  # CycloneDX 1.4's array of tools.
  doc$specVersion <- "1.4"
  doc$metadata$tools <- list(list(vendor = "Acme", name = "maker", version = "1.0"))
  expect_identical(only(cdx_findings(doc), "ntia-author"), warning("/metadata/tools/0"))
  # A tool beside a person is no finding; neither authors nor tools is an error.
  doc$metadata$authors <- list(list(name = "Ann"))
  expect_identical(only(cdx_findings(doc), "ntia-author"), findings_frame())
  doc$metadata$authors <- NULL
  doc$metadata$tools <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-author")$severity, "error")
})

test_that("ntia-timestamp: no timestamp is an error, and a SWID tag never has one", {
  doc <- cdx()
  doc$metadata$timestamp <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-timestamp"), findings_frame(
    check = "ntia-timestamp", severity = "error", location = "", message = "The document has no timestamp."
  ))
  expect_identical(only(findings_of(swid_text(), ".swidtag"), "ntia-timestamp"), findings_frame(
    check = "ntia-timestamp", severity = "error", location = "",
    message = "A SWID tag has no field for the time it was made, so it has no timestamp."
  ))
})

test_that("ntia-supplier: a component without a supplier or originator is an error", {
  doc <- spdx()
  doc$packages[[2]]$supplier <- "NOASSERTION"
  expect_identical(only(spdx_findings(doc), "ntia-supplier"), findings_frame(
    check = "ntia-supplier", severity = "error", location = "/packages/1", message = "alpha 1.0 has no supplier."
  ))
  # An originator is enough.
  doc$packages[[2]]$originator <- "Person: Ann"
  expect_identical(only(spdx_findings(doc), "ntia-supplier"), findings_frame())
  doc <- cdx()
  doc$components[[1]]$supplier <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-supplier")$message, "alpha 1.0 has no supplier.")
})

test_that("ntia-name: a component without a name is an error", {
  doc <- cdx()
  doc$components <- list(cdx_component("", "1.0", "pkg:generic/x@1.0"), cdx_component("beta", "1.0"))
  doc$components[[2]]$name <- NULL
  doc$components[[2]]$`bom-ref` <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-name"), findings_frame(
    check = "ntia-name", severity = "error", location = c("/components/0", "/components/1"),
    message = c("The component pkg:generic/x@1.0 has no name.", "The component at /components/1 has no name.")
  ))
  expect_identical(only(cdx_findings(cdx()), "ntia-name"), findings_frame())
})

test_that("ntia-version: a component without a version is an error", {
  doc <- spdx()
  doc$packages[[2]]$versionInfo <- NULL
  doc$packages[[1]]$versionInfo <- "NOASSERTION"
  expect_identical(only(spdx_findings(doc), "ntia-version"), findings_frame(
    check = "ntia-version", severity = "error", location = c("/packages/0", "/packages/1"),
    message = c("app has no version.", "alpha has no version.")
  ))
})

test_that("ntia-identifier: a component needs a purl, CPE or SWID id", {
  doc <- cdx()
  doc$components[[1]]$purl <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-identifier"), findings_frame(
    check = "ntia-identifier", severity = "error", location = "/components/0",
    message = "alpha 1.0 has no purl, CPE or SWID identifier."
  ))
  doc$components[[1]]$cpe <- "cpe:2.3:a:example:a:1.0:*:*:*:*:*:*:*"
  doc$metadata$component$purl <- NULL
  doc$metadata$component$swid <- list(tagId = "app-1.0", name = "app")
  expect_identical(only(cdx_findings(doc), "ntia-identifier"), findings_frame())
})

test_that("ntia-relationships: the document must name a primary component and state its relationships", {
  doc <- cdx()
  doc$metadata$component <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-relationships"), findings_frame(
    check = "ntia-relationships", severity = "error", location = "",
    message = "The document names no primary component."
  ))
  doc <- cdx()
  doc$dependencies <- list(list(ref = "pkg:cran/alpha@1.0", dependsOn = list("app")))
  expect_identical(only(cdx_findings(doc), "ntia-relationships"), findings_frame(
    check = "ntia-relationships", severity = "error", location = "/metadata/component",
    message = "The document states no relationships for its primary component app 1.0."
  ))
  # DESCRIBES alone is not a relationship of the root, nor SPDX 3's describes.
  doc <- spdx()
  doc$relationships <- doc$relationships[1]
  expect_identical(only(spdx_findings(doc), "ntia-relationships")$location, "/packages/0")
  doc <- spdx3()
  doc$`@graph`[[6]]$relationshipType <- "describes"
  expect_identical(only(spdx3_findings(doc), "ntia-relationships")$message,
    "The document states no relationships for its primary component app 1.0.")
})

test_that("ntia-relationships: an empty dependencies entry, an inverse SPDX relationship or a lone root is enough", {
  doc <- cdx()
  doc$dependencies <- list(list(ref = "app"))
  expect_identical(only(cdx_findings(doc), "ntia-relationships"), findings_frame())
  doc$dependencies <- list(list(ref = "app", dependsOn = list()))
  expect_identical(only(cdx_findings(doc), "ntia-relationships"), findings_frame())
  # A document of one component has nothing to relate it to.
  doc <- cdx()
  doc$components <- NULL
  doc$dependencies <- NULL
  expect_identical(only(cdx_findings(doc), "ntia-relationships"), findings_frame())
  # sbom writes Suggests as OPTIONAL_DEPENDENCY_OF, to the root.
  doc <- spdx()
  doc$relationships[[2]] <- spdx_rel("SPDXRef-alpha", "OPTIONAL_DEPENDENCY_OF", "SPDXRef-app")
  expect_identical(only(spdx_findings(doc), "ntia-relationships"), findings_frame())
})

test_that("the NTIA component checks apply to components only", {
  doc <- spdx()
  doc$files <- list(list(SPDXID = "SPDXRef-f", fileName = "./f.c", licenseConcluded = "MIT"))
  doc$relationships[[3]] <- spdx_rel("SPDXRef-app", "CONTAINS", "SPDXRef-f")
  expect_identical(spdx_findings(doc), findings_frame())
})

test_that("swid-links: only the tag itself gets the component checks", {
  links <- c(
    '<Link rel="requires" href="swid:a-1.0"/>', '<Link rel="component" href="swid:b-2.0"/>',
    '<Link rel="related" href="https://example.org"/>'
  )
  f <- findings_of(swid_text(links), ".swidtag")
  expect_identical(f, findings_frame(
    check = c("ntia-timestamp", "swid-links"), severity = c("error", "info"), location = c("", "/links"),
    message = c(
      "A SWID tag has no field for the time it was made, so it has no timestamp.",
      "A SWID tag describes only itself, so the 2 tags it links to were not checked."
    )
  ))
  expect_identical(
    only(findings_of(swid_text(links[1]), ".swidtag"), "swid-links")$message,
    "A SWID tag describes only itself, so the 1 tag it links to was not checked."
  )
  expect_identical(only(findings_of(swid_text(), ".swidtag"), "swid-links"), findings_frame())
  # Two links to one tag name it twice; they do not define it twice.
  expect_identical(only(findings_of(swid_text(links[c(1, 1)]), ".swidtag"), "duplicate-id"), findings_frame())
  # As an <sbom>, the links are components like any other.
  f <- findings_of(swid_text(links), ".swidtag", format = NA_character_)
  expect_identical(only(f, "swid-links"), findings_frame())
  expect_identical(only(f, "ntia-timestamp")$message, "The document has no timestamp.")
  expect_identical(only(f, "ntia-version")$location, c("/links/0", "/links/1"))
})

# Profiles, order and hints ----------------------------------------------------

test_that("findings are ordered by severity, then check, then location", {
  doc <- cdx()
  doc$components <- list(
    cdx_component("alpha", "1.0", license = "GPL-2.0"), cdx_component("beta", "1.0", license = "Foo"),
    cdx_component("gamma", "1.0", license = "LGPL-2.1")
  )
  doc$components[[1]]$purl <- "pkg:"
  doc$components[[3]]$version <- NULL
  doc$metadata$component$version <- NULL
  doc$dependencies[[1]]$dependsOn <- list("pkg:cran/alpha@1.0", "pkg:cran/beta@1.0", "pkg:cran/gamma@1.0")
  f <- cdx_findings(doc)
  expect_identical(f$check, c(
    "license-unknown", "ntia-version", "ntia-version", "purl-invalid",
    "license-deprecated", "license-deprecated"
  ))
  expect_identical(f$severity, c(rep("error", 4), rep("warning", 2)))
  expect_identical(f$location, c(
    "/components/1/licenses/0/expression", "/components/2", "/metadata/component", "/components/0/purl",
    "/components/0/licenses/0/expression", "/components/2/licenses/0/expression"
  ))
})

test_that("locations are in document order: numbers compare as numbers, segment by segment", {
  doc <- cdx()
  doc$components <- lapply(0:11, function(i) {
    x <- cdx_component(paste0("comp", i), "1.0")
    x$supplier <- NULL
    x
  })
  doc$components[[12]]$components <- list(list(type = "library", `bom-ref` = "inner", name = "inner"))
  doc$dependencies <- list(list(ref = "app"))
  expect_identical(
    only(cdx_findings(doc), "ntia-supplier")$location,
    c(sprintf("/components/%d", 0:11), "/components/11/components/0")
  )
  locations <- c("/a/10", "/a/9", "/a-b", "/a/b", "", "/10/a", "/9", "/a/09")
  expect_identical(
    locations[order(content_location_key(locations), locations, method = "radix")],
    c("", "/9", "/10/a", "/a/09", "/a/9", "/a/10", "/a/b", "/a-b")
  )
})

test_that("the none profile adds nothing, and an unknown profile is an error that lists the profiles", {
  doc <- cdx()
  doc$metadata <- NULL
  doc$dependencies <- NULL
  doc$components[[1]]$licenses[[1]]$expression <- "Foo"
  expect_identical(cdx_findings(doc, profile = "none")$check, "license-unknown")
  expect_true(any(startsWith(cdx_findings(doc)$check, "ntia-")))
  expect_identical(names(content_profiles()), c("ntia-2021", "none"))
  t <- document_tables(read_document(generate_cdx(1)))
  expect_error(content_findings(t, "cyclonedx-json", "cisa-2025"), "ntia-2021.*none")
  expect_identical(content_profiles()$none(t, "cyclonedx-json"), findings_frame())
})

test_that("every check has a one-sentence fix hint", {
  hints <- check_hints()
  checks <- c(
    "duplicate-id", "dangling-relationship", "license-invalid", "license-unknown",
    "license-deprecated", "license-ref-undefined", "purl-invalid", "r-package-name", "r-version",
    "r-purl-name", "ntia-author", "ntia-timestamp", "ntia-supplier", "ntia-name", "ntia-version",
    "ntia-identifier", "ntia-relationships", "swid-links"
  )
  expect_setequal(names(hints), checks)
  expect_true(all(grepl("^[A-Z].*[a-z0-9)]\\.$", hints)))
  expect_false(any(grepl("[.;!?] [A-Z]", hints)))
  # A hint leads with the fix in the document; sbom's own ways come after.
  expect_false(any(grepl("sbom", sub(";.*$", "", hints), fixed = TRUE)))
  sbom_hints <- hints[grepl("sbom", hints, fixed = TRUE)]
  expect_true(all(grepl("; if sbom made this SBOM, ", sbom_hints, fixed = TRUE)))
  expect_identical(sub(";.*$", "", hints[["ntia-supplier"]]), "State each component's supplier")
})

# sbom's own output ------------------------------------------------------------

test_that("sbom's own output, fully described, has no errors but SWID's timestamp", {
  skip_on_cran()
  skip_if_not_installed("yaml")
  r_supplier <- "The R Foundation"
  ov <- data.frame(
    component = c(
      "R", "R", "methods", "methods", "methods", "utils", "utils", "utils",
      "localpkg", "localpkg", "srcpkg", "srcpkg", "local/srcpkg#embedded/cranpkg"
    ),
    field = c(
      "supplier_name", "purl", "supplier_name", "version", "purl", "supplier_name", "version", "purl",
      "supplier_name", "purl", "supplier_name", "purl", "supplier_name"
    ),
    value = c(
      r_supplier, "pkg:generic/r@4.1.0", r_supplier, "4.1.0", "pkg:generic/methods@4.1.0",
      r_supplier, "4.1.0", "pkg:generic/utils@4.1.0", "Alan Turing", "pkg:generic/localpkg@0.0.1",
      "Ada Lovelace", "pkg:cran/srcpkg@0.1.0", "CRAN"
    ),
    asserted_by = "Test", reason = "Fixture"
  )
  x <- sbom_package(
    test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), author = "Test Author",
    organization = "Test Org", timestamp = as.POSIXct("2026-11-04", tz = "UTC"), overrides = ov
  )
  comps <- sbom_components(x)
  expect_false(anyNA(comps[c("supplier_name", "purl", "version")]))
  # The SPDX 2 writers leave out the supplier of R and of the base packages
  # unless it is asserted, as it is here. A SWID tag has no field for its
  # timestamp.
  swid <- "A SWID tag has no field for the time it was made, so it has no timestamp."
  reg <- format_registry()
  for (f in setdiff(names(reg), "csv")) {
    for (v in reg[[f]]$versions) {
      tf <- withr::local_tempfile(fileext = reg[[f]]$extension)
      write_sbom(x, tf, format = f, version = v)
      d <- read_document(tf)
      found <- content_findings(document_tables(d), d$format)
      expected <- if (f == "swid") swid else character()
      expect_identical(found$message[found$severity == "error"], expected, label = paste(f, v))
    }
  }
})

test_that("sbom's own output, as it comes, lacks only what the fixture does not say", {
  withr::local_options(sbom.author = NULL, sbom.organization = NULL, sbom.regid = NULL)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), system = FALSE, lib = fixture_lib())
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf, format = "cyclonedx-json", version = "1.6")
  d <- read_document(tf)
  f <- content_findings(document_tables(d), d$format)
  errors <- f[f$severity == "error", c("check", "location")]
  rownames(errors) <- NULL
  # R, its base packages and the local packages have no purl, base packages
  # no version, and neither R, its base packages nor the copy of cranpkg
  # compiled into srcpkg has a supplier or a maintainer.
  expect_identical(errors, data.frame(
    check = c(rep("ntia-identifier", 5), rep("ntia-supplier", 4), rep("ntia-version", 2)),
    location = c(
      "/components/0", "/components/0/components/0", "/components/0/components/1", "/components/1",
      "/metadata/component",
      "/components/0", "/components/0/components/0", "/components/0/components/1",
      "/metadata/component/components/0",
      "/components/0/components/0", "/components/0/components/1"
    ),
    stringsAsFactors = FALSE
  ))
  el <- document_tables(d)$elements
  expect_identical(
    el$name[match(errors$location, el$location)],
    c("R", "methods", "utils", "localpkg", "srcpkg", "R", "methods", "utils", "cranpkg", "methods", "utils")
  )
  # It names no author, only sbom, the tool that made it.
  expect_identical(only(f, "ntia-author"), findings_frame(
    check = "ntia-author", severity = "warning", location = "/metadata/tools/components/0",
    message = "The document names only a tool (sbom) as its author; NTIA asks for the person or organization that made the SBOM data."
  ))
})

test_that("CycloneDX file components get the integrity checks, but not the NTIA component checks", {
  # A Shiny app with a Posit Connect manifest lists its app.R as a file.
  x <- sbom_shiny(test_path("fixtures", "rsconnect"), system = FALSE)
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf, format = "cyclonedx-json", version = "1.6")
  d <- read_document(tf)
  t <- document_tables(d)
  files <- t$elements$location[t$elements$type %in% "file"]
  expect_length(files, 1L)
  f <- content_findings(t, d$format)
  expect_identical(f[startsWith(f$check, "ntia-") & f$location %in% files, ], f[0, ])
  # A file still gets the integrity checks, and is not a component for the
  # root's relationships.
  doc <- cdx()
  doc$components <- list(list(type = "file", `bom-ref` = "file/app.R", name = "app.R", purl = "app.R"))
  doc$dependencies <- NULL
  f <- cdx_findings(doc)
  expect_identical(f$check, "purl-invalid")
  expect_identical(f$location, "/components/0/purl")
  # SPDX 3 packages whose purpose is file are packages.
  doc <- spdx3()
  doc$`@graph`[[5]]$software_primaryPurpose <- "file"
  doc$`@graph`[[5]]$suppliedBy <- NULL
  expect_identical(only(spdx3_findings(doc), "ntia-supplier")$location, "/@graph/4")
})

test_that("a SWID tag sbom writes without an author names only the tool", {
  withr::local_options(sbom.author = NULL, sbom.organization = NULL, sbom.regid = NULL)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), system = FALSE, lib = fixture_lib())
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_sbom(x, tf, format = "swid")
  d <- read_document(tf)
  expect_identical(only(content_findings(document_tables(d), d$format), "ntia-author"), findings_frame(
    check = "ntia-author", severity = "warning", location = "/entities/0",
    message = "The document names only a tool (sbom) as its author; NTIA asks for the person or organization that made the SBOM data."
  ))
})

test_that("a LicenseRef override is defined in every SPDX 2.3 serialization, which still validates", {
  skip_on_cran()
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  ov <- data.frame(
    component = "localpkg", field = "license_spdx", value = "LicenseRef-Proprietary",
    asserted_by = "Legal", reason = "Reviewed"
  )
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
  entry <- list(list(
    licenseId = "LicenseRef-Proprietary",
    extractedText = "The text of this license is not included in this SBOM.", name = "Proprietary"
  ))
  status <- c(`spdx-json` = "pass", `spdx-yaml` = "pass", `spdx-xml` = "partial", `spdx-tv` = "partial")
  reg <- format_registry()
  for (f in names(status)) {
    tf <- withr::local_tempfile(fileext = reg[[f]]$extension)
    write_sbom(x, tf, format = f, version = "2.3")
    d <- read_document(tf)
    expect_identical(sort_keys(d$doc$hasExtractedLicensingInfos), sort_keys(entry), label = f)
    found <- content_findings(document_tables(d), d$format)
    expect_identical(only(found, "license-ref-undefined"), findings_frame(), label = f)
    expect_identical(schema_validate(tf, f)$status, status[[f]], label = f)
  }
})

# Third-party documents --------------------------------------------------------

test_that("the SPDX 2.3 examples give only the NTIA gaps they truly have", {
  skip_if_not_installed("yaml")
  json <- findings_frame(
    check = c(rep("ntia-identifier", 2), rep("ntia-supplier", 3), "ntia-version"),
    severity = "error",
    location = c("/packages/1", "/packages/3", "/packages/1", "/packages/2", "/packages/3", "/packages/1"),
    message = c(
      "Apache Commons Lang has no purl, CPE or SWID identifier.", "Saxon 8.8 has no purl, CPE or SWID identifier.",
      "Apache Commons Lang has no supplier.", "Jena 3.12.0 has no supplier.", "Saxon 8.8 has no supplier.",
      "Apache Commons Lang has no version."
    )
  )
  of <- function(file) {
    d <- read_document(tp("spdx-2.3", file))
    content_findings(document_tables(d), d$format)
  }
  expect_identical(of("SPDXJSONExample-v2.3.spdx.json"), json)
  expect_identical(of("SPDXYAMLExample-2.3.spdx.yaml"), json)
  expect_identical(of("SPDXXMLExample-v2.3.spdx.xml"), json)
  expect_identical(of("SPDXTagExample-v2.3.spdx"), json)
})

test_that("the SPDX 3 individuals exempt from dangling-relationship are those of the bundled schema", {
  schema <- jsonlite::fromJSON(
    system.file("schemas", "spdx", "spdx-3.0.1.schema.json", package = "sbom"), simplifyVector = FALSE
  )
  consts <- unlist(lapply(schema[["$defs"]][["Element_derived"]][["anyOf"]], `[[`, "const"))
  expect_setequal(content_spdx3_individuals, consts)
})

test_that("LicenseRef references are matched against the defined ones in linear time", {
  skip_on_cran()
  # 20,000 packages, each with its own LicenseRef, none of them among the
  # document's 40,000 definitions. Checking the expressions takes about 2 s
  # here; matching their references one expression at a time added 5 s more.
  n <- 20000L
  i <- seq_len(n)
  package <- sprintf(paste0(
    '{"SPDXID":"SPDXRef-c%d","name":"comp%d","versionInfo":"1.0.%d","supplier":"Organization: S",',
    '"downloadLocation":"NOASSERTION","licenseConcluded":"NOASSERTION",',
    '"licenseDeclared":"MIT OR LicenseRef-L%d"}'
  ), i, i, i, i)
  defined <- sprintf('{"licenseId":"LicenseRef-D%d","extractedText":"x"}', seq_len(2L * n))
  tf <- withr::local_tempfile(fileext = ".spdx.json")
  write_text(paste0(
    '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"g",',
    '"documentNamespace":"https://example.org/g","creationInfo":{"created":"2026-11-06T00:00:00Z",',
    '"creators":["Organization: G"]},"packages":[', paste(package, collapse = ","), "],",
    '"hasExtractedLicensingInfos":[', paste(defined, collapse = ","), "],",
    '"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES",',
    '"relatedSpdxElement":"SPDXRef-c1"}]}\n'
  ), tf)
  d <- read_document(tf)
  t <- document_tables(d)
  time <- system.time(f <- content_findings(t, d$format, profile = "none"))[["elapsed"]]
  expect_identical(sum(f$check == "license-ref-undefined"), n)
  skip_unless_timing()
  expect_lt(time, 25)
})

test_that("the content checks of 20,000 components take seconds", {
  skip_on_cran()
  times <- numeric()
  for (path in c(generate_cdx(20000), generate_spdx(20000))) {
    times[[path]] <- system.time({
      d <- read_document(path)
      f <- content_findings(document_tables(d), d$format)
    })[["elapsed"]]
    # The generated root has no purl; everything else is complete.
    expect_identical(f$message, "root 1.0.0 has no purl, CPE or SWID identifier.", label = path)
  }
  skip_unless_timing()
  expect_lt(max(times), 40)
})

test_that("an author named NOASSERTION, or blank, is no author", {
  doc <- function(authors) {
    tf <- withr::local_tempfile(fileext = ".cdx.json", .local_envir = parent.frame())
    write_text(paste0(
      '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"2026-01-01T00:00:00Z",',
      '"authors":[', paste0('{"name":"', authors, '"}', collapse = ","), '],',
      '"component":{"type":"application","bom-ref":"app","name":"app","version":"1","purl":"pkg:npm/app@1",',
      '"supplier":{"name":"S"}}}}\n'
    ), tf)
    tf
  }
  v <- validate_sbom(doc(c("NOASSERTION", " ")), checks = "content")
  expect_identical(v$findings$check, "ntia-author")
  expect_identical(v$findings$message, "The document names no author.")
  expect_identical(validate_sbom(doc(c("NOASSERTION", "Ann")), checks = "content")$status, "pass")
  spdx <- withr::local_tempfile(fileext = ".spdx.json")
  write_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"d","creationInfo":{"created":"2026-01-01T00:00:00Z",',
    '"creators":["Person: NOASSERTION","Organization: NOASSERTION","Tool: t-1"]},"documentDescribes":["SPDXRef-a"],',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","versionInfo":"1","supplier":"Organization: S",',
    '"downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",',
    '"referenceLocator":"pkg:npm/a@1"}]}]}\n'
  ), spdx)
  f <- validate_sbom(spdx, checks = "content")$findings
  expect_identical(f$check, "ntia-author")
  expect_identical(f$severity, "warning")
  expect_identical(read_sbom(spdx)$metadata$author, NA_character_)
})
