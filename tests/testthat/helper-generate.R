# Large generated SBOMs, for the timing tests: a root and `n` library
# components, each with a purl, a license expression and a supplier. The root
# depends on the first component, and each other component on the one before
# it. The licenses repeat, as they do in real documents. Each function writes
# a schema-valid document to a temporary file, removed when `env` ends, and
# returns its path.

generate_licenses <- c("MIT", "Apache-2.0", "GPL-2.0-only OR MIT", "BSD-3-Clause")

generate_cdx <- function(n, env = parent.frame()) {
  path <- withr::local_tempfile(fileext = ".cdx.json", .local_envir = env)
  i <- seq_len(n)
  ref <- sprintf("pkg:cran/comp%d@1.0.%d", i, i)
  components <- sprintf(
    paste0(
      '{"type":"library","bom-ref":"%s","name":"comp%d","version":"1.0.%d",',
      '"supplier":{"name":"Example Supplier %d"},',
      '"licenses":[{"expression":"%s"}],"purl":"%s"}'
    ),
    ref, i, i, i %% 10L, generate_licenses[(i - 1L) %% length(generate_licenses) + 1L], ref
  )
  dependencies <- c(
    sprintf('{"ref":"root","dependsOn":["%s"]}', ref[1]),
    sprintf('{"ref":"%s","dependsOn":["%s"]}', ref[-1], ref[-n])
  )
  write_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6",',
    '"serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1,',
    '"metadata":{"timestamp":"2026-11-06T00:00:00Z","authors":[{"name":"Generator"}],',
    '"component":{"type":"application","bom-ref":"root","name":"root","version":"1.0.0",',
    '"supplier":{"name":"Example Supplier"},"licenses":[{"expression":"MIT"}]}},',
    '"components":[', paste(components, collapse = ","), "],",
    '"dependencies":[', paste(dependencies, collapse = ","), "]}\n"
  ), path)
  path
}

generate_spdx <- function(n, env = parent.frame()) {
  path <- withr::local_tempfile(fileext = ".spdx.json", .local_envir = env)
  i <- seq_len(n)
  id <- sprintf("SPDXRef-comp%d", i)
  packages <- sprintf(
    paste0(
      '{"SPDXID":"%s","name":"comp%d","versionInfo":"1.0.%d",',
      '"supplier":"Organization: Example Supplier %d","downloadLocation":"NOASSERTION",',
      '"filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":"%s",',
      '"copyrightText":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER",',
      '"referenceType":"purl","referenceLocator":"pkg:cran/comp%d@1.0.%d"}]}'
    ),
    id, i, i, i %% 10L, generate_licenses[(i - 1L) %% length(generate_licenses) + 1L], i, i
  )
  root <- paste0(
    '{"SPDXID":"SPDXRef-root","name":"root","versionInfo":"1.0.0",',
    '"supplier":"Organization: Example Supplier","downloadLocation":"NOASSERTION",',
    '"filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":"MIT",',
    '"copyrightText":"NOASSERTION","primaryPackagePurpose":"APPLICATION"}'
  )
  relationship <- '{"spdxElementId":"%s","relationshipType":"%s","relatedSpdxElement":"%s"}'
  relationships <- c(
    sprintf(relationship, "SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-root"),
    sprintf(relationship, c("SPDXRef-root", id[-1]), "DEPENDS_ON", c(id[1], id[-n]))
  )
  write_text(paste0(
    '{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",',
    '"name":"generated","documentNamespace":"https://example.org/spdxdocs/generated",',
    '"creationInfo":{"created":"2026-11-06T00:00:00Z",',
    '"creators":["Organization: Generator","Tool: generator-1.0"]},',
    '"packages":[', paste(c(root, packages), collapse = ","), "],",
    '"relationships":[', paste(relationships, collapse = ","), "]}\n"
  ), path)
  path
}
