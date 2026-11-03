test_that("SPDX 3 follows R Observatory's element structure", {
  x <- fixture_sbom(); d <- spdx3_document(x); g <- d[["@graph"]]
  types <- vapply(g, `[[`, "", "type")
  expect_equal(d[["@context"]], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
  expect_equal(types[1], "CreationInfo")
  expect_equal(utils::tail(types, 2), c("software_Sbom", "SpdxDocument"))
  pk <- Filter(function(e) e$type == "software_Package", g)
  cran <- Find(function(e) e$name == "cranpkg", pk)
  expect_equal(cran$software_packageUrl, "pkg:cran/cranpkg@1.2.0")
  expect_equal(cran$comment, "Maintainer Grace Hopper.")
  expect_equal(Find(function(e) e$name == "R", pk)$software_primaryPurpose, "platform")
  expect_match(Find(function(e) e$name == "localpkg", pk)$comment,
               "Licence declared in DESCRIPTION as file LICENSE, which has no SPDX expression in R's licence database.", fixed = TRUE)
  ids <- unlist(lapply(g, `[[`, "spdxId"))
  expect_false(anyDuplicated(ids) > 0)
  expect_true(all(startsWith(ids, spdx_namespace(x))))
})

test_that("Suggests, LinkingTo and Imports keep their meaning", {
  g <- spdx3_document(fixture_sbom())[["@graph"]]
  rel <- Filter(function(e) e$type %in% c("Relationship", "LifecycleScopedRelationship"), g)
  pid <- function(n) Find(function(e) e$type == "software_Package" && e$name == n, g)$spdxId
  to_cran <- Filter(function(e) identical(unlist(e$to), pid("cranpkg")) && e$from == pid("srcpkg"), rel)
  expect_setequal(vapply(to_cran, `[[`, "", "type"), c("Relationship", "LifecycleScopedRelationship"))
  expect_equal(Find(function(e) e$type == "LifecycleScopedRelationship", to_cran)$scope, "build")
  sug <- Find(function(e) identical(unlist(e$to), pid("suggestpkg")), rel)
  expect_equal(sug$relationshipType, "hasOptionalDependency")
})

test_that("every relationship endpoint is an element of the graph", {
  g <- spdx3_document(fixture_sbom())[["@graph"]]
  ids <- c(unlist(lapply(g, `[[`, "spdxId")), "expandedlicensing_NoAssertionLicense")
  rel <- Filter(function(e) grepl("Relationship$", e$type), g)
  expect_true(all(c(vapply(rel, `[[`, "", "from"), unlist(lapply(rel, `[[`, "to"))) %in% ids))
})

test_that("SPDX 3 passes its JSON schema, which is a partial check", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld"); write_text(spdx3_jsonld(fixture_sbom()), tf)
  res <- schema_validate(tf, "spdx3-jsonld", "3.0.1")
  expect_equal(res$status, "partial")
  expect_match(res$findings$message, "SHACL")
})

test_that("SPDX 3 matches R Observatory's dplyr 1.2.1 sample", {
  ours <- jsonlite::fromJSON(spdx3_jsonld(parity_sbom()), simplifyVector = FALSE)
  theirs <- jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx3.jsonld"))
  expect_equal(normalize_spdx3(ours), normalize_spdx3(theirs))
  expect_gte(length(normalize_spdx3(theirs)$packages), 20)
})

test_that("package elements carry suppliers, hashes, references and the DOI", {
  x <- fixture_sbom()
  at <- which(x$components$name == "cranpkg")
  x$components$hashes[[at]] <- data.frame(alg = "SHA-256", content = strrep("a", 64), of = "source tarball")
  g <- spdx3_document(x)[["@graph"]]
  el <- function(id) Find(function(e) identical(e$spdxId, id), g)
  cran <- Find(function(e) e$type == "software_Package" && e$name == "cranpkg", g)
  supplier <- el(cran$suppliedBy)
  expect_equal(supplier$type, "Organization")
  expect_equal(supplier$name, "CRAN")
  expect_equal(supplier$externalIdentifier[[1]]$identifier, "https://cran.r-project.org")
  expect_equal(el(cran$originatedBy[[1]])$name, "Grace Hopper")
  expect_match(cran$originatedBy[[1]], paste0("#person-", substr(cli::hash_sha1("Grace Hopper"), 1, 12)), fixed = TRUE)
  expect_equal(cran$verifiedUsing, list(list(type = "Hash", algorithm = "sha256", hashValue = strrep("a", 64))))
  expect_equal(cran$externalRef[[1]]$locator, list("https://github.com/example/cranpkg"))
  expect_equal(cran$externalIdentifier[[1]][c("externalIdentifierType", "identifier", "comment")],
               list(externalIdentifierType = "other", identifier = "10.32614/CRAN.package.cranpkg", comment = "DOI"))
  expect_equal(cran$externalIdentifier[[1]]$identifierLocator, list("https://doi.org/10.32614/CRAN.package.cranpkg"))
  expect_equal(cran$releaseTime, "2026-01-02T00:00:00Z")
  expect_equal(cran$software_packageVersion, "1.2.0")
  expect_null(cran$software_downloadLocation)
})

test_that("licences are expressions, NOASSERTION, or nothing for R's own packages", {
  g <- spdx3_document(fixture_sbom())[["@graph"]]
  pid <- function(n) Find(function(e) e$type == "software_Package" && e$name == n, g)$spdxId
  lic <- Filter(function(e) e$type == "Relationship" && e$relationshipType == "hasDeclaredLicense", g)
  lic_of <- function(n) Find(function(e) e$from == pid(n), lic)
  exprs <- Filter(function(e) e$type == "simplelicensing_LicenseExpression", g)
  expect_setequal(vapply(exprs, `[[`, "", "simplelicensing_licenseExpression"),
                  c("MIT", "GPL-2.0-only OR GPL-3.0-only"))
  gpl <- Find(function(e) e$simplelicensing_licenseExpression == "GPL-2.0-only OR GPL-3.0-only", exprs)
  expect_equal(lic_of("cranpkg")$to, list(gpl$spdxId))
  expect_equal(lic_of("R")$to, list(gpl$spdxId))
  expect_match(lic_of("cranpkg")$spdxId, "#rel-lic-SPDXRef-cran-cranpkg$")
  expect_equal(lic_of("localpkg")$to, list("expandedlicensing_NoAssertionLicense"))
  expect_null(lic_of("utils"))
  part <- Find(function(e) !is.null(e$spdxId) && grepl("#rel-part-of-R$", e$spdxId), g)
  expect_equal(part$from, pid("R"))
  expect_equal(part$to, list(pid("methods"), pid("utils")))
  expect_equal(part$comment, "R's own packages are part of R")
})

test_that("dependency relationships are numbered in sorted order", {
  g <- spdx3_document(fixture_sbom())[["@graph"]]
  dep <- Filter(function(e) !is.null(e$spdxId) && grepl("#rel-dep-[0-9]+$", e$spdxId), g)
  n <- as.integer(sub("^.*#rel-dep-", "", vapply(dep, `[[`, "", "spdxId")))
  expect_equal(n, seq_along(dep))
  key <- vapply(dep, function(e) paste(e$from, e$relationshipType, e$to[[1]]), "")
  expect_identical(key, sort(key, method = "radix"))
  expect_true(all(grepl("^(Depends|Imports|LinkingTo|Suggests): ", vapply(dep, `[[`, "", "comment"))))
})

test_that("creators, the tool, the Sbom and the document follow the mapping", {
  x <- fixture_sbom(); g <- spdx3_document(x)[["@graph"]]
  ns <- spdx_namespace(x)
  ci <- g[[1]]
  expect_equal(ci[["@id"]], "_:creationinfo")
  expect_equal(ci$created, "2026-11-04T00:00:00Z")
  expect_equal(ci$createdBy, list(paste0(ns, "#creator-organization"), paste0(ns, "#creator-person-1")))
  expect_equal(ci$createdUsing, list(paste0(ns, "#tool-sbom")))
  expect_equal(g[[2]][c("type", "name")], list(type = "Organization", name = "Test Org"))
  expect_equal(g[[3]][c("type", "name")], list(type = "Person", name = "Test Author"))
  expect_equal(g[[4]]$name, paste("sbom", x$metadata$tool_version))
  sbom <- g[[length(g) - 1L]]; doc <- g[[length(g)]]
  ids <- unlist(lapply(g[-c(1L, length(g) - 1L, length(g))], `[[`, "spdxId"))
  expect_equal(sbom$name, "srcpkg-0.1.0")
  expect_equal(unlist(sbom$element), ids)
  expect_equal(sbom$rootElement, list(paste0(ns, "#SPDXRef-local-srcpkg")))
  expect_equal(doc$rootElement, list(sbom$spdxId))
  expect_equal(unlist(doc$element), c(ids, sbom$spdxId))
  expect_equal(doc$comment, paste(document_notes(x), collapse = " "))
  expect_equal(doc$profileConformance, list("core", "software", "simpleLicensing"))
  expect_equal(doc$dataLicense, "https://spdx.org/licenses/CC0-1.0")
})

test_that("a library SBOM without an author has a software agent and contains its packages", {
  skip_if_not_installed("jsonvalidate")
  lib <- local_fake_lib(list(a = c(Version = "1.0", License = "MIT + file LICENSE", Imports = "utils"), b = c(Version = "2.0")))
  x <- sbom_installed(lib = lib)
  g <- spdx3_document(x)[["@graph"]]
  ns <- spdx_namespace(x)
  expect_equal(g[[1]]$createdBy, list(paste0(ns, "#creator-sbom")))
  expect_equal(g[[2]][c("type", "name")], list(type = "SoftwareAgent", name = "sbom"))
  pid <- function(n) Find(function(e) e$type == "software_Package" && e$name == n, g)$spdxId
  has <- Find(function(e) !is.null(e$spdxId) && grepl("#rel-contains-library$", e$spdxId), g)
  expect_equal(has$from, paste0(ns, "#SPDXRef-library"))
  expect_equal(has$to, list(pid("a"), pid("b")))
  expect_null(has$comment)
  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld"); write_text(spdx3_jsonld(x), tf)
  expect_equal(schema_validate(tf, "spdx3-jsonld")$status, "partial")
})

test_that("an asserted licence is an expression, and the comment says who asserted it", {
  ov <- data.frame(component = "localpkg", field = "license_spdx", value = "Apache-2.0",
                   asserted_by = "Legal", reason = "Reviewed")
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
  g <- spdx3_document(x)[["@graph"]]
  local <- Find(function(e) e$type == "software_Package" && e$name == "localpkg", g)
  expect_equal(local$comment, "Maintainer Alan Turing. Asserted by Legal: license_spdx is Apache-2.0 (Reviewed).")
  lic <- Find(function(e) e$type == "Relationship" && e$from == local$spdxId, g)
  expect_equal(Find(function(e) identical(e$spdxId, lic$to[[1]]), g)$simplelicensing_licenseExpression, "Apache-2.0")
})

test_that("the schema accepts R Observatory's sample and rejects a broken element", {
  skip_if_not_installed("jsonvalidate")
  sample <- test_path("fixtures/r-observatory/dplyr-1.2.1.spdx3.jsonld")
  expect_equal(schema_validate(sample, "spdx3-jsonld")$status, "partial")
  doc <- jsonlite::read_json(sample)
  doc[["@graph"]][[3]]$type <- "NotAType"
  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld")
  write_text(jsonlite::toJSON(doc, auto_unbox = TRUE), tf)
  res <- schema_validate(tf, "spdx3-jsonld")
  expect_equal(res$status, "fail")
  expect_true(any(startsWith(res$findings$location, "/@graph/2")))
  local_mocked_bindings(has_jsonvalidate = function() FALSE)
  expect_equal(schema_validate(sample, "spdx3-jsonld")$status, "skipped")
})

test_that("SPDX 3 text is UTF-8 and literal in a C locale", {
  local_c_ctype()
  dir <- local_latin1_pkg()
  x <- sbom_package(dir, lib = dirname(dir))
  txt <- spdx3_jsonld(x)
  expect_identical(Encoding(txt), "UTF-8")
  expect_true(grepl("Gábor Csárdi", txt, fixed = TRUE))
  expect_true(grepl(paste0("#person-", substr(cli::hash_sha1("Gábor Csárdi"), 1, 12)), txt, fixed = TRUE))
  ours <- jsonlite::fromJSON(spdx3_jsonld(parity_sbom()), simplifyVector = FALSE)
  theirs <- jsonlite::read_json(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx3.jsonld"))
  expect_equal(normalize_spdx3(ours), normalize_spdx3(theirs))
})

test_that("the registry lists SPDX 3 JSON-LD and rejects other versions", {
  r <- format_registry()[["spdx3-jsonld"]]
  expect_equal(r$name, "SPDX 3 JSON-LD")
  expect_equal(r$extension, ".spdx3.jsonld")
  expect_equal(r$versions, "3.0.1")
  expect_equal(r$media_type, "application/spdx+json")
  expect_true(r$all)
  expect_error(spdx3_jsonld(fixture_sbom(), "3.1"), "3.0.1")
  txt <- spdx3_jsonld(fixture_sbom())
  expect_match(txt, "\n$")
  expect_false(grepl("\r", txt, fixed = TRUE))
})

test_that("a library root's purpose is platform, as its CycloneDX type is", {
  x <- sbom_installed(lib = fixture_lib())
  g <- spdx3_document(x)[["@graph"]]
  root <- Find(function(e) identical(e$type, "software_Package") && identical(e$name, "R library"), g)
  expect_equal(root$software_primaryPurpose, "platform")
  expect_equal(cdx_document(x)$metadata$component$type, "platform")
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".spdx3.jsonld")
  write_text(spdx3_jsonld(x), tf)
  expect_equal(schema_validate(tf, "spdx3-jsonld")$status, "partial")
})
