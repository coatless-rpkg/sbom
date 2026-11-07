test_that("sbom_rsconnect() reads packages, R and app files", {
  x <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"))
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$ref == "R"], "4.6.2")
  expect_equal(comps$evidence[comps$ref == "R"], "declared")
  expect_match(comps$description[comps$is_root], "Deployed to Posit Connect as a shiny application.", fixed = TRUE)
  expect_equal(comps$type[comps$is_root], "application")
  f <- comps[comps$type == "file", ]
  expect_equal(f$ref, "file/app.R")
  expect_equal(f$ecosystem, "file")
  expect_equal(f$hashes[[1]]$alg, "MD5")
  expect_equal(f$hashes[[1]]$content, unname(tools::md5sum(test_path("fixtures/rsconnect/app.R"))))
  expect_equal(f$hashes[[1]]$of, "app file")
  expect_equal(comps$purl[comps$name == "ghpkg"], "pkg:github/example/ghpkg@abc123")
  expect_match(comps$purl[comps$name == "ppmpkg"], "repository_url=https://packagemanager.posit.co/cran/latest", fixed = TRUE)
  expect_true(all(comps$evidence[comps$name %in% c("cli", "ghpkg", "ppmpkg")] == "declared"))
  expect_true(all(comps$source_input[comps$name %in% c("cli", "ghpkg", "ppmpkg", "app.R")] == "manifest.json"))
  rel <- sbom_dependencies(x)
  expect_true(any(rel$field == "contains" & rel$to == "file/app.R" & rel$evidence == "declared"))
  root <- comps$ref[comps$is_root]
  expect_equal(rel$to[rel$from == root & rel$field == "Imports"], comps$ref[comps$name == "cli"])
  expect_equal(rel$evidence[rel$from == root & rel$field == "Imports"], "inferred")
  expect_equal(x$metadata$inputs$kind, "manifest.json")
  expect_equal(comps$ref[comps$is_root], "project/rsconnect")
})

test_that("a dependency missing from the manifest is an unknown component", {
  x <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"))
  comps <- sbom_components(x)
  expect_equal(comps$ecosystem[comps$name == "notrecorded"], "unknown")
  iss <- sbom_issues(x)
  expect_equal(
    iss$message[iss$code == "dependency-not-recorded"],
    "notrecorded is named as a dependency of ghpkg but is not recorded in manifest.json, so its version and source are unknown."
  )
  expect_equal(iss$severity[iss$code == "dependency-not-recorded"], "warning")
})

test_that("a manifest without an appmode is still described", {
  dir <- withr::local_tempdir()
  write_text('{"packages": {}, "files": {}}', file.path(dir, "manifest.json"))
  x <- sbom_rsconnect(file.path(dir, "manifest.json"))
  comps <- sbom_components(x)
  expect_equal(comps$description[comps$is_root], "Deployed to Posit Connect.")
  expect_true(is.na(comps$version[comps$ref == "R"]))
})

test_that("an unparseable app file is reported as an incomplete scan", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/rsconnect/manifest.json"), dir)
  write_text("library(glue", file.path(dir, "bad.R"))
  x <- sbom_rsconnect(file.path(dir, "manifest.json"))
  expect_true("code-scan-incomplete" %in% sbom_issues(x)$code)
})

test_that("a manifest SBOM validates in every format", {
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  x <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"))
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  expected <- c(`cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
                `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "partial")
  for (f in names(expected)) {
    tf <- withr::local_tempfile(fileext = ext[[f]]); write_sbom(x, tf, format = f)
    expect_identical(schema_validate(tf, f)$status, expected[[f]], label = f)
  }
})

test_that("app files are typed as files in each writer", {
  x <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"))
  spdx <- jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE)
  pkg <- Filter(function(p) p$name == "app.R", spdx$packages)[[1]]
  expect_equal(pkg$primaryPackagePurpose, "FILE")
  expect_equal(pkg$SPDXID, "SPDXRef-file-app.R")
  expect_equal(pkg$checksums[[1]]$algorithm, "MD5")
  spdx3 <- jsonlite::fromJSON(spdx3_jsonld(x), simplifyVector = FALSE)
  el <- Filter(function(e) identical(e$name, "app.R"), spdx3$`@graph`)[[1]]
  expect_equal(el$software_primaryPurpose, "file")
  cdx <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  expect_equal(Filter(function(c) c$name == "app.R", cdx$components)[[1]]$type, "file")
  expect_false("file/app.R" %in% vapply(cdx$dependencies, function(d) d$ref, ""))
  expect_false(grepl("file/app.R", swid_tag(x), fixed = TRUE))
})

test_that("a broken manifest is a clear error", {
  bad <- withr::local_tempfile(fileext = ".json"); write_text("[]", bad)
  expect_error(sbom_rsconnect(bad), "manifest")
  expect_error(sbom_rsconnect(file.path(tempdir(), "nope", "manifest.json")), "does not exist")
  junk <- withr::local_tempfile(fileext = ".json"); write_text("{not json", junk)
  expect_error(sbom_rsconnect(junk), "not valid JSON")
  nopkg <- withr::local_tempfile(fileext = ".json"); write_text('{"version": 1}', nopkg)
  expect_error(sbom_rsconnect(nopkg), "no.*packages")
})

test_that("a manifest SBOM says its checksums come from the manifest", {
  notes <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"))$metadata$notes
  expect_true(
    "The MD5 checksums of the app files are those recorded in manifest.json; sbom did not read the files." %in% notes
  )
  expect_false(any(startsWith(notes, "Checksums are only")))
})

# A manifest.json in a new folder, from `packages`, a list of package entries.
local_manifest <- function(packages, env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  m <- list(version = 1, platform = "4.5.0", packages = packages)
  write_text(jsonlite::toJSON(m, auto_unbox = TRUE), file.path(dir, "manifest.json"))
  file.path(dir, "manifest.json")
}

test_that("a manifest entry's Source and Repository stand in for a bare description", {
  desc <- function(name, version) {
    list(Package = name, Version = version, Imports = "utils", License = "MIT + file LICENSE",
         Maintainer = "A B <a@example.org>")
  }
  x <- sbom_rsconnect(local_manifest(list(
    cli = list(Source = "CRAN", Repository = "https://cloud.r-project.org", description = desc("cli", "3.6.6")),
    ppmpkg = list(Source = "CRAN", Repository = "https://packagemanager.posit.co/cran/latest",
                  description = desc("ppmpkg", "2.0.0")),
    Biobase = list(Source = "Bioconductor", Repository = "https://bioconductor.org/packages/3.18/bioc",
                   description = desc("Biobase", "2.62.0")),
    ghpkg = list(Source = "github", description = desc("ghpkg", "0.1.0")),
    unk = list(description = desc("unk", "1.0"))
  )))
  comps <- sbom_components(x)
  row <- function(n) comps[comps$name == n, ]
  expect_equal(row("cli")$ecosystem, "cran")
  expect_equal(row("cli")$purl, "pkg:cran/cli@3.6.6")
  expect_equal(row("ppmpkg")$ecosystem, "repository")
  expect_equal(row("ppmpkg")$purl,
               "pkg:cran/ppmpkg@2.0.0?repository_url=https://packagemanager.posit.co/cran/latest")
  expect_equal(row("ppmpkg")$supplier_name, "Posit Package Manager")
  expect_equal(row("Biobase")$ecosystem, "bioconductor")
  expect_equal(row("Biobase")$purl,
               "pkg:cran/Biobase@2.62.0?repository_url=https://bioconductor.org/packages/3.18/bioc")
  expect_equal(row("Biobase")$bioc_release, "3.18")
  expect_equal(row("ghpkg")$ecosystem, "github")
  # No owner on record, so the forge is the supplier.
  expect_equal(row("ghpkg")$supplier_name, "GitHub")
  expect_true(is.na(row("ghpkg")$supplier_url))
  expect_equal(row("unk")$ecosystem, "unknown")
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "source-unknown"], "manifest.json does not record where unk 1.0 came from.")
  expect_false(any(grepl("local source", iss$message)))
})

test_that("a manifest that omits a license or dependencies says so", {
  x <- sbom_rsconnect(local_manifest(list(
    cli = list(Source = "CRAN", Repository = "https://cloud.r-project.org",
               description = list(Package = "cli", Version = "3.6.6")),
    praise = list(Source = "CRAN", Repository = "https://cloud.r-project.org",
                  description = list(Package = "praise", Version = "1.0.0", Title = "Praise Users",
                                     License = "MIT + file LICENSE", Maintainer = "G C <g@example.org>"))
  )))
  comps <- sbom_components(x)
  # A full description without dependency fields has none.
  expect_true(comps$deps_known[comps$name == "praise"])
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "license-missing"], "manifest.json does not record the license of cli 3.6.6.")
  expect_equal(iss$message[iss$code == "maintainer-missing"], "manifest.json does not record the maintainer of cli 3.6.6.")
  expect_false(comps$deps_known[comps$name == "cli"])
  expect_equal(
    iss$message[iss$code == "dependencies-not-recorded"],
    "manifest.json does not record what some of its packages depend on, so the links between them are unknown."
  )
  cdx <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  listed <- vapply(cdx$dependencies, function(d) d$ref, "")
  expect_false(comps$ref[comps$name == "cli"] %in% listed)
  expect_true(comps$ref[comps$name == "praise"] %in% listed)
})

test_that("a manifest of the wrong shape is a clear error, and not a Posit Connect manifest", {
  dir <- withr::local_tempdir()
  f <- file.path(dir, "manifest.json")
  shapes <- list(
    files = c('{"version": 1, "packages": {}, "files": [{"checksum": "abc"}]}', "files.*not an object"),
    entry = c('{"version": 1, "packages": {"cli": "oops"}}', "cli.*not an object"),
    file_entry = c('{"version": 1, "packages": {}, "files": {"app.R": "abc"}}', "app.R.*not an object"),
    packages = c('{"version": 1, "packages": [{"Package": "cli"}]}', "packages.*not an object"),
    twice = c('{"version": 1, "packages": {}, "files": {"a.R": {}, "a.R": {}}}', "file/a.R")
  )
  for (s in names(shapes)) {
    write_text(shapes[[s]][[1]], f)
    expect_error(sbom_rsconnect(f), shapes[[s]][[2]], class = "rlang_error", label = s)
    if (s != "twice") {
      expect_error(sbom_rsconnect(f), "manifest.json", class = "rlang_error", label = s)
      expect_false(is_connect_manifest(f), label = s)
    }
  }
  write_text('{"version": 1, "packages": {}, "metadata": "shiny"}', f)
  comps <- sbom_components(sbom_rsconnect(f))
  expect_equal(comps$description[comps$is_root], "Deployed to Posit Connect.")
  # sbom() reads the code instead, and says why.
  write_text(shapes$files[[1]], f)
  write_text("library(cli)\n", file.path(dir, "app.R"))
  x <- sbom(dir, lib = local_fake_lib(list()))
  expect_equal(x$metadata$inputs$kind, c("code", "library"))
  expect_true("manifest.json is not a Posit Connect manifest, so it was not read." %in% sbom_issues(x)$message)
})

test_that("a manifest whose files are not an object says so in a full sentence", {
  f <- file.path(withr::local_tempdir(), "manifest.json")
  write_text('{"version": 1, "packages": {}, "files": [{"checksum": "abc"}]}', f)
  err <- expect_error(sbom_rsconnect(f), class = "rlang_error")
  expect_true("Its files entry is not an object." %in% cli::ansi_strip(err$body))
})

test_that("a constraint on a package whose description has no Version is kept and raises no issue", {
  dir <- withr::local_tempdir()
  write_text(paste0(
    '{"version": 1, "metadata": {"appmode": "shiny"}, "packages": {',
    '"a": {"Source": "CRAN", "description": {"Package": "a", "Version": "1.0", "Imports": "b (>= 1.0)"}},',
    '"b": {"Source": "CRAN", "description": {"Package": "b"}}}, "files": {}}'
  ), file.path(dir, "manifest.json"))
  x <- sbom_rsconnect(file.path(dir, "manifest.json"))
  rels <- sbom_dependencies(x)
  comps <- sbom_components(x)
  row <- rels[rels$from == comps$ref[comps$name == "a"] & rels$to == comps$ref[comps$name == "b"], ]
  expect_equal(row$spec, "b (>= 1.0)")
  expect_false(any(sbom_issues(x)$code == "constraint-unsatisfied"))
})
