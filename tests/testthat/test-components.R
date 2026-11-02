test_that("each ecosystem rule gives the pinned identity", {
  bioc <- package_ecosystem(c(Package = "DESeq2", Version = "1.50.2",
    git_url = "https://git.bioconductor.org/packages/DESeq2", git_branch = "RELEASE_3_22"))
  expect_equal(bioc$purl, "pkg:cran/DESeq2@1.50.2?repository_url=https://bioconductor.org/packages/3.22/bioc")
  expect_equal(bioc$homepage, "https://bioconductor.org/packages/3.22/bioc/html/DESeq2.html")
  expect_equal(bioc$supplier_name, "Bioconductor")
  gh <- package_ecosystem(c(Package = "srcpkg", Version = "0.1.0", RemoteType = "github",
    RemoteUsername = "example", RemoteRepo = "srcpkg", RemoteSha = "abc123"))
  expect_equal(gh$purl, "pkg:github/example/srcpkg@abc123")
  expect_equal(gh$supplier_url, "https://github.com/example/srcpkg")
  ppm <- package_ecosystem(c(Package = "x", Version = "1.0", Repository = "RSPM",
    RemoteRepos = "https://ppm.example.org/cran/latest"))
  expect_equal(ppm$ecosystem, "repository")
  expect_equal(ppm$purl, "pkg:cran/x@1.0?repository_url=https://ppm.example.org/cran/latest")
  expect_equal(ppm$supplier_name, "Posit Package Manager")
  expect_equal(package_ecosystem(c(Package = "y", Version = "1.0"))$ecosystem, "local")
})

test_that("an unknown Bioconductor release falls back to the site URL", {
  b <- package_ecosystem(c(Package = "B", Version = "1.0",
    git_url = "https://git.bioconductor.org/packages/B", git_branch = "devel"))
  expect_equal(b$purl, "pkg:cran/B@1.0?repository_url=https://bioconductor.org")
  expect_true(is.na(b$homepage))
  expect_true(is.na(b$bioc_release))
})

test_that("a GitHub package without RemoteUsername falls back to github/<name>", {
  desc <- c(Package = "g", Version = "1.0", RemoteType = "github", RemoteRepo = "g",
    License = "MIT + file LICENSE", Maintainer = "A B <a@b.org>")
  out <- package_component(desc, "observed", "library")
  expect_equal(out$component$ref, "github/g")
  expect_true(is.na(out$component$purl))
})

test_that("a CRAN package matches R Observatory's fields", {
  desc <- c(Package = "cranpkg", Version = "1.2.0", Repository = "CRAN", License = "GPL-2 | GPL-3",
            Maintainer = "Grace Hopper <grace@example.org>", Imports = "methods",
            `Date/Publication` = "2026-01-02 10:00:00 UTC", URL = "https://github.com/example/cranpkg")
  c1 <- package_component(desc, "observed", "library")$component
  expect_equal(c1$ref, "pkg:cran/cranpkg@1.2.0")
  expect_equal(c1$maintainer, "Grace Hopper")
  expect_equal(c1$license_spdx, "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(c1$license_comment, "Declared in DESCRIPTION as GPL-2 | GPL-3.")
  expect_equal(c1$published, "2026-01-02")
  expect_equal(c1$vcs_url, "https://github.com/example/cranpkg")
  expect_equal(c1$doi, "10.32614/CRAN.package.cranpkg")
  expect_equal(c1$deps[[1]], data.frame(field = "Imports", spec = "methods"))
  expect_equal(names(c1), component_columns())
  expect_equal(c1$package_file_name, "cranpkg_1.2.0.tar.gz")
  expect_equal(nrow(rbind(empty_components(), c1)), 1L)
})

test_that("vcs_url strips .git and /issues and falls back to BugReports", {
  desc <- c(Package = "p", Version = "1", BugReports = "https://github.com/o/p.git/issues")
  expect_equal(package_component(desc, "observed", "library")$component$vcs_url,
    "https://github.com/o/p")
})

test_that("a local package with file LICENSE raises two issues", {
  desc <- c(Package = "localpkg", Version = "0.0.1", License = "file LICENSE",
            Maintainer = "Alan Turing <alan@example.org>")
  out <- package_component(desc, "observed", "library")
  expect_equal(out$component$ref, "local/localpkg")
  expect_true(is.na(out$component$license_spdx))
  expect_setequal(out$issues$code, c("license-no-spdx", "supplier-unknown"))
  expect_equal(out$issues$message[out$issues$code == "license-no-spdx"],
    "The licence of localpkg 0.0.1, file LICENSE, has no SPDX expression, so it is recorded as NOASSERTION.")
  expect_true(all(out$issues$ref == "local/localpkg"))
})

test_that("missing and blank licence and maintainer raise issues", {
  desc <- c(Package = "q", Version = "2.0", Repository = "CRAN", License = "  ")
  out <- package_component(desc, "observed", "library")
  expect_setequal(out$issues$code, c("license-missing", "maintainer-missing"))
  expect_equal(out$issues$message[out$issues$code == "license-missing"], "q 2.0 declares no licence.")
  expect_equal(out$issues$message[out$issues$code == "maintainer-missing"], "q 2.0 names no maintainer.")
  expect_true(is.na(out$component$license_comment))
  expect_equal(nrow(out$component$deps[[1]]), 0L)
  expect_named(out$component$hashes[[1]], c("alg", "content", "of"))
  expect_named(out$component$asserted[[1]], c("field", "value", "asserted_by", "reason"))
})

test_that("r_components() uses R Observatory's sentences", {
  r <- r_components("4.1.0", "minimum", "R (>= 4.1.0)", c("utils", "methods"))
  expect_equal(r$ref, c("R", "R/methods", "R/utils"))
  expect_equal(r$description[1], "The lowest R version stated, R (>= 4.1.0).")
  expect_equal(r$license_spdx[1], "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(r$description[2], "Part of R. It comes with R and has no file of its own.")
  expect_equal(r$license_comment[2], "Part of R, under R's own licence.")
  expect_true(all(is.na(r$version[2:3])))
  expect_equal(r$evidence, c("declared", "inferred", "inferred"))
  expect_equal(r$parent_ref, c(NA, "R", "R"))
  expect_equal(names(r), component_columns())
})

test_that("r_components() handles exact and missing versions", {
  ex <- r_components("4.6.2", "exact", NA, character())
  expect_equal(nrow(ex), 1L)
  expect_equal(ex$evidence, "observed")
  expect_true(is.na(ex$description))
  none <- r_components(NA, NA, NA, "stats")
  expect_equal(none$description[1], "R is listed without a version, since no minimum is stated.")
  expect_equal(none$evidence[1], "unknown")
  expect_true(is.na(none$version_is[1]))
})

test_that("unknown_component() builds the placeholder row", {
  u <- unknown_component("foo")
  expect_equal(u$ref, "unknown/foo")
  expect_equal(u$evidence, "unknown")
  expect_false(u$is_root)
  expect_equal(nrow(rbind(empty_components(), u)), 1L)
})
