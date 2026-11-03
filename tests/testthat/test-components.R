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

test_that("a GitHub Enterprise package points at its own host", {
  gh <- function(host) {
    c(Package = "g", Version = "1.0", RemoteType = "github", RemoteHost = host,
      RemoteUsername = "team", RemoteRepo = "g", RemoteSha = "abc123",
      License = "MIT + file LICENSE", Maintainer = "A B <a@b.org>")
  }
  for (host in c("https://github.acme.com/api/v3", "github.acme.com/api", "http://github.acme.com/")) {
    c1 <- package_component(gh(host), "observed", "library")$component
    expect_equal(c1$supplier_name, "github.acme.com", label = host)
    expect_equal(c1$supplier_url, "https://github.acme.com/team/g", label = host)
    expect_equal(c1$homepage, "https://github.acme.com/team/g", label = host)
    expect_equal(c1$vcs_url, "https://github.acme.com/team/g", label = host)
    expect_equal(c1$purl, "pkg:github/team/g@abc123?repository_url=https://github.acme.com", label = host)
  }
  for (host in c("api.github.com", "https://api.github.com", "github.com", "https://github.com/api/v3")) {
    c1 <- package_component(gh(host), "observed", "library")$component
    expect_equal(c1$supplier_name, "GitHub", label = host)
    expect_equal(c1$supplier_url, "https://github.com/team/g", label = host)
    expect_equal(c1$purl, "pkg:github/team/g@abc123", label = host)
  }
})

test_that("a non-CRAN repository without a URL gives an inferred purl and an issue", {
  desc <- c(Package = "x", Version = "1.0", Repository = "RSPM",
            License = "MIT + file LICENSE", Maintainer = "A B <a@b.org>")
  out <- package_component(desc, "observed", "library")
  expect_equal(out$component$purl, "pkg:cran/x@1.0")
  iss <- out$issues[out$issues$code == "purl-inferred", , drop = FALSE]
  expect_equal(nrow(iss), 1L)
  expect_equal(iss$severity, "warning")
  expect_equal(iss$field, "purl")
  expect_equal(iss$message, paste(
    "x 1.0 came from Posit Package Manager without a recorded repository URL,",
    "so its package URL assumes it is the CRAN package of that name."
  ))
  other <- package_component(c(desc[names(desc) != "Repository"], Repository = "Internal"),
                             "observed", "library")
  expect_match(other$issues$message[other$issues$code == "purl-inferred"], "^x 1.0 came from Internal ")
  for (with_url in list(c(desc, RemoteRepos = "https://ppm.example.org/cran/latest"),
                        c(desc[names(desc) != "Repository"], Repository = "https://r.example.org"))) {
    expect_false("purl-inferred" %in% package_component(with_url, "observed", "library")$issues$code)
  }
  cran <- c(desc[names(desc) != "Repository"], Repository = "CRAN")
  expect_false("purl-inferred" %in% package_component(cran, "observed", "library")$issues$code)
})

test_that("a package without a version is labelled by name, with an issue", {
  out <- package_component(c(Package = "myanalysis"), "declared", "package", is_root = TRUE)
  msgs <- out$issues$message
  expect_true(all(c("myanalysis declares no licence.", "myanalysis names no maintainer.") %in% msgs))
  expect_false(any(grepl("\\bNA\\b", msgs)))
  v <- out$issues[out$issues$code == "version-missing", , drop = FALSE]
  expect_equal(nrow(v), 1L)
  expect_equal(v$severity, "warning")
  expect_equal(v$field, "version")
  expect_equal(v$message, "myanalysis declares no version.")
  expect_true(is.na(out$component$package_file_name))
})

test_that("only repository packages with a version get a package file name", {
  file_name <- function(...) package_component(c(...), "observed", "library")$component$package_file_name
  expect_equal(file_name(Package = "B", Version = "1.0", git_url = "https://git.bioconductor.org/packages/B",
                         git_branch = "RELEASE_3_22"), "B_1.0.tar.gz")
  expect_equal(file_name(Package = "x", Version = "1.0", Repository = "RSPM",
                         RemoteRepos = "https://ppm.example.org/cran/latest"), "x_1.0.tar.gz")
  expect_true(is.na(file_name(Package = "y", Version = "1.0")))
  expect_true(is.na(file_name(Package = "g", Version = "1.0", RemoteType = "github",
                              RemoteUsername = "o", RemoteRepo = "g", RemoteSha = "abc")))
  expect_true(is.na(file_name(Package = "z", Repository = "CRAN")))
})
