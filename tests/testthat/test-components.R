test_that("each ecosystem rule gives the pinned identity", {
  bioc <- package_ecosystem(c(Package = "DESeq2", Version = "1.50.2",
    git_url = "https://git.bioconductor.org/packages/DESeq2", git_branch = "RELEASE_3_22"))
  expect_equal(bioc$purl, "pkg:cran/DESeq2@1.50.2?repository_url=https://bioconductor.org/packages/3.22/bioc")
  expect_equal(bioc$homepage, "https://bioconductor.org/packages/3.22/bioc/html/DESeq2.html")
  expect_equal(bioc$supplier_name, "Bioconductor")
  gh <- package_ecosystem(c(Package = "srcpkg", Version = "0.1.0", RemoteType = "github",
    RemoteUsername = "example", RemoteRepo = "srcpkg", RemoteSha = "abc123"))
  expect_equal(gh$purl, "pkg:github/example/srcpkg@abc123")
  expect_equal(gh$supplier_name, "example")
  expect_equal(gh$supplier_url, "https://github.com/example")
  expect_equal(gh$vcs_url, "https://github.com/example/srcpkg")
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
    "The license of localpkg 0.0.1, file LICENSE, has no SPDX expression, so it is recorded as NOASSERTION.")
  expect_true(all(out$issues$ref == "local/localpkg"))
})

test_that("missing and blank license and maintainer raise issues", {
  desc <- c(Package = "q", Version = "2.0", Repository = "CRAN", License = "  ")
  out <- package_component(desc, "observed", "library")
  expect_setequal(out$issues$code, c("license-missing", "maintainer-missing"))
  expect_equal(out$issues$message[out$issues$code == "license-missing"], "q 2.0 declares no license.")
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
  expect_equal(r$license_comment[2], "Part of R, under R's own license.")
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
  skip_on_cran()
  gh <- function(host) {
    c(Package = "g", Version = "1.0", RemoteType = "github", RemoteHost = host,
      RemoteUsername = "team", RemoteRepo = "g", RemoteSha = "abc123",
      License = "MIT + file LICENSE", Maintainer = "A B <a@b.org>")
  }
  for (host in c("https://github.acme.com/api/v3", "github.acme.com/api", "http://github.acme.com/")) {
    c1 <- package_component(gh(host), "observed", "library")$component
    expect_equal(c1$supplier_name, "team", label = host)
    expect_equal(c1$supplier_url, "https://github.acme.com/team", label = host)
    expect_equal(c1$homepage, "https://github.acme.com/team/g", label = host)
    expect_equal(c1$vcs_url, "https://github.acme.com/team/g", label = host)
    expect_equal(c1$purl, "pkg:github/team/g@abc123?repository_url=https://github.acme.com", label = host)
  }
  for (host in c("api.github.com", "https://api.github.com", "github.com", "https://github.com/api/v3")) {
    c1 <- package_component(gh(host), "observed", "library")$component
    expect_equal(c1$supplier_name, "team", label = host)
    expect_equal(c1$supplier_url, "https://github.com/team", label = host)
    expect_equal(c1$vcs_url, "https://github.com/team/g", label = host)
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

test_that("a package without a version is labeled by name, with an issue", {
  out <- package_component(c(Package = "myanalysis"), "declared", "package", is_root = TRUE)
  msgs <- out$issues$message
  expect_true(all(c("myanalysis declares no license.", "myanalysis names no maintainer.") %in% msgs))
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

test_that("a component's dependencies are known unless a reader says otherwise", {
  expect_true(component_row(ref = "x", name = "x")$deps_known)
  expect_false(component_row(ref = "x", name = "x", deps_known = FALSE)$deps_known)
  expect_true(unknown_component("foo")$deps_known)
})

test_that("GitLab, Bitbucket and git sources are recognized in an installed DESCRIPTION", {
  desc <- function(...) {
    c(Package = "p", Version = "1.0", License = "MIT + file LICENSE", Maintainer = "A B <a@b.org>",
      RemoteUsername = "team", RemoteRepo = "p", RemoteSha = "abc123", ...)
  }
  gl <- package_component(desc(RemoteType = "gitlab", RemoteHost = "gitlab.com"), "observed", "library")
  expect_equal(gl$component$ecosystem, "gitlab")
  expect_equal(gl$component$purl, "pkg:gitlab/team/p@abc123")
  expect_equal(gl$component$supplier_name, "team")
  expect_equal(gl$component$supplier_url, "https://gitlab.com/team")
  expect_equal(gl$component$vcs_url, "https://gitlab.com/team/p")
  expect_equal(nrow(gl$issues), 0L)
  own <- package_component(desc(RemoteType = "gitlab", RemoteHost = "https://gitlab.acme.com/"), "observed", "library")
  expect_equal(own$component$purl, "pkg:gitlab/team/p@abc123?repository_url=https://gitlab.acme.com")
  expect_equal(own$component$supplier_name, "team")
  expect_equal(own$component$supplier_url, "https://gitlab.acme.com/team")
  expect_equal(own$component$vcs_url, "https://gitlab.acme.com/team/p")
  bb <- package_component(desc(RemoteType = "bitbucket"), "observed", "library")
  expect_equal(bb$component$ecosystem, "bitbucket")
  expect_equal(bb$component$purl, "pkg:bitbucket/team/p@abc123")
  expect_equal(bb$component$supplier_name, "team")
  expect_equal(bb$component$supplier_url, "https://bitbucket.org/team")
  expect_equal(bb$component$vcs_url, "https://bitbucket.org/team/p")
  for (type in c("git2r", "xgit")) {
    g <- package_component(desc(RemoteType = type, RemoteUrl = "https://git.example.com/p.git"), "observed", "library")
    expect_equal(g$component$ecosystem, "git", label = type)
    expect_equal(g$component$ref, "git/p", label = type)
    expect_true(is.na(g$component$purl), label = type)
    expect_true(is.na(g$component$supplier_name), label = type)
    expect_equal(g$component$vcs_url, "https://git.example.com/p.git", label = type)
    expect_equal(g$issues$code, "source-git", label = type)
    expect_equal(g$issues$message, "p 1.0 was installed from a git repository, so it has no package URL.")
  }
})

test_that("a git remote's URL is kept only as a URL, without credentials", {
  vcs <- function(url) {
    desc <- c(Package = "p", Version = "1.0", RemoteType = "git", RemoteUrl = url)
    package_component(desc, "observed", "library")$component$vcs_url
  }
  expect_identical(vcs("/Users/me/my repo"), NA_character_)
  expect_identical(vcs("../relative/repo"), NA_character_)
  expect_identical(vcs("file:///Users/me/repo.git"), NA_character_)
  expect_identical(vcs("FILE:///Users/me/repo.git"), NA_character_)
  expect_identical(vcs("https://user:tok@git.example.org/x/y.git?ref=1#frag"), "https://git.example.org/x/y.git")
  expect_identical(vcs("git://host/x"), "git://host/x")
  # scp-style remotes become ssh:// URLs, without the user.
  expect_identical(vcs("git@github.com:owner/repo.git"), "ssh://github.com/owner/repo.git")
  expect_identical(vcs("git@host.example:/srv/repo.git"), "ssh://host.example/srv/repo.git")
})

test_that("a local git remote's path enters no document", {
  skip_on_cran()
  lib <- local_fake_lib(list(gitpkg = c(
    Version = "1.0", License = "MIT", Maintainer = "A B <a@b.org>",
    RemoteType = "git", RemoteUrl = "/Users/me/my repo"
  )))
  x <- sbom_installed("gitpkg", lib = lib)
  for (f in sbom_formats()$format) {
    tf <- withr::local_tempfile(fileext = sbom_formats()$extension[sbom_formats()$format == f])
    write_sbom(x, tf, format = f)
    expect_false(grepl("/Users/me", readChar(tf, file.size(tf), useBytes = TRUE), fixed = TRUE), label = f)
  }
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf, format = "cyclonedx-json")
  expect_identical(schema_validate(tf, "cyclonedx-json")$status, "pass")
})

test_that("a forge package's supplier is the account that owns it, or the forge without one", {
  owned <- package_ecosystem(c(Package = "p", Version = "1.0", RemoteType = "github",
    RemoteUsername = "coatless-rpkg", RemoteRepo = "p", RemoteSha = "abc123"))
  expect_equal(owned$supplier_name, "coatless-rpkg")
  expect_equal(owned$supplier_url, "https://github.com/coatless-rpkg")
  expect_equal(owned$vcs_url, "https://github.com/coatless-rpkg/p")
  expect_equal(owned$homepage, "https://github.com/coatless-rpkg/p")
  for (type in c("github", "gitlab", "bitbucket")) {
    bare <- package_ecosystem(c(Package = "p", Version = "1.0", RemoteType = type, RemoteSha = "abc123"))
    expect_equal(bare$supplier_name, c(github = "GitHub", gitlab = "GitLab", bitbucket = "Bitbucket")[[type]],
                 label = type)
    expect_true(is.na(bare$supplier_url), label = type)
  }
  enterprise <- package_ecosystem(c(Package = "p", Version = "1.0", RemoteType = "github",
    RemoteHost = "https://github.acme.com/api/v3", RemoteSha = "abc123"))
  expect_equal(enterprise$supplier_name, "github.acme.com")
})
