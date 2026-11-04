test_that("sbom_renv() reads every source a lockfile can name", {
  x <- sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = local_fake_lib(list()))
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$ref == "R"], "4.6.2")
  expect_equal(comps$version_is[comps$ref == "R"], "exact")
  expect_equal(comps$evidence[comps$ref == "R"], "declared")
  expect_equal(comps$purl[comps$name == "cli"], "pkg:cran/cli@3.6.6")
  expect_equal(comps$purl[comps$name == "glue"],
               paste0("pkg:cran/glue@", comps$version[comps$name == "glue"],
                      "?repository_url=https://packagemanager.posit.co/cran/latest"))
  expect_equal(comps$purl[comps$name == "ghpkg"], "pkg:github/example/ghpkg@abc123")
  expect_equal(comps$ecosystem[comps$name == "biocpkg"], "bioconductor")
  expect_equal(comps$ecosystem[comps$name == "localpkg"], "local")
  expect_true(all(comps$evidence[comps$name %in% c("cli", "glue")] == "declared"))
  expect_true(all(comps$scope[comps$type == "library"] == "required"))
  rel <- sbom_dependencies(x)
  root <- comps$ref[comps$is_root]
  expect_setequal(rel$to[rel$from == root], comps$ref[comps$name %in% c("cli", "glue")])
  expect_true(all(rel$evidence[rel$from == root] == "inferred"))
  expect_true(all(rel$field[rel$from == root] == "Imports"))
  expect_true(any(rel$from == comps$ref[comps$name == "ghpkg"] &
    rel$to == comps$ref[comps$name == "cli"] & rel$evidence == "declared"))
})

test_that("a legacy lockfile takes licences from a matching installed version only", {
  lock <- test_path("fixtures/renv/legacy/renv.lock")
  locked <- jsonlite::read_json(lock)$Packages
  nm <- names(locked)
  lib <- local_fake_lib(stats::setNames(list(
    c(Version = locked[[1]]$Version, License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>"),
    c(Version = "0.0.0.1", License = "GPL-3", Maintainer = "C D <c@example.org>")), nm))
  x <- sbom_renv(lock, library = lib)
  comps <- sbom_components(x)
  expect_equal(comps$license_spdx[comps$name == nm[1]], "MIT")
  expect_true(is.na(comps$license_spdx[comps$name == nm[2]]))
  iss <- sbom_issues(x)
  expect_true("fields-from-library" %in% iss$code)
  expect_equal(sum(iss$code == "fields-from-library"), 1L)
  expect_true(any(iss$code == "license-missing" & grepl(nm[2], iss$message)))
  expect_true(any(iss$code == "drift-version" & grepl(nm[2], iss$message)))
  rel <- sbom_dependencies(x)
  req <- rel[rel$field == "Requirements" & rel$evidence == "declared", ]
  expect_setequal(req$to, c("R/utils", comps$ref[comps$name == nm[1]]))
  expect_true(all(is.na(req$spec) | !grepl("\\(", req$spec)))
  # No dependency is found in the scanned code, so the root takes what
  # nothing else requires.
  root <- rel[rel$from == comps$ref[comps$is_root], ]
  expect_equal(root$to, comps$ref[comps$name == nm[2]])
  expect_equal(root$field, "Requirements")
  expect_equal(root$evidence, "inferred")
})

test_that("drift between renv.lock and a library it is given is reported", {
  lib <- local_fake_lib(list(cli = c(Version = "3.6.5", Repository = "CRAN"),
                             extra = c(Version = "1.0", Repository = "CRAN")))
  x <- sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = lib)
  msg <- sbom_issues(x)$message
  expect_true("cli is 3.6.6 in renv.lock but 3.6.5 in the library." %in% msg)
  expect_true("extra 1.0 is in the library but not in renv.lock." %in% msg)
  expect_equal(sbom_components(x)$version[sbom_components(x)$name == "cli"], "3.6.6")
})

test_that("a project without a git repository has no version, with an issue", {
  dir <- local_fixture_copy("fixtures/renv/modern")
  x <- sbom_renv(file.path(dir, "renv.lock"), library = local_fake_lib(list()))
  comps <- sbom_components(x)
  expect_equal(comps$name[comps$is_root], "modern")
  expect_equal(comps$ref[comps$is_root], "project/modern")
  expect_equal(comps$ecosystem[comps$is_root], "local")
  expect_equal(x$metadata$inputs$kind, c("renv.lock", "library"))
  expect_true("The project folder modern is not a git repository, so it has no version." %in%
    sbom_issues(x)$message)
})

test_that("a broken lockfile is a clear error", {
  bad <- withr::local_tempfile(fileext = ".lock"); write_text("{ not json", bad)
  expect_error(sbom_renv(bad), "not valid JSON", class = "rlang_error")
  expect_error(sbom_renv(bad), basename(bad), class = "rlang_error")
  none <- withr::local_tempfile(fileext = ".lock"); write_text("{}", none)
  expect_error(sbom_renv(none), "no Packages", class = "rlang_error")
  empty <- withr::local_tempfile(fileext = ".lock"); write_text("", empty)
  expect_error(sbom_renv(empty), basename(empty), class = "rlang_error")
  expect_error(sbom_renv(file.path(withr::local_tempdir(), "renv.lock")), "renv.lock")
})

test_that("a lockfile with no packages gives an SBOM of just the project and R", {
  empty <- withr::local_tempfile(fileext = ".lock")
  write_text('{"R": {"Version": "4.5.0"}, "Packages": {}}', empty)
  x <- sbom_renv(empty, library = local_fake_lib(list()))
  expect_equal(nrow(sbom_components(x)), 2L)
})

test_that("renv_records() joins arrays and maps sources", {
  rec <- renv_records(renv::lockfile_read(test_path("fixtures/renv/modern/renv.lock")))
  expect_equal(names(rec), c("biocpkg", "cli", "ghpkg", "glue", "localpkg"))
  expect_equal(rec$cli[["Depends"]], "R (>= 3.4)")
  expect_equal(rec$glue[["RemoteRepos"]], "https://packagemanager.posit.co/cran/latest")
  expect_false("RemoteRepos" %in% names(rec$cli) && is.na(rec$cli[["RemoteRepos"]]))
  expect_false("Repository" %in% names(rec$localpkg))
  expect_false("Hash" %in% names(rec$cli))
})

# A project folder holding renv.lock (from `pkgs`, a list of package records)
# and the given R files.
local_renv_project <- function(pkgs, files = list(), env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  lock <- list(R = list(Version = "4.5.0"), Packages = pkgs)
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  for (f in names(files)) write_text(files[[f]], file.path(dir, f))
  file.path(dir, "renv.lock")
}

cli_rec <- function() {
  list(Package = "cli", Version = "3.6.6", Source = "Repository", Repository = "CRAN",
       License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>")
}

test_that("a requirement that is not locked is reported as such, not as drift", {
  rec <- cli_rec(); rec$Requirements <- list("zzz")
  lock <- local_renv_project(list(cli = rec[names(rec) != "License"]))
  lib <- local_fake_lib(list(cli = c(Version = "3.6.6", License = "MIT", Maintainer = "A B <a@example.org>")))
  x <- sbom_renv(lock, library = lib)
  iss <- sbom_issues(x)
  expect_true("zzz is named as a dependency of cli but is not recorded in renv.lock, so its version and source are unknown." %in%
    iss$message[iss$code == "dependency-not-locked"])
  expect_false(any(grepl("zzz", iss$message[grepl("^drift-", iss$code)])))
  expect_false(any(grepl("zzz( [0-9.]+)? is in renv.lock", iss$message)))
})

test_that("code that cannot be parsed is reported, and the rest is still scanned", {
  lock <- local_renv_project(
    list(cli = cli_rec(), glue = modifyList(cli_rec(), list(Package = "glue", Version = "1.8.1"))),
    list(bad.R = "library(glue", ok.R = "library(cli)\n")
  )
  x <- sbom_renv(lock, library = local_fake_lib(list()))
  comps <- sbom_components(x)
  rel <- sbom_dependencies(x)
  expect_equal(rel$to[rel$from == comps$ref[comps$is_root] & rel$evidence == "inferred" & rel$field == "Imports"],
    comps$ref[comps$name == "cli"])
  iss <- sbom_issues(x)
  expect_equal(
    iss$message[iss$code == "code-scan-incomplete"],
    paste0("Some R code in ", comps$name[comps$is_root],
      " could not be parsed, so the project's direct dependencies may be incomplete.")
  )
  expect_equal(iss$severity[iss$code == "code-scan-incomplete"], "info")
  clean <- sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = local_fake_lib(list()))
  expect_false("code-scan-incomplete" %in% sbom_issues(clean)$code)
})

test_that("a repository that renv.lock does not list gives an inferred CRAN purl", {
  rec <- cli_rec(); rec$Repository <- "RSPM"
  x <- sbom_renv(local_renv_project(list(cli = rec)), library = local_fake_lib(list()))
  expect_equal(sbom_components(x)$purl[sbom_components(x)$name == "cli"], "pkg:cran/cli@3.6.6")
  expect_true("purl-inferred" %in% sbom_issues(x)$code)
})

test_that("a non-ASCII maintainer is decoded as UTF-8 in a C locale", {
  local_c_ctype()
  rec <- cli_rec(); rec$Maintainer <- "Gábor Csárdi <g@example.org>"
  x <- sbom_renv(local_renv_project(list(cli = rec)), library = local_fake_lib(list()))
  m <- sbom_components(x)$maintainer[sbom_components(x)$name == "cli"]
  expect_equal(Encoding(m), "UTF-8")
  expect_equal(m, "Gábor Csárdi")
})

# The packages of a lockfile from renv before 0.15, which records no
# dependencies, licences or maintainers.
pre_015 <- function() test_path("fixtures/renv/pre-0.15/renv.lock")

test_that("a lockfile that records no dependencies claims none in CycloneDX", {
  x <- sbom_renv(pre_015(), library = local_fake_lib(list()))
  comps <- sbom_components(x)
  pkgs <- comps$ref[comps$name %in% c("cli", "glue", "rlang")]
  expect_length(pkgs, 3L)
  expect_false(any(comps$deps_known[comps$ref %in% pkgs]))
  expect_true(all(comps$deps_known[!comps$ref %in% pkgs]))
  cdx <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  listed <- vapply(cdx$dependencies, function(d) d$ref, "")
  expect_false(any(pkgs %in% listed))
  expect_true(comps$ref[comps$is_root] %in% listed)
  iss <- sbom_issues(x)
  hit <- iss[iss$code == "dependencies-not-recorded", ]
  expect_equal(hit$message, paste0(
    "renv.lock does not record what some of its packages depend on, so the ",
    "links between them are unknown."
  ))
  expect_equal(hit$severity, "warning")
  expect_equal(hit$ref, comps$ref[comps$is_root])
  expect_equal(hit$field, "dependencies")
  # A lockfile whose every record lists its dependencies raises no such issue.
  golem <- sbom_renv(test_path("fixtures/golem/myapp/renv.lock"), library = local_fake_lib(list()))
  expect_false("dependencies-not-recorded" %in% sbom_issues(golem)$code)
  expect_true(all(sbom_components(golem)$deps_known))
})

test_that("a DESCRIPTION-shaped record without dependency fields has none", {
  x <- sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = local_fake_lib(list()))
  comps <- sbom_components(x)
  bare <- comps$ref[comps$name %in% c("biocpkg", "localpkg")]
  expect_length(bare, 2L)
  expect_true(all(comps$deps_known[comps$ref %in% bare]))
  cdx <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  entries <- Filter(function(d) d$ref %in% bare, cdx$dependencies)
  expect_setequal(vapply(entries, function(d) d$ref, ""), bare)
  expect_true(all(lengths(lapply(entries, function(d) d$dependsOn)) == 0L))
  expect_false("dependencies-not-recorded" %in% sbom_issues(x)$code)
  # A record of only the package's name, version and source still says nothing.
  old <- sbom_renv(pre_015(), library = local_fake_lib(list()))
  expect_true("dependencies-not-recorded" %in% sbom_issues(old)$code)
})

test_that("an installed copy at the locked version supplies the dependencies a lockfile lacks", {
  lib <- local_fake_lib(list(
    cli = c(Version = "2.2.0", Imports = "glue, utils", License = "MIT + file LICENSE",
            Maintainer = "G C <g@example.org>"),
    glue = c(Version = "1.4.3", Imports = "methods")
  ))
  x <- sbom_renv(pre_015(), library = lib)
  comps <- sbom_components(x)
  ref <- function(n) comps$ref[comps$name == n]
  expect_true(comps$deps_known[comps$name == "cli"])
  # Installed at another version, so not used.
  expect_false(comps$deps_known[comps$name == "glue"])
  rel <- sbom_dependencies(x)
  expect_setequal(rel$to[rel$from == ref("cli")], c(ref("glue"), "R/utils"))
  cdx <- jsonlite::fromJSON(cdx_json(x), simplifyVector = FALSE)
  entry <- Filter(function(d) d$ref == ref("cli"), cdx$dependencies)
  expect_length(entry, 1L)
  expect_setequal(unlist(entry[[1]]$dependsOn), c(ref("glue"), "R/utils"))
  iss <- sbom_issues(x)
  expect_equal(
    iss$message[iss$code == "fields-from-library"],
    paste0("The licence, maintainer and dependencies of cli 2.2.0 come from the ",
           "installed library, because renv.lock does not record them.")
  )
  expect_true("dependencies-not-recorded" %in% iss$code)
})

test_that("fields-from-library names only the fields it borrowed", {
  lock <- local_renv_project(list(glue = list(
    Package = "glue", Version = "1.7.0", Source = "Repository", Repository = "CRAN",
    License = "MIT + file LICENSE", Imports = "methods"
  )))
  lib <- local_fake_lib(list(glue = c(Version = "1.7.0", Maintainer = "J B <j@example.org>", License = "GPL-3")))
  x <- sbom_renv(lock, library = lib)
  iss <- sbom_issues(x)
  expect_equal(
    iss$message[iss$code == "fields-from-library"],
    "The maintainer of glue 1.7.0 comes from the installed library, because renv.lock does not record it."
  )
  expect_equal(iss$field[iss$code == "fields-from-library"], "maintainer")
  comps <- sbom_components(x)
  expect_equal(comps$license_spdx[comps$name == "glue"], "MIT")
  expect_equal(comps$maintainer[comps$name == "glue"], "J B")
})

test_that("a lockfile that omits a licence says so, rather than that the package declares none", {
  rec <- list(Package = "cli", Version = "3.6.6", Source = "Repository", Repository = "CRAN", Imports = "utils")
  lock <- local_renv_project(list(cli = rec))
  msg <- function(x, code) sbom_issues(x)$message[sbom_issues(x)$code == code]
  x <- sbom_renv(lock, library = local_fake_lib(list()))
  expect_equal(msg(x, "license-missing"), paste0(
    "renv.lock does not record the licence of cli 3.6.6, and no installed copy ",
    "of that version was found."
  ))
  expect_equal(msg(x, "maintainer-missing"), paste0(
    "renv.lock does not record the maintainer of cli 3.6.6, and no installed copy ",
    "of that version was found."
  ))
  # An installed copy of that version that does not record them either.
  y <- sbom_renv(lock, library = local_fake_lib(list(cli = c(Version = "3.6.6"))))
  expect_equal(msg(y, "license-missing"), "renv.lock does not record the licence of cli 3.6.6.")
  # No library to look in.
  withr::local_envvar(RENV_PATHS_LIBRARY = NA, RENV_PATHS_LIBRARY_ROOT = NA)
  z <- sbom_renv(lock)
  expect_equal(msg(z, "license-missing"), "renv.lock does not record the licence of cli 3.6.6.")
  expect_equal(msg(z, "maintainer-missing"), "renv.lock does not record the maintainer of cli 3.6.6.")
})

test_that("every source renv can record gets its own ecosystem", {
  dir <- withr::local_tempdir()
  sha <- "0123456789abcdef0123456789abcdef01234567"
  pkgs <- list(
    Biobase = list(Package = "Biobase", Version = "2.50.0", Source = "Bioconductor"),
    glpkg = list(Package = "glpkg", Version = "1.0", Source = "GitLab", RemoteType = "gitlab",
                 RemoteHost = "gitlab.com", RemoteUsername = "me", RemoteRepo = "glpkg", RemoteSha = sha),
    glsrc = list(Package = "glsrc", Version = "1.0", Source = "GitLab", RemoteUsername = "me",
                 RemoteRepo = "glsrc", RemoteSha = sha),
    bbpkg = list(Package = "bbpkg", Version = "1.0", Source = "Bitbucket", RemoteType = "bitbucket",
                 RemoteUsername = "me", RemoteRepo = "bbpkg", RemoteSha = "0123456"),
    gitpkg = list(Package = "gitpkg", Version = "1.0", Source = "git", RemoteType = "git2r",
                  RemoteUrl = "https://git.example.com/gitpkg.git", RemoteSha = "0123456"),
    unk = list(Package = "unk", Version = "1.0", Source = "unknown"),
    nosrc = list(Package = "nosrc", Version = "1.0")
  )
  pkgs <- lapply(pkgs, function(p) c(p, Imports = "utils", License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>"))
  lock <- list(R = list(Version = "4.0.3"), Bioconductor = list(Version = "3.12"), Packages = pkgs)
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  x <- sbom_renv(file.path(dir, "renv.lock"), library = local_fake_lib(list()))
  comps <- sbom_components(x)
  row <- function(n) comps[comps$name == n, ]
  expect_equal(row("Biobase")$ecosystem, "bioconductor")
  expect_equal(row("Biobase")$purl,
               "pkg:cran/Biobase@2.50.0?repository_url=https://bioconductor.org/packages/3.12/bioc")
  expect_equal(row("Biobase")$bioc_release, "3.12")
  expect_equal(row("Biobase")$supplier_name, "Bioconductor")
  expect_equal(row("glpkg")$ecosystem, "gitlab")
  expect_equal(row("glpkg")$purl, paste0("pkg:gitlab/me/glpkg@", sha))
  expect_equal(row("glpkg")$supplier_name, "GitLab")
  expect_equal(row("glpkg")$supplier_url, "https://gitlab.com/me/glpkg")
  expect_equal(row("glpkg")$vcs_url, "https://gitlab.com/me/glpkg")
  expect_equal(row("glsrc")$purl, paste0("pkg:gitlab/me/glsrc@", sha))
  expect_equal(row("bbpkg")$ecosystem, "bitbucket")
  expect_equal(row("bbpkg")$purl, "pkg:bitbucket/me/bbpkg@0123456")
  expect_equal(row("bbpkg")$supplier_name, "Bitbucket")
  expect_equal(row("gitpkg")$ecosystem, "git")
  expect_true(is.na(row("gitpkg")$purl))
  expect_true(is.na(row("gitpkg")$supplier_name))
  expect_equal(row("gitpkg")$vcs_url, "https://git.example.com/gitpkg.git")
  expect_equal(row("unk")$ecosystem, "unknown")
  expect_equal(row("unk")$evidence, "declared")
  expect_equal(row("nosrc")$ecosystem, "unknown")
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "source-git"],
               "gitpkg 1.0 was installed from a git repository, so it has no package URL.")
  expect_equal(iss$severity[iss$code == "source-git"], "warning")
  expect_setequal(iss$message[iss$code == "source-unknown"], c(
    "renv.lock does not record where unk 1.0 came from.",
    "renv.lock does not record where nosrc 1.0 came from."
  ))
  expect_false(any(grepl("local source", iss$message)))
  ids <- vapply(jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE)$packages, function(p) p$SPDXID, "")
  expect_true(all(c("SPDXRef-gitlab-glpkg", "SPDXRef-bitbucket-bbpkg", "SPDXRef-git-gitpkg",
                    "SPDXRef-bioc-Biobase", "SPDXRef-unknown-unk") %in% ids))
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  expect_valid_in_every_format(x, "sources")
})

test_that("recommended packages left in R's own library are not drift from the project library", {
  matrix <- tryCatch(read_description(file.path(.Library, "Matrix")), error = function(e) NULL)
  skip_if(is.null(matrix) || !identical(unname(matrix["Priority"]), "recommended"),
          "Matrix is not a recommended package in R's own library.")
  withr::local_envvar(RENV_PATHS_LIBRARY = NA, RENV_PATHS_LIBRARY_ROOT = NA)
  mat <- list(Package = "Matrix", Version = unname(matrix[["Version"]]), Source = "Repository",
              Repository = "CRAN", License = "GPL-2 | GPL-3", Maintainer = "M M <m@example.org>",
              Imports = "methods")
  lock <- local_renv_project(list(Matrix = mat, cli = cli_rec()))
  proj_lib <- renv::paths$library(project = dirname(lock))
  dir.create(proj_lib, recursive = TRUE)
  write_fake_lib(proj_lib, list(cli = c(Version = "3.6.5")))
  x <- sbom_renv(lock)
  drift <- sbom_issues(x)[startsWith(sbom_issues(x)$code, "drift-"), ]
  expect_equal(drift$message, "cli is 3.6.6 in renv.lock but 3.6.5 in the project library.")
  expect_true(.Library %in% x$metadata$inputs$path)
  # A library that is given is compared on its own.
  y <- sbom_renv(lock, library = proj_lib)
  expect_true(paste0("Matrix ", matrix[["Version"]], " is in renv.lock but not in the library.") %in%
    sbom_issues(y)$message)
})

test_that("without a project library, drift is not checked, and an issue says so", {
  withr::local_envvar(RENV_PATHS_LIBRARY = NA, RENV_PATHS_LIBRARY_ROOT = NA)
  lock <- local_renv_project(list(cli = cli_rec()))
  iss <- sbom_issues(sbom_renv(lock))
  expect_equal(
    iss$message[iss$code == "drift-not-checked"],
    "No project library was found, so the installed packages were not compared with renv.lock."
  )
  expect_equal(iss$severity[iss$code == "drift-not-checked"], "info")
  expect_false("drift-not-checked" %in% sbom_issues(sbom_renv(lock, library = local_fake_lib(list())))$code)
})

test_that("a project folder named after a locked package does not hide its drift", {
  dir <- file.path(withr::local_tempdir(), "cli")
  dir.create(dir)
  lock <- list(R = list(Version = "4.5.0"), Packages = list(cli = cli_rec()))
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  lib <- local_fake_lib(list(cli = c(Version = "3.6.5")))
  msg <- sbom_issues(sbom_renv(file.path(dir, "renv.lock"), library = lib))$message
  expect_true("cli is 3.6.6 in renv.lock but 3.6.5 in the library." %in% msg)
})

test_that("the root's edges leave out renv itself and the files a package does not ship", {
  rec_renv <- list(Package = "renv", Version = "1.1.5", Source = "Repository", Repository = "CRAN",
                   License = "MIT + file LICENSE", Maintainer = "K U <k@example.org>")
  glue <- modifyList(cli_rec(), list(Package = "glue", Version = "1.8.1"))
  lock <- local_renv_project(
    list(cli = cli_rec(), glue = glue, renv = rec_renv),
    list(DESCRIPTION = "Package: mypkg\nVersion: 1.0\nImports: cli\n", .Rbuildignore = "^data-raw$\n")
  )
  dir <- dirname(lock)
  for (f in c("data-raw/make.R", "tests/testthat/fixtures/x.R")) {
    dir.create(dirname(file.path(dir, f)), recursive = TRUE)
    write_text("library(glue)\n", file.path(dir, f))
  }
  x <- sbom_renv(lock, library = local_fake_lib(list()))
  comps <- sbom_components(x)
  rel <- sbom_dependencies(x)
  expect_equal(rel$to[rel$from == comps$ref[comps$is_root]], comps$ref[comps$name == "cli"])
})
