test_that("git_commit() reads branches, packed refs, detached heads and worktrees", {
  d <- withr::local_tempdir(); sha <- strrep("a1", 20)
  dir.create(file.path(d, ".git", "refs", "heads"), recursive = TRUE)
  write_text("ref: refs/heads/main\n", file.path(d, ".git", "HEAD"))
  write_text(paste0(sha, "\n"), file.path(d, ".git", "refs", "heads", "main"))
  expect_equal(git_commit(d), sha)
  unlink(file.path(d, ".git", "refs", "heads", "main"))
  write_text(paste0("# pack-refs with: peeled\n", sha, " refs/heads/main\n"), file.path(d, ".git", "packed-refs"))
  expect_equal(git_commit(d), sha)
  write_text(paste0(strrep("b2", 20), "\n"), file.path(d, ".git", "HEAD"))
  expect_equal(git_commit(d), strrep("b2", 20))
  w <- withr::local_tempdir(); write_text(paste0("gitdir: ", file.path(d, ".git"), "\n"), file.path(w, ".git"))
  expect_equal(git_commit(w), strrep("b2", 20))
  expect_true(is.na(git_commit(withr::local_tempdir())))
})

test_that("git_commit() follows branch names with slashes and real worktree layouts", {
  main <- withr::local_tempdir(); sha <- strrep("c3", 20)
  git <- file.path(main, ".git")
  dir.create(file.path(git, "refs", "heads", "feature"), recursive = TRUE)
  write_text("ref: refs/heads/feature/x\n", file.path(git, "HEAD"))
  write_text(paste0(sha, "\n"), file.path(git, "refs", "heads", "feature", "x"))
  expect_equal(git_commit(main), sha)
  # A worktree's .git names its own git directory, absolute or relative, whose
  # commondir leads back to the shared refs.
  wt_git <- file.path(git, "worktrees", "wt")
  dir.create(wt_git, recursive = TRUE)
  write_text("ref: refs/heads/feature/x\n", file.path(wt_git, "HEAD"))
  write_text("../..\n", file.path(wt_git, "commondir"))
  wt <- withr::local_tempdir()
  write_text(paste0("gitdir: ", wt_git, "\n"), file.path(wt, ".git"))
  expect_equal(git_commit(wt), sha)
  sub <- file.path(main, "sub"); dir.create(sub)
  write_text("gitdir: ../.git/worktrees/wt\n", file.path(sub, ".git"))
  expect_equal(git_commit(sub), sha)
})

test_that("git_commit() gives NA for anything it cannot read as a commit", {
  d <- withr::local_tempdir(); heads <- file.path(d, ".git", "refs", "heads")
  dir.create(heads, recursive = TRUE)
  head <- file.path(d, ".git", "HEAD")
  write_text("ref: refs/heads/main\n", head)
  expect_true(is.na(git_commit(d)))
  write_text("ref: refs/heads/other\n", file.path(heads, "main"))
  write_text(paste0(strrep("d4", 20), "\n"), file.path(heads, "other"))
  expect_true(is.na(git_commit(d)))
  write_text(paste0(strrep("d4", 20), "\n"), file.path(d, "outside"))
  bad <- c(toupper(strrep("d4", 20)), strrep("d4", 10), strrep("d4", 32),
           "ref: refs/../../outside", "")
  for (b in bad) {
    write_text(b, head)
    expect_true(is.na(git_commit(d)), label = b)
  }
  w <- withr::local_tempdir()
  write_text("not a gitdir line\n", file.path(w, ".git"))
  expect_true(is.na(git_commit(w)))
  write_text(paste0("gitdir: ", file.path(w, "nowhere"), "\n"), file.path(w, ".git"))
  expect_true(is.na(git_commit(w)))
})

test_that("a plain project is scanned and its root is named after the folder", {
  dir <- withr::local_tempdir("myproject")
  file.copy(list.files(test_path("fixtures/project"), full.names = TRUE), dir)
  lib <- local_fake_lib(list(cli = c(Version = "3.6.6", Repository = "CRAN", License = "MIT + file LICENSE",
                                     Maintainer = "G C <g@example.org>")))
  x <- sbom(dir, lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$type[comps$is_root], "application")
  expect_match(comps$name[comps$is_root], "^myproject")
  expect_equal(comps$evidence[comps$name == "cli"], "inferred")
  expect_true("version-missing" %in% sbom_issues(x)$code)
  expect_true(any(grepl("scan of the R code", x$metadata$notes)))
})

test_that("the code scan lists the packages it finds that are not installed as unknown", {
  dir <- withr::local_tempdir("myproject")
  file.copy(list.files(test_path("fixtures/project"), full.names = TRUE), dir)
  x <- sbom(dir, lib = local_fake_lib(list(cli = c(Version = "3.6.6", Repository = "CRAN"))))
  comps <- sbom_components(x)
  root <- comps[comps$is_root, ]
  expect_equal(comps$ecosystem[comps$name == "glue"], "unknown")
  expect_true(paste0(
    "glue is named as a dependency of ", root$name, " but is not installed in ",
    "the library sbom read, so its version and source are unknown."
  ) %in% sbom_issues(x)$message[sbom_issues(x)$code == "dependency-not-installed"])
  rel <- sbom_dependencies(x)
  mine <- rel[rel$from == root$ref, ]
  # renv counts rmarkdown as a dependency of an R Markdown file.
  expect_setequal(mine$to, comps$ref[comps$name %in% c("cli", "glue", "rmarkdown")])
  expect_true(all(mine$field == "Imports" & mine$evidence == "inferred"))
  expect_equal(x$metadata$inputs$kind, c("code", "library"))
})

test_that("code the scan cannot parse is reported as an incomplete scan", {
  dir <- withr::local_tempdir()
  write_text("library(cli)\n", file.path(dir, "ok.R"))
  write_text("library(glue", file.path(dir, "bad.R"))
  x <- sbom(dir, lib = local_fake_lib(list(cli = c(Version = "3.6.6"))))
  iss <- sbom_issues(x)
  expect_equal(iss$severity[iss$code == "code-scan-incomplete"], "info")
  expect_true("cli" %in% sbom_components(x)$name)
})

test_that("the lockfile wins over the manifest, and every disagreement is reported", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  file.copy(test_path("fixtures/rsconnect/manifest.json"), dir)
  file.copy(test_path("fixtures/rsconnect/app.R"), dir)
  write_text("", file.path(dir, "default.nix"))
  x <- sbom(dir, library = local_fake_lib(list()))
  expect_true("renv.lock" %in% x$metadata$inputs$kind)
  iss <- sbom_issues(x)
  expect_true(any(iss$code == "drift-missing" & grepl("in renv.lock but not in manifest.json", iss$message)))
  expect_true(any(iss$code == "drift-extra" & grepl("ppmpkg", iss$message)))
  expect_true("nix-not-read" %in% iss$code)
})

# A folder holding the renv.lock and manifest.json fixtures, which disagree,
# and the app.R that the manifest lists.
local_lock_and_manifest <- function(env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  file.copy(test_path("fixtures/rsconnect/manifest.json"), dir)
  file.copy(test_path("fixtures/rsconnect/app.R"), dir)
  dir
}

test_that("a cross-check adds the drift it finds and nothing else", {
  dir <- local_lock_and_manifest()
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib)
  alone <- sbom_renv(file.path(dir, "renv.lock"), library = lib)
  expect_equal(sbom_components(x), sbom_components(alone))
  expect_equal(sbom_dependencies(x), sbom_dependencies(alone))
  iss <- sbom_issues(x)
  expect_equal(iss[seq_len(nrow(sbom_issues(alone))), ], sbom_issues(alone))
  added <- iss[-seq_len(nrow(sbom_issues(alone))), ]
  expect_equal(added$message, c(
    "biocpkg 1.2.3 is in renv.lock but not in manifest.json.",
    "glue 1.8.1 is in renv.lock but not in manifest.json.",
    "localpkg 0.0.1 is in renv.lock but not in manifest.json.",
    "ppmpkg 2.0.0 is in manifest.json but not in renv.lock."
  ))
  expect_equal(added$code, c(rep("drift-missing", 3), "drift-extra"))
  expect_equal(
    x$metadata$inputs,
    data.frame(kind = c("renv.lock", "library", "manifest.json", "code"),
               path = c(file.path(dir, "renv.lock"), lib, file.path(dir, "manifest.json"), dir))
  )
})

test_that("DESCRIPTION and the code report only what they use that the SBOM lacks", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text("Package: mypkg\nVersion: 1.0\nImports: cli, yyy\nSuggests: sss\n",
             file.path(dir, "DESCRIPTION"))
  dir.create(file.path(dir, "tests"))
  write_text("library(mypkg)\nlibrary(zzz)\n", file.path(dir, "tests", "run.R"))
  lib <- local_fake_lib(list())
  msg <- sbom_issues(sbom(dir, library = lib, lib = lib))$message
  expect_true("yyy is in DESCRIPTION but not in renv.lock." %in% msg)
  expect_true("zzz is in the code but not in renv.lock." %in% msg)
  expect_false(any(grepl("but not in (DESCRIPTION|the code)", msg)))
  expect_false(any(grepl("^(sss|mypkg) ", msg)))

  # As the SBOM's own source, DESCRIPTION records its Suggests too.
  file.remove(file.path(dir, "renv.lock"))
  write_text("library(sss)\n", file.path(dir, "tests", "suggested.R"))
  y <- sbom(dir, lib = lib)
  expect_equal(sbom_components(y)$name[sbom_components(y)$is_root], "mypkg")
  msg <- sbom_issues(y)$message
  expect_true("zzz is in the code but not in DESCRIPTION." %in% msg)
  expect_false(any(grepl("^(cli|yyy|sss|mypkg) is in the code", msg)))
})

test_that("a source that cannot be read is reported and not cross-checked", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text("{ not json", file.path(dir, "manifest.json"))
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib)
  iss <- sbom_issues(x)
  expect_equal(
    iss$message[iss$code == "cross-check-failed"],
    "manifest.json could not be read (The manifest 'manifest.json' is not valid JSON), so it was not cross-checked."
  )
  expect_equal(iss$severity[iss$code == "cross-check-failed"], "info")
  expect_false("manifest.json" %in% x$metadata$inputs$kind)

  # A DESCRIPTION that cannot be parsed, with the reason.
  file.remove(file.path(dir, "manifest.json"))
  write_text("Package mypkg\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  z <- sbom(dir, library = lib, lib = lib)
  expect_equal(
    sbom_issues(z)$message[sbom_issues(z)$code == "cross-check-failed"],
    "DESCRIPTION could not be read (Line starting 'Package mypkg ...' is malformed!), so it was not cross-checked."
  )
  file.remove(file.path(dir, "DESCRIPTION"))

  # Without `version`, it is not a Posit Connect manifest, so the code is read.
  file.remove(file.path(dir, "renv.lock"))
  write_text('{"packages": {}}', file.path(dir, "manifest.json"))
  y <- sbom(dir, lib = lib)
  expect_equal(y$metadata$inputs$kind, c("code", "library"))
  expect_equal(
    sbom_issues(y)$message[sbom_issues(y)$code == "cross-check-failed"],
    "manifest.json is not a Posit Connect manifest, so it was not read."
  )
  # Nor is a web app manifest.
  write_text('{"name": "x", "short_name": "x", "start_url": "."}', file.path(dir, "manifest.json"))
  w <- sbom(dir, lib = lib)
  expect_equal(
    sbom_issues(w)$message[sbom_issues(w)$code == "cross-check-failed"],
    "manifest.json is not a Posit Connect manifest, so it was not read."
  )
})

test_that("a source's read failure names no path, even for a relative folder", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text("{ not json", file.path(dir, "manifest.json"))
  lib <- local_fake_lib(list())
  withr::local_dir(dirname(dir))
  x <- sbom(basename(dir), library = lib, lib = lib)
  expect_equal(
    sbom_issues(x)$message[sbom_issues(x)$code == "cross-check-failed"],
    "manifest.json could not be read (The manifest 'manifest.json' is not valid JSON), so it was not cross-checked."
  )
})

test_that("a manifest outranks DESCRIPTION, and DESCRIPTION outranks the code", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/rsconnect/manifest.json"), dir)
  file.copy(test_path("fixtures/rsconnect/app.R"), dir)
  write_text("Package: mypkg\nVersion: 1.0\nImports: cli\n", file.path(dir, "DESCRIPTION"))
  lib <- local_fake_lib(list())
  x <- sbom(dir, lib = lib)
  expect_equal(x$metadata$inputs$kind, c("manifest.json", "DESCRIPTION", "library", "code"))
  expect_true("file/app.R" %in% sbom_components(x)$ref)
  file.remove(file.path(dir, "manifest.json"))
  y <- sbom(dir, lib = lib)
  expect_equal(sbom_components(y)$name[sbom_components(y)$is_root], "mypkg")
  expect_equal(y$metadata$inputs$kind, c("DESCRIPTION", "library", "code"))
})

test_that("sbom() passes on only the arguments its reader takes", {
  dir <- local_lock_and_manifest()
  expect_error(sbom(dir, libary = "x", foo = 1), "libary.*foo", class = "rlang_error")
  expect_error(sbom(dir, "x"), "named", class = "rlang_error")
  expect_error(sbom(dir, lib = file.path(dir, "nope")), "nope", class = "rlang_error")
  expect_error(sbom(file.path(dir, "nope")), "does not exist", class = "rlang_error")
  expect_error(sbom(file.path(dir, "renv.lock")), "renv.lock.* is not a folder", class = "rlang_error")
  # The SBOM's own source must be readable.
  write_text("{ not json", file.path(dir, "renv.lock"))
  expect_error(sbom(dir), "renv.lock.*not valid JSON", class = "rlang_error")
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir, overwrite = TRUE)
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib, dependencies = "Imports", author = "A Person")
  expect_equal(x$metadata$author, "A Person")
  # Overrides apply to the SBOM, while drift compares what the sources say.
  ov <- data.frame(component = "glue", field = "version", value = "9.9.9",
                   asserted_by = "A Person", reason = "Checked by hand.")
  y <- sbom(dir, library = lib, lib = lib, overrides = ov)
  comps <- sbom_components(y)
  expect_equal(comps$version[comps$name == "glue"], "9.9.9")
  expect_true("glue 1.8.1 is in renv.lock but not in manifest.json." %in% sbom_issues(y)$message)
})

test_that("sbom() forwards every argument the reader it picks takes", {
  dir <- withr::local_tempdir()
  write_text("Package: mypkg\nVersion: 1.0\nImports: cli\n", file.path(dir, "DESCRIPTION"))
  x <- sbom(dir, r_version = "4.6.2", lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$ref == "R"], "4.6.2")
  expect_equal(comps$version_is[comps$ref == "R"], "exact")
  # Only the readers' own arguments are taken, not the code scan's internals.
  expect_error(sbom(dir, lookup = list()), "lookup", class = "rlang_error")
})

test_that("the code scan ignores the renv that renv infers from its own lockfile", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text("library(cli)\n", file.path(dir, "analysis.R"))
  lib <- local_fake_lib(list())
  expect_false(any(grepl("^renv ", sbom_issues(sbom(dir, library = lib, lib = lib))$message)))
  expect_false(any(grepl("^renv ", sbom_issues(sbom(system.file("extdata", package = "sbom")))$message)))
})

test_that("a git project takes its commit as the version", {
  dir <- withr::local_tempdir(); sha <- strrep("e5", 20)
  dir.create(file.path(dir, ".git"))
  write_text(paste0(sha, "\n"), file.path(dir, ".git", "HEAD"))
  lib <- local_fake_lib(list())
  comps <- sbom_components(x <- sbom(dir, lib = lib))
  expect_equal(comps$version[comps$is_root], sha)
  expect_equal(comps$version_is[comps$is_root], "exact")
  expect_false("version-missing" %in% sbom_issues(x)$code)
  write_text("ref: refs/heads/main\n", file.path(dir, ".git", "HEAD"))
  y <- sbom(dir, lib = lib)
  expect_equal(
    sbom_issues(y)$message[sbom_issues(y)$code == "version-missing"],
    paste0("The git commit of the project folder ", basename(dir),
           " could not be read, so it has no version.")
  )
})

test_that("no machine path appears outside metadata$inputs", {
  dir <- local_lock_and_manifest()
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib)
  out <- paste(cdx_json(x), spdx_json(x), paste(sbom_issues(x)$message, collapse = "\n"))
  expect_false(grepl(basename(tempdir()), out, fixed = TRUE))
})

test_that("a package's code scan skips data and files R CMD build leaves out", {
  dir <- withr::local_tempdir()
  write_text("Package: tmppkg\nVersion: 1.0\nImports: cli\n", file.path(dir, "DESCRIPTION"))
  write_text("# Data scripts\n\n^data-raw$\n", file.path(dir, ".Rbuildignore"))
  files <- c(
    "R/a.R" = "cli::cli_text('a')\n",
    "tests/testthat/test-a.R" = "withr::local_tempdir()\n",
    "tests/testthat/fixtures/x.R" = "glue::glue('x')\n",
    "tests/testthat/_snaps/a.R" = "yaml::as.yaml(1)\n",
    "inst/extdata/y.R" = "jsonlite::toJSON(1)\n",
    "data-raw/z.R" = "xml2::read_xml('<a/>')\n",
    "Data-Raw.R" = "rlang::abort('x')\n"
  )
  for (f in names(files)) {
    dir.create(dirname(file.path(dir, f)), recursive = TRUE, showWarnings = FALSE)
    write_text(files[[f]], file.path(dir, f))
  }
  extra <- function(x) sbom_issues(x)$message[sbom_issues(x)$code == "drift-extra"]
  msg <- extra(sbom(dir, lib = local_fake_lib(list())))
  # The tests themselves are still scanned.
  expect_equal(msg, c(
    "rlang is in the code but not in DESCRIPTION.",
    "withr is in the code but not in DESCRIPTION."
  ))
  # Matching ignores case, as in R CMD build.
  write_text("^data-raw", file.path(dir, ".Rbuildignore"))
  expect_equal(extra(sbom(dir, lib = local_fake_lib(list()))),
               "withr is in the code but not in DESCRIPTION.")
  # Without a DESCRIPTION, every file is scanned.
  file.remove(file.path(dir, "DESCRIPTION"))
  x <- sbom(dir, lib = local_fake_lib(list()))
  expect_true(all(c("glue", "jsonlite", "xml2", "yaml") %in% sbom_components(x)$name))
})

test_that("sbom() finds no drift between this package's DESCRIPTION and its code", {
  root <- test_path("../..")
  desc <- file.path(root, "DESCRIPTION")
  skip_if_not(file.exists(desc) && identical(read_description(desc)[["Package"]], "sbom"),
              "The package source folder is not available.")
  expect_false("drift-extra" %in% sbom_issues(sbom(root))$code)
})

test_that("every reader's SBOM validates in every format and is byte-identical across runs", {
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  build <- list(
    renv = function() sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = local_fake_lib(list())),
    rsconnect = function() sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json")),
    project = function() sbom(test_path("fixtures/project"), lib = local_fake_lib(list())))
  expected <- c(`cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
                `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "pass")
  for (nm in names(build)) {
    d1 <- withr::local_tempdir(); d2 <- withr::local_tempdir()
    write_sbom(build[[nm]](), d1, format = "all"); write_sbom(build[[nm]](), d2, format = "all")
    for (f in list.files(d1)) {
      expect_identical(readBin(file.path(d1, f), "raw", 1e7), readBin(file.path(d2, f), "raw", 1e7), label = paste(nm, f))
    }
    files <- list.files(d1, full.names = TRUE)
    for (f in names(expected)) {
      file <- files[endsWith(files, sbom_formats()$extension[sbom_formats()$format == f])]
      expect_length(file, 1L)
      expect_identical(schema_validate(file, f)$status, expected[[f]], label = paste(nm, f))
    }
  }
})

test_that("a golem app's own locked package and its project root keep separate refs", {
  dir <- local_fixture_copy("fixtures/golem/myapp")
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$ref[comps$is_root], "project/myapp")
  expect_equal(comps$ecosystem[comps$is_root], "local")
  expect_equal(comps$ref[!comps$is_root & comps$name == "myapp"], "local/myapp")
  expect_equal(anyDuplicated(comps$ref), 0L)
  ids <- vapply(jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE)$packages, function(p) p$SPDXID, "")
  expect_true(all(c("SPDXRef-project-myapp", "SPDXRef-local-myapp") %in% ids))
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  expect_valid_in_every_format(x, "golem")
})

test_that("a project inside a git repository takes the repository's commit", {
  repo <- withr::local_tempdir(); sha <- strrep("f6", 20)
  dir.create(file.path(repo, ".git"))
  write_text(paste0(sha, "\n"), file.path(repo, ".git", "HEAD"))
  sub <- file.path(repo, "apps", "report")
  dir.create(sub, recursive = TRUE)
  expect_equal(git_commit(sub), sha)
  lib <- local_fake_lib(list())
  x <- sbom(sub, lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$is_root], sha)
  expect_false("version-missing" %in% sbom_issues(x)$code)
  # The nearest .git decides, even when its commit cannot be read.
  write_text("ref: refs/heads/main\n", file.path(repo, ".git", "HEAD"))
  y <- sbom(sub, lib = lib)
  expect_equal(
    sbom_issues(y)$message[sbom_issues(y)$code == "version-missing"],
    "The git commit of the project folder report could not be read, so it has no version."
  )
})

test_that("a DESCRIPTION without a Package field is used only for the dependencies it declares", {
  dir <- withr::local_tempdir()
  write_text("Type: project\nTitle: My analysis\nImports: cli, yyy\nSuggests: sss\n", file.path(dir, "DESCRIPTION"))
  write_text("library(cli)\n", file.path(dir, "a.R"))
  lib <- local_fake_lib(list(cli = c(Version = "3.6.6", Repository = "CRAN")))
  partial <- "DESCRIPTION has no Package field, so it was used only for the dependencies it declares."
  x <- sbom(dir, lib = lib)
  expect_equal(x$metadata$inputs$kind, c("code", "library", "DESCRIPTION"))
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "cross-check-partial"], partial)
  expect_equal(iss$severity[iss$code == "cross-check-partial"], "info")
  expect_false("cross-check-failed" %in% iss$code)
  # Behind a lockfile, its Depends and Imports are cross-checked.
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  y <- sbom(dir, library = lib, lib = lib)
  msg <- sbom_issues(y)$message
  expect_true(partial %in% msg)
  expect_true("yyy is in DESCRIPTION but not in renv.lock." %in% msg)
  expect_false(any(grepl("^(cli|sss) is in DESCRIPTION", msg)))
  expect_false("cross-check-failed" %in% sbom_issues(y)$code)
  expect_true("DESCRIPTION" %in% y$metadata$inputs$kind)
})

test_that("a nested project's code is not scanned as the parent's", {
  dir <- withr::local_tempdir()
  files <- c(
    "analysis.R" = "library(cli)\n",
    "notes/extra.R" = "library(withr)\n",
    "pkg/DESCRIPTION" = "Package: inner\nVersion: 1.0\nImports: glue\n",
    "pkg/R/inner.R" = "glue::glue('x')\n",
    "app/renv.lock" = '{"R": {"Version": "4.5.0"}, "Packages": {}}',
    "app/deep/app.R" = "library(yaml)\n",
    "deploy/manifest.json" = '{"version": 1, "packages": {}}',
    "deploy/server.R" = "library(jsonlite)\n"
  )
  for (f in names(files)) {
    dir.create(dirname(file.path(dir, f)), recursive = TRUE, showWarnings = FALSE)
    write_text(files[[f]], file.path(dir, f))
  }
  lib <- local_fake_lib(list(cli = c(Version = "3.6.6"), withr = c(Version = "3.0.0")))
  root_deps <- function(x) {
    comps <- sbom_components(x)
    rel <- sbom_dependencies(x)
    comps$name[match(rel$to[rel$from == comps$ref[comps$is_root]], comps$ref)]
  }
  expect_setequal(root_deps(sbom(dir, lib = lib)), c("cli", "withr"))
  lock <- list(R = list(Version = "4.5.0"), Packages = list(
    cli = list(Package = "cli", Version = "3.6.6", Source = "Repository", Repository = "CRAN"),
    glue = list(Package = "glue", Version = "1.8.1", Source = "Repository", Repository = "CRAN")
  ))
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  x <- sbom(dir, library = lib, lib = lib)
  expect_equal(root_deps(x), "cli")
  extra <- sbom_issues(x)$message[sbom_issues(x)$code == "drift-extra"]
  expect_equal(extra[grepl("in the code", extra)], "withr is in the code but not in renv.lock.")
})

test_that("sbom() applies sbom-overrides.csv from the folder unless overrides are given", {
  dir <- local_lock_and_manifest()
  csv <- file.path(dir, "sbom-overrides.csv")
  write_text("component,field,value,asserted_by,reason\nglue,license_spdx,Apache-2.0,A Person,Checked by hand.\n", csv)
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$license_spdx[comps$name == "glue"], "Apache-2.0")
  expect_equal(x$metadata$inputs[x$metadata$inputs$kind == "overrides", "path"], csv)
  ov <- data.frame(component = "glue", field = "version", value = "9.9.9",
                   asserted_by = "A Person", reason = "Checked by hand.")
  y <- sbom(dir, library = lib, lib = lib, overrides = ov)
  comps <- sbom_components(y)
  expect_equal(comps$license_spdx[comps$name == "glue"], "MIT")
  expect_equal(comps$version[comps$name == "glue"], "9.9.9")
  expect_false("overrides" %in% y$metadata$inputs$kind)
})

test_that("a read failure's reason names no path, whatever cli's colours", {
  withr::local_options(cli.num_colors = 256)
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text("{ not json", file.path(dir, "manifest.json"))
  x <- sbom(dir, library = local_fake_lib(list()))
  msg <- paste(sbom_issues(x)$message, collapse = " ")
  expect_false(grepl(dir, msg, fixed = TRUE))
  expect_false(grepl(normalizePath(dir), msg, fixed = TRUE))
  expect_false(grepl("\033[", msg, fixed = TRUE))
})

test_that("git_commit() does not take a commit from a repository at the home folder", {
  home <- withr::local_tempdir()
  proj <- file.path(home, "work", "proj")
  dir.create(proj, recursive = TRUE)
  dir.create(file.path(home, ".git", "refs", "heads"), recursive = TRUE)
  write_text(paste0(strrep("c3", 20), "\n"), file.path(home, ".git", "HEAD"))
  withr::local_envvar(HOME = home)
  expect_true(is.na(git_commit(proj)))
  # A repository below the home folder is still found.
  dir.create(file.path(proj, ".git"))
  write_text(paste0(strrep("d4", 20), "\n"), file.path(proj, ".git", "HEAD"))
  expect_equal(git_commit(proj), strrep("d4", 20))
})
