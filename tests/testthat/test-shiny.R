shiny_fixture <- function(...) test_path("fixtures", "shiny", ...)

test_that("each Shiny layout is recognised, and other folders are not", {
  f <- function(x) shiny_layout(shiny_fixture(x))
  expect_equal(f("app-r"), "app.R")
  expect_equal(f("ui-server"), "ui-server")
  expect_equal(f("golem"), "golem")
  expect_equal(f("rhino"), "rhino")
  expect_true(is.na(shiny_layout(test_path("fixtures", "pkgs", "srcpkg"))))
})

test_that("an app's root is an application, and its own JavaScript is nested under it", {
  x <- sbom_shiny(shiny_fixture("app-r"), system = FALSE)
  comps <- sbom_components(x)
  root <- comps[comps$is_root, ]
  expect_equal(root$type, "application")
  expect_equal(root$ref, "project/app-r")
  js <- comps[grepl("project/app-r#js/jquery@3.5.1", comps$ref, fixed = TRUE), ]
  expect_equal(nrow(js), 1L)
  expect_equal(js$parent_ref, root$ref)
  expect_true(all(c("shiny", "DT") %in% comps$name))
  expect_true(any(x$relationships$from == root$ref & x$relationships$to == js$ref))
})

test_that("a ui.R and server.R app is an app, whose root is its folder", {
  x <- sbom_shiny(shiny_fixture("ui-server"), system = FALSE)
  root <- sbom_components(x)[sbom_components(x)$is_root, ]
  expect_equal(c(root$ref, root$type), c("project/ui-server", "application"))
})

test_that("a golem app takes its name and version from DESCRIPTION", {
  x <- sbom_shiny(shiny_fixture("golem"), system = FALSE)
  comps <- sbom_components(x)
  root <- comps[comps$is_root, ]
  expect_equal(
    c(root$ref, root$version, root$type, root$evidence),
    c("project/golemapp", "0.1.0", "application", "declared")
  )
  expect_equal(root$version_is, "exact")
  # The rewrite reaches every place the old root was named.
  expect_equal(x$metadata$root, "project/golemapp")
  expect_false(any(grepl("golemapp", c(comps$ref, x$relationships$from, x$issues$ref), fixed = TRUE) &
    !grepl("^project/golemapp", c(comps$ref, x$relationships$from, x$issues$ref))))
  expect_true(all(x$relationships$from %in% comps$ref))
  expect_true(all(x$relationships$to %in% comps$ref))
  expect_true(all(x$issues$ref %in% c(comps$ref, NA)))
  expect_true(all(comps$parent_ref[!is.na(comps$parent_ref)] %in% comps$ref))
  expect_true(all(c("shiny", "golem") %in% comps$name))
  # The DESCRIPTION is the source, not a code scan.
  expect_false(any(grepl("scan of the R code", x$metadata$notes)))
  expect_equal(sum(comps$name == "custom.js"), 0L)
})

test_that("the root rewrite also reaches an app built from the code scan or a lockfile", {
  x <- sbom_shiny(shiny_fixture("app-r"), system = FALSE)
  expect_equal(x$metadata$root, "project/app-r")
  expect_true(all(x$relationships$from %in% sbom_components(x)$ref))

  dir <- withr::local_tempdir()
  file.copy(shiny_fixture("app-r", c("app.R", "www")), dir, recursive = TRUE)
  file.copy(test_path("fixtures", "renv", "modern", "renv.lock"), file.path(dir, "renv.lock"))
  y <- sbom_shiny(dir, system = FALSE)
  root <- sbom_components(y)[sbom_components(y)$is_root, ]
  expect_equal(root$type, "application")
  expect_equal(y$metadata$root, root$ref)
  expect_true(all(y$relationships$from %in% sbom_components(y)$ref))
})

test_that("replace_root() rewrites every ref that is, or is under, the old root", {
  x <- sbom_package(test_path("fixtures", "golem", "myapp"), system = FALSE)
  old <- x$metadata$root
  new <- component_row(ref = "project/other", name = "other", type = "application",
    is_root = TRUE, ecosystem = "local")
  y <- replace_root(x, new)
  expect_equal(y$metadata$root, "project/other")
  expect_false(any(startsWith(y$components$ref, old)))
  expect_false(any(c(y$relationships$from, y$relationships$to) == old, na.rm = TRUE))
  expect_false(any(y$issues$ref == old, na.rm = TRUE))
  expect_equal(sum(y$components$is_root), 1L)
  expect_equal(nrow(y$components), nrow(x$components))
  # The old root's licence is kept; its package URL is not.
  root <- y$components[y$components$is_root, ]
  expect_equal(root$license_spdx, "MIT")
  expect_true(is.na(root$purl))
})

test_that("rhino's npm files are an issue, and a folder that is not an app is an error", {
  x <- sbom_shiny(shiny_fixture("rhino"), system = FALSE)
  issues <- sbom_issues(x)
  expect_equal(sum(issues$code == "npm-not-covered"), 1L)
  expect_equal(
    issues$message[issues$code == "npm-not-covered"],
    paste0("The app's npm dependencies in .rhino/package.json are not in this SBOM, ",
      "because sbom does not read npm files yet.")
  )
  expect_error(sbom_shiny(test_path("fixtures", "pkgs", "srcpkg")), "does not look like a Shiny app")
})

test_that("sbom() sends an app folder to sbom_shiny()", {
  a <- sbom(shiny_fixture("app-r"), system = FALSE, timestamp = 0)
  b <- sbom_shiny(shiny_fixture("app-r"), system = FALSE, timestamp = 0)
  expect_identical(sbom_components(a), sbom_components(b))
  # Other folders ignore evaluate_ui.
  expect_no_error(sbom(test_path("fixtures", "pkgs", "srcpkg"), evaluate_ui = TRUE, system = FALSE))
})

test_that("a Posit Connect manifest adds its sentence to the notes once, whichever source built the SBOM", {
  dir <- withr::local_tempdir()
  write_text("library(shiny)\n", file.path(dir, "app.R"))
  write_text(
    paste0(
      '{"version": 1, "metadata": {"appmode": "shiny"}, "locale": "en_US", "platform": "4.4.0",',
      ' "packages": {}, "files": {}}'
    ),
    file.path(dir, "manifest.json")
  )
  x <- sbom_shiny(dir, system = FALSE)
  expect_equal(sum(x$metadata$notes == "Deployed to Posit Connect as a shiny application."), 1L)
  write_text(
    '{"R": {"Version": "4.4.0", "Repositories": []}, "Packages": {}}',
    file.path(dir, "renv.lock")
  )
  y <- sbom_shiny(dir, system = FALSE)
  expect_equal(sum(y$metadata$notes == "Deployed to Posit Connect as a shiny application."), 1L)
})

test_that("a www/ folder with a symlink loop, non-library files and a deep tree stays bounded", {
  skip_on_os("windows")
  dir <- withr::local_tempdir()
  write_text("library(shiny)\n", file.path(dir, "app.R"))
  deep <- file.path(dir, "www", "a", "b", "c", "d", "e", "f", "g")
  dir.create(deep, recursive = TRUE)
  file.symlink(file.path(dir, "www"), file.path(dir, "www", "a", "loop"))
  # Beyond the 6 levels.
  write_text("/*! jQuery v3.5.1 */\n", file.path(deep, "jquery.min.js"))
  # A real library inside www/, which must be found, so that the test can fail.
  dir.create(file.path(dir, "www", "js"))
  write_text("/*! jQuery v3.5.1 */\n", file.path(dir, "www", "js", "jquery.min.js"))
  # A library reachable only through a symlinked folder, at depth 1.
  outside <- file.path(dir, "outside")
  dir.create(outside)
  write_text("/*! jQuery v2.2.4 */\n", file.path(outside, "jquery.min.js"))
  file.symlink(outside, file.path(dir, "www", "linked"))
  # A big file without a header, and a stylesheet naming no known library.
  write_text(strrep("var x = 1;\n", 100000L), file.path(dir, "www", "jquery.js"))
  write_text("/*! Mystery Library v9.9.9 */\nbody {}\n", file.path(dir, "www", "site.css"))

  x <- expect_no_error(sbom_shiny(dir, system = FALSE, lib = character()))
  refs <- sbom_components(x)$ref
  expect_equal(refs[grepl("#js/", refs, fixed = TRUE)], paste0(x$metadata$root, "#js/jquery@3.5.1"))
  expect_false(any(grepl("Mystery", sbom_components(x)$name)))
})

test_that("no issue about the root is repeated, in any layout or source", {
  lib <- local_fake_lib(list())
  for (layout in c("app-r", "ui-server", "golem", "rhino")) {
    for (lock in c(FALSE, TRUE)) {
      dir <- withr::local_tempdir()
      src <- shiny_fixture(layout)
      file.copy(list.files(src, full.names = TRUE, all.files = TRUE, no.. = TRUE), dir, recursive = TRUE)
      if (lock) {
        file.copy(test_path("fixtures", "renv", "modern", "renv.lock"), file.path(dir, "renv.lock"))
      }
      x <- sbom_shiny(dir, system = FALSE, lib = lib, library = lib)
      info <- paste(layout, "lock =", lock)
      expect_false(any(duplicated(sbom_issues(x))), info = info)
      expect_equal(x$metadata$root, sbom_components(x)$ref[sbom_components(x)$is_root], info = info)
      if (layout == "golem") {
        iss <- sbom_issues(x)
        msg <- iss$message[iss$ref == "project/golemapp"]
        expect_false(any(grepl("installed from a local source|is not a git repository", msg)), info = info)
        expect_false(any(grepl("names no maintainer", msg)), info = info)
      }
    }
  }
})

test_that("a folder with renv.lock, a Connect manifest and app.R keeps its drift and notes once", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures", "renv", "modern", "renv.lock"), dir)
  file.copy(test_path("fixtures", "rsconnect", c("manifest.json", "app.R")), dir)
  lib <- local_fake_lib(list())
  x <- sbom(dir, library = lib, lib = lib, system = FALSE)
  root <- sbom_components(x)[sbom_components(x)$is_root, ]
  expect_equal(root$type, "application")
  notes <- x$metadata$notes
  expect_equal(sum(startsWith(notes, "Deployed to Posit Connect")), 1L)
  iss <- sbom_issues(x)
  expect_true(any(iss$code == "drift-missing" & grepl("in renv.lock but not in manifest.json", iss$message)))
  expect_true(any(iss$code == "drift-extra" & grepl("in manifest.json but not in renv.lock", iss$message)))
  expect_false(any(duplicated(iss)))
})

test_that("sbom() accepts evaluate_ui = FALSE for an app", {
  expect_no_error(sbom(shiny_fixture("app-r"), evaluate_ui = FALSE, system = FALSE))
})

test_that("evaluated UI dependencies are observed and nested under the package that ships them", {
  local_mocked_bindings(sys_ui_dependencies = function(dir, layout, ...) data.frame(
    name = c("jquery", "bootstrap", "appjs"), version = c("3.7.1", "3.4.1", "1.0"),
    package = c("shiny", "shiny", NA), src = c("file", "file", "file")))
  x <- sbom_shiny(test_path("fixtures", "shiny", "app-r"), evaluate_ui = TRUE, system = FALSE)
  comps <- sbom_components(x)
  shiny_ref <- comps$ref[comps$name == "shiny" & !grepl("#", comps$ref)]
  jq <- comps[comps$ref == paste0(shiny_ref, "#js/jquery@3.7.1"), ]
  expect_equal(jq$evidence, "observed")
  expect_equal(jq$parent_ref, shiny_ref)
  expect_true(any(comps$ref == "project/app-r#js/appjs@1.0"))
})

test_that("an evaluated dependency matching a static one raises its evidence, and a known name gets an npm purl", {
  local_mocked_bindings(sys_ui_dependencies = function(dir, layout, ...) data.frame(
    name = "jquery", version = "3.5.1", package = NA_character_, src = "file"))
  x <- sbom_shiny(test_path("fixtures", "shiny", "app-r"), evaluate_ui = TRUE, system = FALSE)
  comps <- sbom_components(x)
  jq <- comps[comps$ref == "project/app-r#js/jquery@3.5.1", ]
  expect_equal(nrow(jq), 1L)
  expect_equal(jq$evidence, "observed")
  expect_equal(jq$purl, "pkg:npm/jquery@3.5.1")
  expect_equal(sum(comps$ref == "project/app-r#js/jquery@3.5.1"), 1L)
  rel <- x$relationships
  expect_equal(rel$evidence[rel$to == "project/app-r#js/jquery@3.5.1"], "observed")
})

test_that("a UI that cannot be evaluated gives one issue and the static result", {
  local_mocked_bindings(sys_ui_dependencies = function(dir, layout, ...) structure(list(), reason = "the UI code failed"))
  x <- sbom_shiny(test_path("fixtures", "shiny", "app-r"), evaluate_ui = TRUE, system = FALSE)
  iss <- sbom_issues(x)
  expect_equal(sum(iss$code == "evaluate-ui-failed"), 1L)
  expect_equal(
    iss$message[iss$code == "evaluate-ui-failed"],
    paste0("sbom could not evaluate the app's UI (the UI code failed), so its browser ",
      "assets come from static detection only.")
  )
  expect_true(any(grepl("#js/jquery@3.5.1", sbom_components(x)$ref, fixed = TRUE)))
})

test_that("the lib the build uses reaches the wrapper", {
  seen <- new.env()
  local_mocked_bindings(sys_ui_dependencies = function(dir, layout, lib, ...) {
    seen$lib <- lib
    structure(list(), reason = "x")
  })
  lib <- withr::local_tempdir()
  sbom_shiny(test_path("fixtures", "shiny", "app-r"), evaluate_ui = TRUE, system = FALSE, lib = lib)
  expect_equal(seen$lib, lib)
  sbom_shiny(test_path("fixtures", "shiny", "app-r"), evaluate_ui = TRUE, system = FALSE)
  expect_equal(seen$lib, .libPaths())
})

test_that("golem apps are not evaluated", {
  x <- sbom_shiny(test_path("fixtures", "shiny", "golem"), evaluate_ui = TRUE, system = FALSE)
  iss <- sbom_issues(x)
  expect_equal(sum(iss$code == "evaluate-ui-unsupported"), 1L)
  expect_equal(iss$severity[iss$code == "evaluate-ui-unsupported"], "info")
  expect_match(
    iss$message[iss$code == "evaluate-ui-unsupported"],
    "sbom can evaluate the UI only of app.R and ui.R apps, so this golem app's browser assets come from static detection only.",
    fixed = TRUE
  )
})

test_that("a real UI evaluates in a child process and leaves this session alone", {
  skip_on_cran()
  skip_if_not_installed("shiny")
  skip_if_not_installed("htmltools")
  local_mocked_bindings(sys_ui_dependencies = sys_ui_dependencies_real)
  state <- function() list(search(), options(), ls(globalenv()), Sys.getenv("R_LIBS", unset = NA))
  before <- state()
  x <- sbom_shiny(test_path("fixtures", "shiny", "ui-server"), evaluate_ui = TRUE, system = FALSE)
  expect_identical(state(), before)
  expect_false(any(sbom_issues(x)$code == "evaluate-ui-failed"))
  comps <- sbom_components(x)
  expect_equal(unique(comps$evidence[grepl("#js/jquery@", comps$ref, fixed = TRUE) & comps$evidence == "observed"]), "observed")
  expect_true(any(grepl("#js/jquery@", comps$ref, fixed = TRUE)))
  expect_false(any(grepl(tempdir(), c(comps$ref, comps$description), fixed = TRUE), na.rm = TRUE))
})

test_that("the child reports a UI that errors, or defines none, or never returns", {
  skip_on_cran()
  skip_if_not_installed("htmltools")
  app <- function(code) {
    dir <- withr::local_tempdir(.local_envir = parent.frame())
    write_text(code, file.path(dir, "app.R"))
    dir
  }
  run <- function(code, timeout = 60) sys_ui_dependencies_real(app(code), "app.R", timeout = timeout)

  r <- run("ui <- stop('boom\nsecond line')")
  expect_false(is.data.frame(r))
  expect_equal(attr(r, "reason"), "the UI code failed")

  r <- run("library(notAPackageAnywhere)\nui <- 1")
  expect_false(is.data.frame(r))
  expect_equal(attr(r, "reason"), "the UI needs the package notAPackageAnywhere, which is not installed")

  r <- run("ui <- stop()")
  expect_equal(attr(r, "reason"), "the UI code failed")

  r <- run("x <- 1")
  expect_false(is.data.frame(r))
  expect_equal(attr(r, "reason"), "the app defines no ui object")

  r <- run("ui <- function(request) repeat Sys.sleep(1)", timeout = 2)
  expect_false(is.data.frame(r))
  expect_equal(attr(r, "reason"), "the UI did not finish within 2 seconds")
  r <- run("repeat Sys.sleep(1)", timeout = 2)
  expect_equal(attr(r, "reason"), "the UI did not finish within 2 seconds")

  r <- run("ui <- htmltools::tagList(htmltools::tags$p('hi'))")
  expect_s3_class(r, "data.frame")
  expect_equal(nrow(r), 0L)
  expect_named(r, c("name", "version", "package", "src"))
})

test_that("an app's error text, with its paths, never reaches the document", {
  skip_on_cran()
  skip_if_not_installed("htmltools")
  dir <- withr::local_tempdir()
  secret <- normalizePath(tempdir())
  write_text("ui <- stop(paste('cannot open', normalizePath(tempdir())))\n", file.path(dir, "app.R"))
  r <- sys_ui_dependencies_real(dir, "app.R")
  expect_equal(attr(r, "reason"), "the UI code failed")
  local_mocked_bindings(sys_ui_dependencies = sys_ui_dependencies_real)
  x <- sbom_shiny(dir, evaluate_ui = TRUE, system = FALSE)
  expect_equal(sum(sbom_issues(x)$code == "evaluate-ui-failed"), 1L)
  expect_false(any(grepl(secret, sbom_issues(x)$message, fixed = TRUE)))
})

test_that("two evaluated dependencies with one ref give one component", {
  dir <- withr::local_tempdir(pattern = "app-r")
  write_text("ui <- 1\n", file.path(dir, "app.R"))
  local_mocked_bindings(sys_ui_dependencies = function(dir, layout, ...) data.frame(
    name = c("jquery", "jquery"), version = c("3.6.0", "3.6.0"),
    package = c("jquerylib", "bslib"), src = c("file", "file")))
  x <- sbom_shiny(dir, evaluate_ui = TRUE, system = FALSE, lib = character())
  comps <- sbom_components(x)
  expect_false(any(c("jquerylib", "bslib") %in% comps$name))
  ref <- paste0(x$metadata$root, "#js/jquery@3.6.0")
  expect_equal(sum(comps$ref == ref), 1L)
  expect_false(any(duplicated(comps$ref)))
  expect_false(any(duplicated(x$relationships[c("from", "to", "field")])))
})
