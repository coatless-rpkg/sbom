ts <- as.POSIXct("2026-01-01", tz = "UTC")

# The study and the analysis, each built from its own folder.
two_projects <- function() {
  list(
    study = sbom(sbom_example("study", copy = TRUE), system = FALSE, timestamp = ts),
    analysis = sbom(sbom_example("analysis", copy = TRUE), system = FALSE, timestamp = ts)
  )
}

# A copy of example `name` in a new folder called `as`, inside a folder of
# its own, so that two copies can share a name.
example_as <- function(name, as, env = parent.frame()) {
  home <- withr::local_tempdir(.local_envir = env)
  dir.create(file.path(home, as))
  from <- sbom_example(name)
  file.copy(list.files(from, full.names = TRUE, all.files = TRUE, no.. = TRUE),
    file.path(home, as), recursive = TRUE)
  file.path(home, as)
}

test_that("combine_sbom() puts the SBOMs under one new root", {
  skip_on_cran()
  p <- two_projects()
  x <- combine_sbom(p$study, p$analysis, name = "suite", timestamp = ts)
  comps <- sbom_components(x)
  expect_s3_class(x, "sbom")
  expect_equal(comps$ref[comps$is_root], "combined/suite")
  expect_equal(x$metadata$root, "combined/suite")
  root <- comps[comps$is_root, ]
  expect_equal(root$name, "suite")
  expect_equal(root$type, "application")
  rels <- sbom_dependencies(x)
  under <- rels[rels$from == "combined/suite", ]
  expect_setequal(under$to, c("project/study", "project/analysis"))
  expect_equal(unique(under$field), "depends_on")
  expect_false(any(comps$is_root[comps$ref %in% c("project/study", "project/analysis")]))
})

test_that("combine_sbom() takes a list as well as separate SBOMs", {
  skip_on_cran()
  p <- two_projects()
  expect_equal(
    combine_sbom(p, name = "suite", timestamp = ts),
    combine_sbom(p$study, p$analysis, name = "suite", timestamp = ts)
  )
})

test_that("a component in both SBOMs is listed once", {
  p <- two_projects()
  x <- combine_sbom(p$study, p$analysis, name = "suite", timestamp = ts)
  refs <- sbom_components(x)$ref
  expect_false(anyDuplicated(refs) > 0)
  expect_equal(sum(refs == "R"), 1L)
  n_in <- length(union(p$study$components$ref, p$analysis$components$ref))
  expect_equal(length(refs), n_in + 1L)
})

test_that("two versions of one package are both listed", {
  locked <- sbom_renv(file.path(sbom_example("analysis"), "renv.lock"), system = FALSE, timestamp = ts)
  installed <- sbom_installed("cli", lib = sbom_example("library"), system = FALSE, timestamp = ts)
  x <- combine_sbom(locked, installed, name = "both", timestamp = ts)
  comps <- sbom_components(x)
  expect_setequal(comps$version[comps$name == "cli"], c("3.6.5", "3.6.6"))
})

test_that("a ref that names different components in two SBOMs is made unique", {
  a <- sbom(example_as("study", "app"), system = FALSE, timestamp = ts)
  later <- example_as("study", "app")
  lock <- readLines(file.path(later, "renv.lock"))
  writeLines(sub('"Version": "0.3.0"', '"Version": "0.4.0"', lock, fixed = TRUE), file.path(later, "renv.lock"))
  b <- sbom(later, system = FALSE, timestamp = ts)

  x <- combine_sbom(a, b, name = "two-apps", timestamp = ts)
  comps <- sbom_components(x)
  expect_false(anyDuplicated(comps$ref) > 0)
  expect_true(all(c("project/app", "project/app~2", "local/inhouse", "local/inhouse@0.4.0") %in% comps$ref))
  expect_equal(comps$version[comps$ref == "local/inhouse@0.4.0"], "0.4.0")

  rels <- sbom_dependencies(x)
  expect_true(any(rels$from == "project/app~2" & rels$to == "local/inhouse@0.4.0"))
  expect_true(any(rels$from == "local/inhouse@0.4.0" & rels$to == "pkg:cran/holeypkg@1.0.0"))
  expect_true(any(rels$from == "combined/two-apps" & rels$to == "project/app~2"))
  expect_true(all(c(rels$from, rels$to) %in% comps$ref))
  issues <- sbom_issues(x)
  expect_true(all(issues$ref %in% comps$ref))
  expect_true("project/app~2" %in% issues$ref)
})

test_that("nested refs follow their renamed parent", {
  a <- sbom(example_as("study", "app"), system = FALSE, timestamp = ts)
  b <- sbom(example_as("study", "app"), system = FALSE, timestamp = ts)
  nested <- component_row(
    ref = "project/app#js/jquery@3.7.1", name = "jquery", version = "3.7.1", type = "library",
    ecosystem = "npm", scope = "required", parent_ref = "project/app", evidence = "inferred"
  )
  b$components <- rbind(b$components, nested)
  b$relationships <- rbind(b$relationships, data.frame(
    from = "project/app", to = "project/app#js/jquery@3.7.1", field = "contains",
    spec = NA_character_, evidence = "inferred"
  ))
  x <- combine_sbom(a, b, name = "two-apps", timestamp = ts)
  comps <- sbom_components(x)
  expect_equal(comps$parent_ref[comps$ref == "project/app~2#js/jquery@3.7.1"], "project/app~2")
})

test_that("the combined SBOM states its own author, timestamp and version", {
  skip_on_cran()
  p <- two_projects()
  x <- combine_sbom(p, name = "suite", version = "1.2.0", author = "Jo Reviewer", timestamp = ts)
  expect_equal(x$metadata$author, "Jo Reviewer")
  expect_equal(x$metadata$timestamp, ts)
  root <- sbom_components(x)[sbom_components(x)$is_root, ]
  expect_equal(root$version, "1.2.0")
  expect_equal(root$version_is, "exact")
  expect_false("no-sbom-author" %in% sbom_issues(x)$code)
  expect_false(any(sbom_issues(x)$ref == "combined/suite" & sbom_issues(x)$code == "version-missing"))

  y <- combine_sbom(p, name = "suite", timestamp = ts)
  issues <- sbom_issues(y)
  expect_equal(issues$ref[issues$code == "no-sbom-author"], "combined/suite")
  expect_equal(issues$ref[issues$code == "version-missing" & issues$ref == "combined/suite"], "combined/suite")
  expect_true(all(c("project/study", "project/analysis") %in% issues$ref[issues$code == "version-missing"]))
})

test_that("notes about each input's timestamp are not carried over", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "1767225600")
  a <- sbom(sbom_example("study", copy = TRUE), system = FALSE)
  b <- sbom(sbom_example("analysis", copy = TRUE), system = FALSE)
  x <- combine_sbom(a, b, name = "suite", timestamp = ts)
  expect_false(any(grepl("SOURCE_DATE_EPOCH", x$metadata$notes)))
  y <- combine_sbom(a, b, name = "suite")
  expect_equal(sum(grepl("SOURCE_DATE_EPOCH", y$metadata$notes)), 1L)
})

test_that("overrides apply to the combined SBOM", {
  p <- two_projects()
  ov <- data.frame(
    component = "inhouse", field = "license_spdx", value = "MIT",
    asserted_by = "Legal", reason = "Checked the LICENSE file."
  )
  x <- combine_sbom(p, name = "suite", timestamp = ts, overrides = ov)
  comps <- sbom_components(x)
  expect_equal(comps$license_spdx[comps$name == "inhouse"], "MIT")
})

test_that("advisories that every SBOM lists from the same data are kept", {
  skip_on_cran()
  osv <- sbom_example("osv-all.zip")
  a <- sbom(sbom_example("study", copy = TRUE), system = FALSE, timestamp = ts, advisories = osv)
  b <- sbom(sbom_example("analysis", copy = TRUE), system = FALSE, timestamp = ts, advisories = osv)
  x <- combine_sbom(a, b, name = "suite", timestamp = ts)
  expect_equal(advisories_status(x), "listed")
  expect_equal(x$advisories$id, "EXAMPLE-2026-1")
  expect_equal(sum(x$metadata$notes == advisory_notes$listed), 1L)
})

test_that("advisories that only some SBOMs list are dropped, with an issue", {
  skip_on_cran()
  osv <- sbom_example("osv-all.zip")
  a <- sbom(sbom_example("study", copy = TRUE), system = FALSE, timestamp = ts, advisories = osv)
  b <- sbom(sbom_example("analysis", copy = TRUE), system = FALSE, timestamp = ts)
  x <- combine_sbom(a, b, name = "suite", timestamp = ts)
  expect_equal(advisories_status(x), "not-requested")
  expect_equal(nrow(x$advisories), 0L)
  expect_true("advisories-not-combined" %in% sbom_issues(x)$code)
  expect_false(advisory_notes$listed %in% x$metadata$notes)
  expect_true(advisory_notes$no_data %in% x$metadata$notes)
  expect_false("advisories" %in% x$metadata$inputs$kind)
})

test_that("advisories asked of combine_sbom() are looked up for every component", {
  p <- two_projects()
  x <- combine_sbom(p, name = "suite", timestamp = ts, advisories = sbom_example("osv-all.zip"))
  expect_equal(advisories_status(x), "listed")
  affects <- x$advisories$affects[[1]]
  expect_equal(affects$ref, "pkg:cran/holeypkg@1.0.0")
})

test_that("a combined SBOM writes valid documents and reads back the same", {
  skip_on_cran()
  p <- two_projects()
  x <- combine_sbom(p, name = "suite", version = "1.0.0", author = "Jo Reviewer", timestamp = ts)
  for (ext in c(".cdx.json", ".spdx.json", ".cdx.xml")) {
    f <- withr::local_tempfile(fileext = ext)
    write_sbom(x, f)
    v <- validate_sbom(f, profile = "none")
    expect_false(identical(v$status, "fail"), info = ext)
    expect_equal(nrow(as.data.frame(sbom_diff(x, read_sbom(f)))), 0L, info = ext)
  }
})

test_that("an SBOM read from a file combines with one built here", {
  skip_on_cran()
  p <- two_projects()
  d <- read_sbom(sbom_example("dashboard.cdx.json"))
  x <- combine_sbom(p$study, d, name = "estate", timestamp = ts)
  comps <- sbom_components(x)
  expect_true(d$metadata$root %in% comps$ref)
  expect_false(anyDuplicated(comps$ref) > 0)
})

test_that("combine_sbom() checks its arguments", {
  skip_on_cran()
  p <- two_projects()
  expect_error(combine_sbom(name = "suite"), "at least one")
  expect_error(combine_sbom(p$study, "analysis", name = "suite"), "<sbom>")
  expect_error(combine_sbom(p$study, p$analysis), "`name`")
  expect_error(combine_sbom(p$study, p$analysis, name = c("a", "b")), "`name` must be a single string")
  expect_error(combine_sbom(p$study, p$analysis, name = ""), "`name` must be a single string")
  expect_error(combine_sbom(p$study, p$analysis, name = "suite", version = 1), "`version` must be")
})

test_that("sbom() combines several paths into one SBOM", {
  skip_on_cran()
  study <- sbom_example("study", copy = TRUE)
  analysis <- sbom_example("analysis", copy = TRUE)
  x <- sbom(c(study, analysis), name = "suite", system = FALSE, timestamp = ts)
  y <- combine_sbom(
    sbom(study, system = FALSE, timestamp = ts),
    sbom(analysis, system = FALSE, timestamp = ts),
    name = "suite", timestamp = ts
  )
  expect_equal(x, y)
})

test_that("sbom() with several paths applies author and advisories once, to the result", {
  skip_on_cran()
  study <- sbom_example("study", copy = TRUE)
  analysis <- sbom_example("analysis", copy = TRUE)
  x <- sbom(c(study, analysis), name = "suite", system = FALSE, timestamp = ts,
    author = "Jo Reviewer", advisories = sbom_example("osv-all.zip"))
  expect_equal(x$metadata$author, "Jo Reviewer")
  expect_false("no-sbom-author" %in% sbom_issues(x)$code)
  expect_equal(advisories_status(x), "listed")
  expect_equal(sum(x$metadata$inputs$kind == "advisories"), 1L)
})

test_that("sbom() with several paths needs a name, and each path once", {
  study <- sbom_example("study", copy = TRUE)
  analysis <- sbom_example("analysis", copy = TRUE)
  expect_error(sbom(c(study, analysis), system = FALSE), "give it a `name`")
  expect_error(sbom(c(study, file.path(study, ".")), name = "suite", system = FALSE), "more than once")
  expect_error(sbom(study, name = "suite", system = FALSE), "more than one path")
  expect_error(sbom(c(study, NA), name = "suite"), "`path`")
  expect_error(sbom(character(), name = "suite"), "`path`")
})

test_that("sbom() reads a DESCRIPTION, lockfile, manifest or Nix file", {
  skip_on_cran()
  pkg <- withr::local_tempdir()
  file.copy(list.files(test_path("fixtures/pkgs/srcpkg"), full.names = TRUE), pkg, recursive = TRUE)
  expect_equal(
    sbom(file.path(pkg, "DESCRIPTION"), system = FALSE, timestamp = ts),
    sbom_package(file.path(pkg, "DESCRIPTION"), system = FALSE, timestamp = ts)
  )
  lock <- file.path(sbom_example("analysis"), "renv.lock")
  expect_equal(
    sbom(lock, system = FALSE, timestamp = ts),
    sbom_renv(lock, system = FALSE, timestamp = ts)
  )
  manifest <- file.path(sbom_example("connect-app"), "manifest.json")
  expect_equal(
    sbom(manifest, system = FALSE, timestamp = ts),
    sbom_rsconnect(manifest, system = FALSE, timestamp = ts)
  )
  nix <- file.path(sbom_example("nix-project"), "default.nix")
  expect_equal(
    sbom(nix, nix = FALSE, system = FALSE, timestamp = ts),
    sbom_nix(nix, nix = FALSE, system = FALSE, timestamp = ts)
  )
})

test_that("sbom() names the files it cannot read, and arguments a file's reader lacks", {
  other <- withr::local_tempfile(fileext = ".json")
  writeLines('{"bomFormat": "CycloneDX"}', other)
  text <- withr::local_tempfile(fileext = ".txt")
  writeLines("hello", text)
  lock <- file.path(sbom_example("analysis"), "renv.lock")
  expect_error(sbom(other), "not a Posit Connect manifest")
  expect_error(sbom(other), "read_sbom")
  expect_error(sbom(text), "cannot build an SBOM from")
  expect_error(sbom(lock, lib = .libPaths()), "sbom_renv\\(\\)` has no argument `lib`")
  expect_error(sbom(file.path(tempdir(), "nope.lock")), "does not exist")
})

test_that("R at a minimum version is not merged with R at that exact version", {
  p <- two_projects()
  b <- p$analysis
  b$components$version_is[b$components$ref == "R"] <- "minimum"
  x <- combine_sbom(p$study, b, name = "suite", timestamp = ts)
  comps <- sbom_components(x)
  r <- comps[comps$name == "R", ]
  expect_equal(nrow(r), 2L)
  expect_setequal(r$version_is, c("exact", "minimum"))
  expect_true(paste0("R@", r$version[[1]]) %in% r$ref)
})
