examples <- c(
  "PACKAGES", "analysis", "analysis-manifest.json", "connect-app", "dashboard.cdx.json",
  "library", "nix-project", "osv-all.zip", "report-after", "report-before", "shiny-app",
  "study", "study-overrides.csv"
)

# A copy of example `name`, removed when the test ends. A copy is outside this
# package's git repository, whose commit would otherwise become the version
# of a project example when the tests run from the source folder.
local_example <- function(name, env = parent.frame()) {
  path <- sbom_example(name, copy = TRUE)
  withr::defer(unlink(dirname(path), recursive = TRUE), envir = env)
  path
}

test_that("sbom_example() lists the examples, sorted, and gives the path of each", {
  expect_identical(sbom_example(), examples)
  root <- normalizePath(system.file("extdata", "examples", package = "sbom"))
  for (name in examples) {
    path <- sbom_example(name)
    expect_true(file.exists(path), label = name)
    expect_identical(basename(path), name)
    expect_identical(normalizePath(dirname(path)), root, label = name)
  }
})

test_that("sbom_example() refuses anything but the name of an example", {
  expect_error(sbom_example("nope"), "There is no example called \"nope\"", class = "rlang_error")
  expect_error(sbom_example("nope"), "study-overrides.csv", class = "rlang_error")
  expect_error(sbom_example("../DESCRIPTION"), "no example called", class = "rlang_error")
  expect_error(sbom_example("study/renv.lock"), "no example called", class = "rlang_error")
  expect_error(sbom_example(""), "no example called", class = "rlang_error")
  for (bad in list(1, NA_character_, c("study", "analysis"), character(), TRUE)) {
    expect_error(sbom_example(bad), "`name` must be a single string or `NULL`", class = "rlang_error")
  }
  for (bad in list(NA, "yes", c(TRUE, FALSE), NULL, 1)) {
    expect_error(sbom_example("study", copy = bad), "`copy` must be `TRUE` or `FALSE`", class = "rlang_error")
  }
})

test_that("a copy keeps its name and contents, and changing it leaves the example alone", {
  installed <- sbom_example("study")
  files <- list.files(installed, recursive = TRUE)
  sums <- tools::md5sum(file.path(installed, files))

  copy <- local_example("study")
  expect_identical(basename(copy), "study")
  expect_true(startsWith(normalizePath(copy), normalizePath(tempdir())))
  expect_identical(unname(tools::md5sum(file.path(copy, files))), unname(sums))
  expect_setequal(list.files(copy, recursive = TRUE), files)

  file.copy(sbom_example("study-overrides.csv"), file.path(copy, "sbom-overrides.csv"))
  expect_false(file.exists(file.path(installed, "sbom-overrides.csv")))
  expect_identical(tools::md5sum(file.path(installed, files)), sums)

  other <- local_example("study")
  expect_false(identical(other, copy))
  expect_false(file.exists(file.path(other, "sbom-overrides.csv")))

  file <- local_example("dashboard.cdx.json")
  expect_identical(basename(file), "dashboard.cdx.json")
  expect_identical(unname(tools::md5sum(file)), unname(tools::md5sum(sbom_example("dashboard.cdx.json"))))

  nested <- local_example("shiny-app")
  expect_true(file.exists(file.path(nested, "www", "jquery-3.7.1.min.js")))
})

# The guides rely on these.
test_that("the analysis lockfile misses a package the script uses, and its manifest drifts", {
  proj <- local_example("analysis")
  x <- sbom(proj, system = FALSE)
  comps <- sbom_components(x)
  expect_setequal(comps$name[comps$ecosystem == "cran"], c("cli", "jsonlite"))
  expect_true("xml2 is in the code but not in renv.lock." %in% sbom_issues(x)$message)

  file.copy(sbom_example("analysis-manifest.json"), file.path(proj, "manifest.json"))
  m <- sbom_rsconnect(file.path(proj, "manifest.json"), system = FALSE)
  expect_identical(sbom_components(m)$version[sbom_components(m)$name == "cli"], "3.6.6")
  y <- sbom(proj, system = FALSE)
  expect_true(any(sbom_issues(y)$code == "drift-version" & grepl("^cli ", sbom_issues(y)$message)))

  z <- sbom_renv(file.path(proj, "renv.lock"), library = sbom_example("library"), system = FALSE)
  expect_true(any(sbom_issues(z)$code == "drift-version" & grepl("^cli ", sbom_issues(z)$message)))
})

test_that("the study's overrides answer what sbom could not determine", {
  study <- local_example("study")
  x <- sbom(study, system = FALSE)
  expect_setequal(sbom_components(x)$name[!sbom_components(x)$is_root %in% TRUE &
    sbom_components(x)$ecosystem != "base-r"], c("R", "holeypkg", "inhouse"))
  expect_identical(validate_sbom(x, checks = "content")$status, "fail")

  file.copy(sbom_example("study-overrides.csv"), file.path(study, "sbom-overrides.csv"))
  y <- sbom(study, system = FALSE)
  expect_identical(validate_sbom(y, checks = "content")$status, "pass")

  adv <- sbom(study, system = FALSE, advisories = sbom_example("osv-all.zip"))
  a <- sbom_advisories(adv)
  expect_identical(a$id, "EXAMPLE-2026-1")
  expect_identical(a$name, "holeypkg")
  expect_identical(a$fixed, "1.0.1")
})

test_that("the Shiny app ships jQuery, and the Nix project's snapshot gives versions", {
  s <- sbom_shiny(local_example("shiny-app"), lib = character(), system = FALSE)
  comps <- sbom_components(s)
  expect_identical(comps$version[comps$name == "jquery"], "3.7.1")

  # The setup stops every test reading a snapshot; this one is a local file.
  local_mocked_bindings(read_packages_file = read_packages_file_real)
  nix <- file.path(local_example("nix-project"), "default.nix")
  n <- sbom_nix(nix, nix = FALSE, system = FALSE, snapshot = sbom_example("PACKAGES"))
  comps <- sbom_components(n)
  expect_identical(comps$version[match(c("cli", "jsonlite"), comps$name)], c("3.6.3", "1.8.9"))
})

test_that("the dashboard reads as another tool's SBOM, and the report's lockfiles differ", {
  d <- read_sbom(sbom_example("dashboard.cdx.json"))
  expect_setequal(sbom_components(d)$purl[!sbom_components(d)$is_root %in% TRUE],
                  c("pkg:pypi/requests@2.32.3", "pkg:pypi/urllib3@2.2.2"))

  before <- file.path(local_example("report-before"), "renv.lock")
  after <- file.path(local_example("report-after"), "renv.lock")
  ch <- sbom_diff(sbom_renv(before, system = FALSE), sbom_renv(after, system = FALSE))$changes
  expect_identical(
    paste(ch$name, ch$change),
    c("cli version", "glue added", "jsonlite removed", "notarealpkg license")
  )
})

test_that("the Connect app's manifest and lockfile disagree", {
  x <- sbom(local_example("connect-app"), system = FALSE)
  expect_true(all(c("renv.lock", "manifest.json") %in% x$metadata$inputs$kind))
  expect_true(any(startsWith(sbom_issues(x)$code, "drift-")))
})
