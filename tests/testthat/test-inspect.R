test_that("summary() counts components, licenses, unknowns and drift", {
  local_plain_cli()
  s <- summary(fixture_sbom())
  expect_s3_class(s, "sbom_summary")
  expect_equal(s$counts$n[s$counts$what == "ecosystem" & s$counts$value == "cran"], 3L)
  expect_true("NOASSERTION" %in% s$licenses$license)
  expect_gte(s$unknowns, 1L)
  expect_equal(nrow(s$drift), 0L)
  expect_snapshot(print(s))
})

test_that("summary() reports drift issues", {
  local_plain_cli()
  x <- minimal_sbom()
  x$issues <- add_issue(x$issues, "pkg:cran/b@2.0", "version", "drift-version", "b is 2.0 in the lockfile but 2.1 in the library.")
  s <- summary(x)
  expect_equal(nrow(s$drift), 1L)
  expect_snapshot(print(s))
  expect_invisible(print(s))
})

test_that("sbom_tree() prints the tree once per node and respects max_depth", {
  local_plain_cli()
  x <- fixture_sbom()
  expect_snapshot(sbom_tree(x))
  expect_snapshot(sbom_tree(x, max_depth = 1))
  expect_invisible(sbom_tree(x))
})

test_that("sbom_tree() shows a minimum version as a minimum", {
  local_plain_cli()
  x <- fixture_sbom()
  expect_equal(x$components$version_is[x$components$name == "R"], "minimum")
  expect_true("+-R (>= 4.1.0)" %in% utils::capture.output(sbom_tree(x, max_depth = 1)))
  x$components$version_is[x$components$name == "R"] <- "exact"
  expect_true("+-R 4.1.0" %in% utils::capture.output(sbom_tree(x, max_depth = 1)))
})

test_that("sbom_tree() terminates on cycles and rejects a bad max_depth", {
  local_plain_cli()
  x <- minimal_sbom()
  x$relationships <- rbind(x$relationships, data.frame(
    from = "pkg:cran/b@2.0", to = "pkg:cran/a@1.0", field = "Imports",
    spec = NA_character_, evidence = "declared"
  ))
  expect_snapshot(sbom_tree(x))
  expect_error(sbom_tree(x, max_depth = -1), "max_depth")
  expect_error(sbom_tree(1), "sbom")
})

test_that("print.sbom_summary() writes to standard output", {
  local_plain_cli()
  s <- summary(fixture_sbom())
  out <- suppressMessages(capture.output(print(s)))
  expect_gt(length(out), 5L)
  expect_true(any(grepl("Licenses", out)))
})

test_that("print(), summary(), sbom_tree() and sbom_diff() show control characters as spaces", {
  local_plain_cli()
  x <- minimal_sbom()
  x$components$name[1] <- "a\u001b]52;c;eA==\u0007"
  x$components$version[2] <- "2.0\u009b31m"
  x$components$license_spdx[2] <- "MIT\u001b[2J"
  x$issues <- add_issue(
    x$issues, "pkg:cran/b@2.0", "version", "drift-version", "b is 2.0\u001b[2J in renv.lock but 2.1 in the library."
  )
  out <- c(
    utils::capture.output(print(x)), utils::capture.output(print(summary(x))),
    utils::capture.output(sbom_tree(x)), utils::capture.output(print(sbom_diff(minimal_sbom(), x)))
  )
  expect_false(any(grepl("[\\x{1b}\\x{07}\\x{9b}]", out, perl = TRUE)))
  expect_true(any(grepl("<sbom> a ]52;c;eA==  1.0", out, fixed = TRUE)))
  expect_true(any(grepl("MIT [2J (1)", out, fixed = TRUE)))
  expect_true(any(grepl("b 2.0 31m", out, fixed = TRUE)))
  expect_true(any(grepl("b is 2.0 [2J in renv.lock", out, fixed = TRUE)))
})
