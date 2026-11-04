local_plain_cli <- function(env = parent.frame()) {
  withr::local_options(
    cli.width = 80, cli.num_colors = 1, cli.unicode = FALSE,
    .local_envir = env
  )
}

test_that("summary() counts components, licences, unknowns and drift", {
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
  expect_true(any(grepl("Licences", out)))
})
