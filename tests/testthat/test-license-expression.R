test_that("the bundled SPDX License List has licences, exceptions and deprecations", {
  lst <- spdx_license_list()
  expect_named(lst, c("id", "kind", "deprecated"))
  expect_true(all(c("MIT", "Apache-2.0", "GPL-2.0-only") %in% lst$id[lst$kind == "license"]))
  expect_true("Classpath-exception-2.0" %in% lst$id[lst$kind == "exception"])
  expect_true(lst$deprecated[lst$id == "GPL-2.0"])
  expect_false(lst$deprecated[lst$id == "MIT"])
  expect_identical(spdx_license_list_version(), "3.29.0")
})

test_that("every SPDX value in R's licence table is a valid, known, current expression", {
  spdx <- license_table()$spdx
  spdx <- spdx[!is.na(spdx)]
  expect_gt(length(spdx), 0L)
  res <- license_expression_check(spdx)
  expect_true(all(res$valid))
  expect_identical(lengths(res$unknown), rep(0L, length(spdx)))
  expect_identical(lengths(res$deprecated), rep(0L, length(spdx)))
})

test_that("valid expressions parse and report their parts", {
  res <- license_expression_check("MIT")
  expect_true(res$valid)
  expect_true(is.na(res$problem))
  expect_identical(res$licenses[[1]], "MIT")

  expect_true(license_expression_check("GPL-2.0-only OR GPL-3.0-only")$valid)

  res <- license_expression_check(
    "(MIT AND Apache-2.0) OR GPL-2.0-or-later WITH Classpath-exception-2.0"
  )
  expect_true(res$valid)
  expect_identical(res$licenses[[1]], c("MIT", "Apache-2.0", "GPL-2.0-or-later"))
  expect_identical(res$exceptions[[1]], "Classpath-exception-2.0")

  res <- license_expression_check("LicenseRef-Proprietary")
  expect_true(res$valid)
  expect_identical(res$refs[[1]], "LicenseRef-Proprietary")

  res <- license_expression_check("DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2")
  expect_true(res$valid)
  expect_identical(res$refs[[1]], "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2")

  res <- license_expression_check("EPL-1.0+")
  expect_true(res$valid)
  expect_identical(res$licenses[[1]], "EPL-1.0")
  expect_length(res$deprecated[[1]], 0L)

  res <- license_expression_check("GPL-2.0+")
  expect_true(res$valid)
  expect_gt(length(res$deprecated[[1]]), 0L)

  res <- license_expression_check("mit")
  expect_true(res$valid)
  expect_length(res$unknown[[1]], 0L)
})

test_that("unknown and deprecated ids are valid syntax and are reported", {
  res <- license_expression_check("FooBar-1.0")
  expect_true(res$valid)
  expect_identical(res$unknown[[1]], "FooBar-1.0")

  res <- license_expression_check("GPL-2.0")
  expect_true(res$valid)
  expect_identical(res$deprecated[[1]], "GPL-2.0")
  expect_length(res$unknown[[1]], 0L)

  res <- license_expression_check(c("MIT WITH MIT", "Classpath-exception-2.0"))
  expect_true(all(res$valid))
  expect_identical(res$unknown[[1]], "MIT")
  expect_identical(res$unknown[[2]], "Classpath-exception-2.0")
})

test_that("invalid expressions have a problem", {
  bad <- c("MIT AND", "(MIT", "MIT Apache-2.0", "MIT WITH", "", "MIT and Apache-2.0")
  res <- license_expression_check(bad)
  expect_identical(res$expression, bad)
  expect_false(any(res$valid))
  expect_false(anyNA(res$problem))
  expect_true(all(nzchar(res$problem)))
})

test_that("NONE and NOASSERTION are accepted only as a whole expression", {
  expect_true(license_expression_check("NOASSERTION")$valid)
  expect_true(license_expression_check("NONE")$valid)
  res <- license_expression_check("NOASSERTION", special = FALSE)
  expect_false(res$valid)
  expect_false(is.na(res$problem))
  expect_false(license_expression_check("MIT OR NOASSERTION")$valid)
})

test_that("license_expression_check() is vectorised", {
  res <- license_expression_check(rep("MIT", 3))
  expect_identical(nrow(res), 3L)
  res <- license_expression_check(c("MIT", "(MIT", "MIT"))
  expect_identical(res$valid, c(TRUE, FALSE, TRUE))
  expect_identical(nrow(license_expression_check(character(0))), 0L)
})

test_that("nesting is capped at 100 levels and never overflows the stack", {
  nest <- function(n) paste0(strrep("(", n), "MIT", strrep(")", n))
  expect_true(license_expression_check(nest(100))$valid)
  for (n in c(101, 1700, 50000)) {
    res <- license_expression_check(nest(n))
    expect_false(res$valid)
    expect_identical(res$problem, "it nests parentheses more than 100 deep")
  }
  res <- license_expression_check(strrep("(", 50000))
  expect_false(res$valid)
})

test_that("bad input is invalid, never an error", {
  res <- license_expression_check(c(NA, "MIT\xff", "MIT"))
  expect_identical(res$valid, c(FALSE, FALSE, TRUE))
  expect_identical(res$problem[1:2], c("it is missing", "it is not valid UTF-8 text"))
  expect_false(license_expression_check(NA_character_, special = FALSE)$valid)
  expect_identical(license_expression_check(NA_character_)$problem, "it is missing")
  expect_false(license_expression_check("MIT / Apache-2.0")$valid)
  expect_false(license_expression_check("MéT")$valid)
})

test_that("malformed references are invalid", {
  bad <- c("LicenseRef-x+", "LicenseRef-", "DocumentRef-x", "AdditionRef-x",
           "DocumentRef-x:LicenseRef-y+", "DocumentRef-x:LicenseRef-", "AdditionRef-x+",
           "MIT WITH LicenseRef-x", "MIT WITH AdditionRef-x+", "DocumentRef-a:AdditionRef-b")
  res <- license_expression_check(bad)
  expect_false(any(res$valid))
  expect_false(anyNA(res$problem))
})

test_that("a plus follows only a licence id", {
  res <- license_expression_check(c("EPL-1.0+", "FooBar-1.0+"))
  expect_true(all(res$valid))
  expect_identical(res$unknown[[2]], "FooBar-1.0")
  expect_false(license_expression_check("MIT WITH Classpath-exception-2.0+")$valid)
})

test_that("AdditionRef after WITH is valid and recorded in refs", {
  res <- license_expression_check(c("MIT WITH AdditionRef-x", "MIT WITH DocumentRef-d:AdditionRef-y"))
  expect_true(all(res$valid))
  expect_identical(res$refs[[1]], "AdditionRef-x")
  expect_identical(res$refs[[2]], "DocumentRef-d:AdditionRef-y")
  expect_length(res$exceptions[[1]], 0L)
})

test_that("operators are upper case and whitespace separates tokens", {
  expect_false(license_expression_check("MIT AND Apache-2.0 or GPL-2.0-only")$valid)
  expect_false(license_expression_check("MIT AND Apache-2.0 with Classpath-exception-2.0")$valid)
  res <- license_expression_check("MIT\n\tAND \n Apache-2.0\t")
  expect_true(res$valid)
  expect_identical(res$licenses[[1]], c("MIT", "Apache-2.0"))
  expect_true(license_expression_check("(MIT)AND(Apache-2.0)")$valid)
})

test_that("WITH applies to one licence wherever it sits in a compound", {
  a <- license_expression_check("MIT WITH Classpath-exception-2.0 AND Apache-2.0")
  b <- license_expression_check("MIT AND Apache-2.0 WITH Classpath-exception-2.0")
  expect_true(a$valid && b$valid)
  expect_identical(a$exceptions[[1]], "Classpath-exception-2.0")
  expect_identical(b$exceptions[[1]], "Classpath-exception-2.0")
  expect_false(license_expression_check("(MIT AND Apache-2.0) WITH Classpath-exception-2.0")$valid)
  expect_false(license_expression_check("MIT WITH Classpath-exception-2.0 WITH Classpath-exception-2.0")$valid)
})

test_that("known ids are returned in their canonical spelling", {
  res <- license_expression_check("mit AND apache-2.0 WITH classpath-exception-2.0 OR FooBar-1.0")
  expect_identical(res$licenses[[1]], c("MIT", "Apache-2.0"))
  expect_identical(res$exceptions[[1]], "Classpath-exception-2.0")
  expect_identical(res$unknown[[1]], "FooBar-1.0")
})

test_that("long and many expressions are fast", {
  skip_on_cran()
  long <- paste(rep("MIT", 50000), collapse = " AND ")
  expect_lt(system.time(res <- license_expression_check(long))[["elapsed"]], 2)
  expect_true(res$valid)
  many <- paste0("Foo-", seq_len(20000))
  expect_lt(system.time(res <- license_expression_check(many))[["elapsed"]], 2)
  expect_true(all(res$valid))
})
