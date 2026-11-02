test_that("the is a package-level cache environment", {
  expect_true(is.environment(the))
  expect_identical(parent.env(the), emptyenv())
})
