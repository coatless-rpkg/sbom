test_that("printable() shows every C0, DEL and C1 control character as a space", {
  x <- c("a\u001b]52;c;eA==\u0007b", "\u009b31mred", "tab\there\nline", "caf\u00e9", NA)
  expect_identical(printable(x), c("a ]52;c;eA== b", " 31mred", "tab here line", "caf\u00e9", NA))
  expect_identical(printable("\u007f\u0080\u009f\u00a0"), "   \u00a0")
})

test_that("printable() keeps a character whose UTF-8 bytes fall in the C1 range, in every locale", {
  local_c_ctype()
  # U+0100 is the bytes C4 80, and an unmarked string holding them is UTF-8.
  x <- rawToChar(as.raw(c(0xc4, 0x80, 0x41)))
  expect_identical(charToRaw(printable(x)), as.raw(c(0xc4, 0x80, 0x41)))
  expect_identical(charToRaw(quote_value(x, 2L)), as.raw(c(0xc4, 0x80, 0x41)))
})

test_that("quote_value() cuts a value to its maximum length, the last character an ellipsis", {
  expect_identical(quote_value(strrep("x", 80)), strrep("x", 80))
  expect_identical(quote_value(strrep("x", 81)), paste0(strrep("x", 79), "\u2026"))
  expect_identical(quote_value(strrep("\u00e9", 12), 10L), paste0(strrep("\u00e9", 9), "\u2026"))
  expect_identical(nchar(quote_value(strrep("y", 1e6))), 80L)
  expect_identical(quote_value(c("a\u001bb", NA)), c("a b", NA))
})

test_that("text_strip() replaces control characters with spaces, keeping tab and newline only in lines", {
  x <- c(" a\u001b[2J ", "b\tc\nd", "\u0001\u0002", "plain  ", NA)
  expect_identical(text_strip(x), c("a [2J", "b c d", NA, "plain  ", NA))
  expect_identical(text_strip(x, lines = TRUE), c(" a [2J ", "b\tc\nd", "  ", "plain  ", NA))
  expect_identical(text_has_controls(x), c(TRUE, TRUE, TRUE, FALSE, FALSE))
  expect_identical(text_has_controls(x, lines = TRUE), c(TRUE, FALSE, TRUE, FALSE, FALSE))
})
