local_latin1_pkg <- function(env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  lines <- c(
    "Package: latin1pkg",
    "Version: 1.0",
    "Encoding: latin1",
    "Maintainer: Gábor Csárdi <g@example.org>"
  )
  con <- file(file.path(dir, "DESCRIPTION"), "wb")
  on.exit(close(con))
  writeLines(iconv(lines, from = "UTF-8", to = "latin1"), con, useBytes = TRUE)
  dir
}
