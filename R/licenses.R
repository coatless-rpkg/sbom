#' Translate a License field into an SPDX expression
#'
#' Looks up `License` strings from `DESCRIPTION` files in a table precomputed
#' from R's own license analysis (`tools::analyze_license()` and R's license
#' database). An expression is returned only when every alternative maps to
#' SPDX, no alternative is `file LICENSE` alone, and every `+ file LICENSE`
#' is attached to a license that R's license database marks extensible: MIT,
#' BSD, GPL-3, LGPL-3, AGPL-3 and the CC BY 4.0 family. So
#' `GPL-3 + file LICENSE` becomes `GPL-3.0-only`, while
#' `GPL-2 + file LICENSE` has no expression. R expands version ranges, so
#' `GPL (>= 2)` becomes `GPL-2.0-only OR GPL-3.0-only`.
#'
#' @param x A character vector of `License` field values.
#' @return A character vector the same length as `x`, with `NA` where there is
#'   no SPDX expression.
#' @export
#' @examples
#' license_spdx(c("MIT + file LICENSE", "GPL (>= 2)", "file LICENSE"))
license_spdx <- function(x) {
  license_lookup(x)$spdx
}

license_normalize <- function(x) {
  gsub("\\s+", " ", trimws(as.character(x)))
}

license_table <- function() {
  if (is.null(the$license_table)) {
    path <- system.file("extdata", "licenses.csv", package = "sbom")
    the$license_table <- utils::read.csv(path, colClasses = "character", na.strings = "")
  }
  the$license_table
}

license_lookup <- function(x) {
  spec <- license_normalize(x)
  tbl <- license_table()
  i <- match(spec, tbl$spec)
  data.frame(
    spec = spec,
    spdx = tbl$spdx[i],
    known = !is.na(i),
    stringsAsFactors = FALSE
  )
}

license_comment <- function(x) {
  r <- license_lookup(x)
  out <- rep(NA_character_, nrow(r))
  have <- !is.na(r$spec)
  mapped <- have & !is.na(r$spdx)
  out[mapped] <- paste0("Declared in DESCRIPTION as ", r$spec[mapped], ".")
  unmapped <- have & r$known & is.na(r$spdx)
  out[unmapped] <- paste0("Declared in DESCRIPTION as ", r$spec[unmapped],
    ", which has no SPDX expression in R's license database.")
  unknown <- have & !r$known
  out[unknown] <- paste0("Declared in DESCRIPTION as ", r$spec[unknown],
    ", which sbom's license table does not cover.")
  out
}
