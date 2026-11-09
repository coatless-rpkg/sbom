# Comparing two SBOMs, and turning the differences into issue sentences.

#' Compare two SBOMs
#'
#' Lists the components that were added or removed between two SBOMs, and the
#' components whose version, license or source changed.
#'
#' The two root components are paired with each other. Components of type
#' `"file"`, embedded components and system components (ecosystems
#' `"system"`, `"deb"` and `"rpm"`) are matched by `ref`, all other
#' components by name. A `"license"` change compares the SPDX
#' expression, then the license as written. A `"source"` change compares the
#' package URLs without their versions, or the ecosystems when either
#' component has no package URL. R itself is compared like any other
#' component, so a change of R version shows up. Base packages have no
#' versions and appear only as added or removed.
#'
#' Only what both SBOMs state is compared. A license that one of them does not
#' state at all, the license as written when only one states it, and an
#' ecosystem of `"unknown"` are not changes. Each format keeps a different
#' part of what sbom knows (an SPDX document has no field for the license as
#' written, and no format records sbom's own ecosystems, such as `"local"`),
#' so an SBOM compared with itself written in another format and read back
#' shows none. An SPDX expression on one side and only the license as written
#' on the other are the same license when [license_spdx()] translates the
#' one to the other.
#'
#' @param old,new `<sbom>` objects, as returned by [sbom_package()] or
#'   [sbom_installed()].
#' @return `sbom_diff()` returns an `<sbom_diff>` object: a list whose
#'   `changes` element is a data frame with one row per change and the columns
#'   `name`, `ecosystem`, `change` (`"added"`, `"removed"`, `"version"`,
#'   `"license"` or `"source"`), `old` and `new`, sorted by name and change.
#'   `as.data.frame()` returns that data frame, and `print()` returns its
#'   argument invisibly.
#' @examples
#' desc <- system.file("DESCRIPTION", package = "sbom")
#' old <- sbom_package(desc, system = FALSE)
#' new <- sbom_package(desc, system = FALSE)
#' sbom_diff(old, new)
#' @export
sbom_diff <- function(old, new) {
  check_sbom(old, "old")
  check_sbom(new, "new")
  oc <- old$components
  nc <- new$components
  ok <- component_keys(oc)
  nk <- component_keys(nc)
  rows <- list()
  for (k in setdiff(ok, nk)) {
    rows[[length(rows) + 1L]] <- diff_row(oc[match(k, ok), ], "removed", old = oc$version[match(k, ok)])
  }
  for (k in setdiff(nk, ok)) {
    rows[[length(rows) + 1L]] <- diff_row(nc[match(k, nk), ], "added", new = nc$version[match(k, nk)])
  }
  for (k in intersect(ok, nk)) {
    o <- oc[match(k, ok), ]
    n <- nc[match(k, nk), ]
    if (!identical(o$version, n$version)) {
      rows[[length(rows) + 1L]] <- diff_row(n, "version", o$version, n$version)
    }
    lic <- license_change(o, n)
    if (!is.null(lic)) {
      rows[[length(rows) + 1L]] <- diff_row(n, "license", lic[1], lic[2])
    }
    src <- source_change(o, n)
    if (!is.null(src)) {
      rows[[length(rows) + 1L]] <- diff_row(n, "source", src[1], src[2])
    }
  }
  changes <- if (length(rows) == 0L) {
    data.frame(
      name = character(), ecosystem = character(), change = character(),
      old = character(), new = character()
    )
  } else {
    do.call(rbind, rows)
  }
  changes <- changes[order(changes$name, changes$change, method = "radix"), , drop = FALSE]
  rownames(changes) <- NULL
  structure(list(changes = changes), class = "sbom_diff")
}

# The two roots pair with each other (a package root's ref carries its
# version); file, embedded and system components match by ref, packages by
# name.
component_keys <- function(comps) {
  by_ref <- comps$type %in% "file" | is_embedded_ref(comps$ref) |
    comps$ecosystem %in% system_ecosystems
  key <- ifelse(by_ref, paste0("ref:", comps$ref), paste0("name:", comps$name))
  key[comps$is_root %in% TRUE] <- "root"
  key
}

# One row of a diff for the component `comp`, with its `change` and the `old`
# and `new` values.
diff_row <- function(comp, change, old = NA_character_, new = NA_character_) {
  data.frame(
    name = comp$name, ecosystem = comp$ecosystem, change = change,
    old = old, new = new, stringsAsFactors = FALSE
  )
}

# The old and new license when they differ in what both SBOMs state, else
# NULL. A side with neither an SPDX expression nor the license as written
# states no license, as a format without the field leaves it.
license_change <- function(o, n) {
  os <- o$license_spdx
  ns <- n$license_spdx
  ow <- o$license_as_written
  nw <- n$license_as_written
  if ((is.na(os) && is.na(ow)) || (is.na(ns) && is.na(nw))) {
    return(NULL)
  }
  if (!identical(os, ns)) {
    if (!is.na(os) && !is.na(ns)) {
      return(c(os, ns))
    }
    # One side has only the license as written: the same license when it
    # translates to the other side's expression.
    translated <- unname(license_spdx(if (is.na(os)) ow else nw))
    if (!identical(translated, if (is.na(os)) ns else os)) {
      return(c(os, ns))
    }
  }
  if (!is.na(ow) && !is.na(nw) && !identical(ow, nw)) {
    return(c(ow, nw))
  }
  NULL
}

# The old and new source when they differ, else NULL: the package URLs without
# their versions when both have one, else the ecosystems when neither is
# unknown.
source_change <- function(o, n) {
  op <- sub("@[^?#]*", "", o$purl)
  np <- sub("@[^?#]*", "", n$purl)
  if (!is.na(op) && !is.na(np)) {
    return(if (!identical(op, np)) c(op, np))
  }
  known <- function(eco) !is.na(eco) && eco != "unknown"
  if (known(o$ecosystem) && known(n$ecosystem) && !identical(o$ecosystem, n$ecosystem)) {
    return(c(o$ecosystem, n$ecosystem))
  }
  NULL
}

#' @param x An `<sbom_diff>` object.
#' @param ... Ignored.
#' @export
#' @rdname sbom_diff
print.sbom_diff <- function(x, ...) {
  ch <- x$changes
  if (nrow(ch) == 0L) {
    cat("No differences.\n")
    return(invisible(x))
  }
  n_add <- sum(ch$change == "added")
  n_rem <- sum(ch$change == "removed")
  n_chg <- nrow(ch) - n_add - n_rem
  cat(n_add, " added, ", n_rem, " removed, ", n_chg, " changed\n", sep = "")
  show <- function(v) if (is.na(v)) "NOASSERTION" else v
  # The values may come from a file of any origin.
  ch[c("name", "old", "new")] <- lapply(ch[c("name", "old", "new")], printable)
  for (i in seq_len(nrow(ch))) {
    row <- ch[i, ]
    line <- switch(row$change,
      added = paste0("+ ", row$name, if (!is.na(row$new)) paste0(" ", row$new)),
      removed = paste0("- ", row$name, if (!is.na(row$old)) paste0(" ", row$old)),
      paste0(
        "~ ", row$name, " (", row$change, "): ",
        show(row$old), " -> ", show(row$new)
      )
    )
    cat(line, "\n", sep = "")
  }
  invisible(x)
}

#' @export
#' @rdname sbom_diff
as.data.frame.sbom_diff <- function(x, ...) x$changes

# Appends one issue per difference between `primary` and `other`. R and base
# packages, embedded and system components and the root components are never
# drift. They are set aside before comparing, so that a root sharing a
# package's name hides nothing.
drift_issues <- function(issues, primary, other, primary_label, other_label) {
  compared <- function(comps) {
    skip <- comps$is_root %in% TRUE | comps$ecosystem %in% c("r", "base-r", system_ecosystems) |
      is_embedded_ref(comps$ref)
    comps[!skip, , drop = FALSE]
  }
  primary$components <- compared(primary$components)
  other$components <- compared(other$components)
  oc <- primary$components
  ch <- sbom_diff(primary, other)$changes
  ch <- ch[ch$change %in% c("version", "added", "removed"), , drop = FALSE]
  pnames <- oc$name
  for (i in seq_len(nrow(ch))) {
    name <- ch$name[i]
    old <- ch$old[i]
    new <- ch$new[i]
    ref <- oc$ref[match(name, pnames)]
    spaced <- function(v) if (is.na(v)) "" else paste0(" ", v)
    switch(ch$change[i],
      version = {
        issues <- add_issue(
          issues, ref, "version", "drift-version",
          paste0(
            name, " is ", if (is.na(old)) "of unknown version" else old, " in ", primary_label,
            " but ", if (is.na(new)) "of unknown version" else new, " in ", other_label, "."
          )
        )
      },
      removed = {
        issues <- add_issue(
          issues, ref, "component", "drift-missing",
          paste0(name, spaced(old), " is in ", primary_label, " but not in ", other_label, ".")
        )
      },
      added = {
        issues <- add_issue(
          issues, paste0("unknown/", name), "component", "drift-extra",
          paste0(name, spaced(new), " is in ", other_label, " but not in ", primary_label, ".")
        )
      }
    )
  }
  issues
}
