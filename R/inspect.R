# Looking inside an SBOM: a summary and the dependency tree.

#' Summarise an SBOM
#'
#' Counts the components of an SBOM by ecosystem, type and evidence, tallies
#' their licences, and collects the drift issues.
#'
#' Every component is counted, including the root, R, base packages and
#' files. A component is unknown when its version is `NA` or its SPDX
#' licence is `NA` (reported as `"NOASSERTION"`). Base packages have no
#' version, so they are always unknown.
#'
#' @param object An `<sbom>` object, as returned by [sbom_package()] or
#'   [sbom_installed()].
#' @param x An `<sbom_summary>` object.
#' @param ... Ignored.
#' @return `summary()` returns an `<sbom_summary>`, a list with `counts` (a
#'   data frame with columns `what`, `value` and `n`, for `"ecosystem"`,
#'   `"type"` and `"evidence"`), `licenses` (columns `license` and `n`, most
#'   common first), `unknowns` (the number of unknown components) and
#'   `drift` (the issues whose code starts with `"drift-"`). `print()`
#'   returns `x` invisibly.
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
#' summary(x)
#' @export
summary.sbom <- function(object, ...) {
  comps <- object$components
  counts <- do.call(rbind, lapply(c("ecosystem", "type", "evidence"), function(what) {
    tab <- table(comps[[what]], useNA = "no")
    if (length(tab) == 0L) {
      return(NULL)
    }
    data.frame(
      what = what, value = names(tab), n = as.integer(tab),
      stringsAsFactors = FALSE
    )
  }))
  if (is.null(counts)) {
    counts <- data.frame(what = character(), value = character(), n = integer())
  }
  counts <- counts[order(match(counts$what, c("ecosystem", "type", "evidence")),
    -counts$n, counts$value,
    method = "radix"
  ), , drop = FALSE]
  rownames(counts) <- NULL

  lic <- ifelse(is.na(comps$license_spdx), "NOASSERTION", comps$license_spdx)
  ltab <- table(lic)
  licenses <- data.frame(
    license = names(ltab), n = as.integer(ltab), stringsAsFactors = FALSE
  )
  licenses <- licenses[order(-licenses$n, licenses$license, method = "radix"), , drop = FALSE]
  rownames(licenses) <- NULL

  unknowns <- sum(is.na(comps$version) | is.na(comps$license_spdx))
  drift <- object$issues[startsWith(object$issues$code, "drift-"), , drop = FALSE]
  rownames(drift) <- NULL

  structure(
    list(
      root = node_label(comps[comps$is_root %in% TRUE, , drop = FALSE][1, ]),
      counts = counts, licenses = licenses,
      unknowns = as.integer(unknowns), drift = drift
    ),
    class = "sbom_summary"
  )
}

#' @export
#' @rdname summary.sbom
print.sbom_summary <- function(x, ...) {
  lines <- cli::cli_fmt({
    cli::cli_text("{.strong {x$root}}")
    cli::cli_h2("Components")
    for (what in unique(x$counts$what)) {
      rows <- x$counts[x$counts$what == what, , drop = FALSE]
      cli::cli_text("{what}: {paste0(rows$value, ' (', rows$n, ')', collapse = ', ')}")
    }
    cli::cli_text("Unknown version or licence: {x$unknowns}")
    cli::cli_h2("Licences")
    cli::cli_text("{paste0(x$licenses$license, ' (', x$licenses$n, ')', collapse = ', ')}")
    cli::cli_h2("Drift")
    if (nrow(x$drift) == 0L) {
      cli::cli_text("No drift.")
    } else {
      for (msg in x$drift$message) {
        cli::cli_bullets(c("!" = "{msg}"))
      }
    }
  })
  cat(lines, sep = "\n")
  invisible(x)
}

node_label <- function(comp) {
  if (is.na(comp$version)) comp$name else paste(comp$name, comp$version)
}

#' Print the dependency tree of an SBOM
#'
#' Prints the dependencies of the root component as a tree. A component
#' reached by several paths is expanded the first time it appears and marked
#' `(see above)` afterwards. Components reached only through `Suggests` are
#' marked `(suggested)`. Files that the root contains are leaves labelled
#' with their path.
#'
#' @param x An `<sbom>` object, as returned by [sbom_package()] or
#'   [sbom_installed()].
#' @param max_depth The number of levels below the root to show. Components
#'   at the limit are shown but not expanded.
#' @return `x`, invisibly.
#' @examples
#' x <- sbom_package(system.file("DESCRIPTION", package = "sbom"))
#' sbom_tree(x)
#' sbom_tree(x, max_depth = 1)
#' @export
sbom_tree <- function(x, max_depth = Inf) {
  check_sbom(x)
  if (!is.numeric(max_depth) || length(max_depth) != 1L || is.na(max_depth) || max_depth < 0) {
    cli::cli_abort("{.arg max_depth} must be a single non-negative number.")
  }
  comps <- x$components
  rel <- x$relationships
  root <- comps$ref[comps$is_root %in% TRUE][1]
  labels <- vapply(seq_len(nrow(comps)), function(i) node_label(comps[i, ]), character(1))
  names(labels) <- comps$ref

  ids <- character()
  lab <- character()
  kids <- list()
  seen <- character()

  add <- function(ref, text, depth, suggested = FALSE) {
    id <- paste0("n", length(ids) + 1L)
    ids[[id]] <<- id
    shown <- ref %in% seen
    suffix <- if (shown) " (see above)" else if (suggested) " (suggested)" else ""
    lab[[id]] <<- paste0(text, suffix)
    kids[[id]] <<- character()
    if (!shown) {
      seen <<- c(seen, ref)
      if (depth < max_depth) {
        out <- rel[rel$from == ref & rel$to %in% comps$ref, , drop = FALSE]
        targets <- unique(out$to)
        targets <- targets[order(labels[targets], targets, method = "radix")]
        for (to in targets) {
          only_suggests <- all(out$field[out$to == to] == "Suggests")
          kids[[id]] <<- c(kids[[id]], add(to, labels[[to]], depth + 1, only_suggests))
        }
      }
    }
    id
  }
  add(root, labels[[root]], 0)

  tree <- data.frame(id = unname(ids), stringsAsFactors = FALSE)
  tree$children <- unname(kids)
  tree$label <- unname(lab)
  print(cli::tree(tree, root = "n1"))
  invisible(x)
}
