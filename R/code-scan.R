# The code scan, the source of last resort: the packages that R code uses,
# found with renv::dependencies(), at the versions installed.

# The name the folder of the code goes by as the stand-in root of a scan.
code_stand_in <- ".sbom-project-root"

# What the code in `dir` uses, as the code scan and its cross-check read it:
# `scan`, renv's scan (project_root_edges()); `edges`, the root's edges, one
# to each package found other than the package `dir` holds, which its tests
# name; and `desc`, a stand-in root DESCRIPTION whose Imports are those
# packages.
code_root <- function(dir) {
  scan <- project_root_edges(dir, NULL, NULL)
  # A package's tests name the package itself, which is not a dependency.
  own <- tryCatch(desc_field(read_description(dir), "Package"), error = function(e) NA_character_)
  edges <- scan$edges[!scan$edges$to %in% own, , drop = FALSE]
  edges$from <- rep(code_stand_in, nrow(edges))
  desc <- c(Package = code_stand_in)
  if (nrow(edges) > 0L) {
    desc[["Imports"]] <- paste(edges$to, collapse = ", ")
  }
  list(scan = scan, edges = edges, desc = desc)
}

# The packages the R code in `dir` uses, found by renv::dependencies() and
# looked up in `lib` at the versions installed there, all as inferred, with
# their dependencies. The root is the folder.
code_scan <- function(dir, lookup = library_lookup(lib), lib = .libPaths(),
                      author = getOption("sbom.author"),
                      organization = getOption("sbom.organization"),
                      regid = getOption("sbom.regid"),
                      timestamp = NULL, overrides = NULL,
                      embedded = TRUE, system = TRUE) {
  check_lib(lib)
  regid <- check_regid(regid)
  code <- code_root(dir)
  scan <- code$scan
  root_edges <- code$edges
  root_desc <- code$desc
  follow <- c("Depends", "Imports", "LinkingTo")
  res <- resolve_dependencies(root_desc, lookup, follow)
  # The root's edges are the scan's own.
  inner <- res$edges[res$edges$from != code_stand_in, , drop = FALSE]
  inner$evidence <- rep("declared", nrow(inner))
  res$edges <- rbind(root_edges, inner)

  root <- project_root_component(dir)
  inputs <- library_inputs("code", dir, lib)
  x <- build_sbom(
    root = root, lookup = lookup, root_desc = root_desc, fields = follow,
    root_suggests = FALSE, lib = lib, r_version = NULL, author = author,
    organization = organization, regid = regid, timestamp = timestamp,
    inputs = inputs, resolved = res, package_evidence = "inferred",
    embedded = embedded, system = system
  )
  x$issues <- scan_issue(x$issues, root, scan)
  x$metadata$notes <- c(
    paste0(
      "The packages come from a scan of the R code, the weakest evidence; ",
      "versions are those installed."
    ),
    x$metadata$notes
  )
  apply_overrides(x, overrides)
}

# For a package folder, a function of file paths that is TRUE for those that
# hold data or are left out of the package, whose code is not the package's:
# test fixtures and snapshots, inst/extdata, and whatever .Rbuildignore
# matches. As in R CMD build, each line of .Rbuildignore is a Perl regex,
# matched without case against the path relative to the folder of the file
# and of each folder above it. NULL for a folder without a DESCRIPTION.
unshipped_files <- function(dir) {
  if (!file.exists(file.path(dir, "DESCRIPTION"))) {
    return(NULL)
  }
  ignore_file <- file.path(dir, ".Rbuildignore")
  patterns <- if (file.exists(ignore_file)) {
    enc2utf8_bytes(readLines(ignore_file, warn = FALSE))
  } else {
    character()
  }
  patterns <- patterns[nzchar(trimws(patterns)) & !startsWith(trimws(patterns), "#")]
  root <- normalizePath(dir, winslash = "/", mustWork = TRUE)
  function(paths) {
    full <- normalizePath(paths, winslash = "/", mustWork = FALSE)
    inside <- startsWith(full, paste0(root, "/"))
    rel <- enc2utf8_bytes(ifelse(inside, substring(full, nchar(root) + 2L), ""))
    vapply(rel, function(r) {
      if (!nzchar(r)) {
        return(FALSE)
      }
      if (grepl("^(tests/testthat/(fixtures|_snaps)|inst/extdata)/", r)) {
        return(TRUE)
      }
      parts <- strsplit(r, "/", fixed = TRUE)[[1L]]
      candidates <- vapply(
        seq_along(parts), function(i) paste(parts[seq_len(i)], collapse = "/"), ""
      )
      any(vapply(patterns, function(p) {
        isTRUE(tryCatch(
          any(grepl(p, candidates, perl = TRUE, ignore.case = TRUE)),
          error = function(e) FALSE, warning = function(w) FALSE
        ))
      }, NA))
    }, NA, USE.NAMES = FALSE)
  }
}
