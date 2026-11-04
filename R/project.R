# sbom(), the front door: it finds a folder's sources, builds the SBOM from
# the strongest and cross-checks it against the rest. Also the code scan, the
# source of last resort, and the git commit of a project folder.

#' Build an SBOM for a project folder
#'
#' `sbom()` looks at what a folder holds, builds the SBOM from the strongest
#' source it finds, and reads every other source to check it. It runs no code
#' from the project and makes no network requests.
#'
#' The sources, from strongest to weakest:
#'
#' 1. `renv.lock`, read by [sbom_renv()].
#' 2. `manifest.json`, read by [sbom_rsconnect()], when it is a Posit Connect
#'    manifest: one with `version` and `packages`, whose packages and files
#'    are objects.
#' 3. `DESCRIPTION`, read by [sbom_package()], when it has a `Package` field.
#' 4. The R code itself, scanned with [renv::dependencies()]. Each package
#'    it uses is looked up in `lib` and listed at the version installed
#'    there, as inferred; one that is not installed is listed as unknown,
#'    with an issue. renv itself, which renv infers from a `renv.lock`, is
#'    left out, and so is the code in any subfolder that holds its own
#'    `renv.lock`, `DESCRIPTION` or `manifest.json`, a project of its own.
#'    In a package folder, so are test fixtures and snapshots,
#'    `inst/extdata` and the files `.Rbuildignore` excludes. The root is the
#'    folder, an application named after it, with its git commit as the
#'    version. This is the weakest evidence, and a note says so.
#'
#' A folder that is a Shiny app (see [sbom_shiny()]) is described by
#' [sbom_shiny()], which `sbom()` calls for it. That includes a folder with
#' `app.R`, or `ui.R` and `server.R`, even when it also has a `DESCRIPTION`
#' without golem structure.
#'
#' The strongest source present makes the SBOM. Every other source present,
#' and the code scan when the SBOM does not already come from it, are read
#' to cross-check it, and their disagreements become issues: a package that
#' one source lists and the other does not, or that they list at different
#' versions. A `DESCRIPTION` and the code declare no versions, so they report
#' only the packages they use that the SBOM does not list. A `DESCRIPTION`
#' without a `Package` field is not a package, so it is used only to
#' cross-check the packages its `Depends` and `Imports` name. A source that
#' cannot be read for a cross-check, or a `manifest.json` that is not a
#' Posit Connect manifest, is an issue, not an error. A `default.nix` is not
#' read yet, and an issue says so.
#'
#' A project folder's git commit is read from the files in the nearest
#' `.git` in it or a folder above it, without running git. A folder that is
#' not in a git repository, or whose commit cannot be read, has no version,
#' with an issue.
#'
#' When the folder holds `sbom-overrides.csv` and `overrides` is not given,
#' that file is applied as the overrides.
#'
#' The `inputs` element of the SBOM's metadata lists every source read.
#'
#' @param path A project folder.
#' @param ... Named arguments for the reader that `sbom()` picks: any
#'   argument of [sbom_renv()], [sbom_rsconnect()] or [sbom_package()] other
#'   than the file or folder it reads, such as `library`, `lib`,
#'   `dependencies`, `r_version`, `author` or `overrides`. The code scan
#'   takes `lib`, `author`, `organization`, `regid`, `timestamp`,
#'   `overrides`, `embedded` and `system`. A Shiny app also takes
#'   `evaluate_ui` (see [sbom_shiny()]), which other folders ignore. A name
#'   that no reader takes is an error. The reader ignores those it does not
#'   take, except that the cross-checks of `DESCRIPTION` and the code also
#'   use `lib`. Overrides, given or from `sbom-overrides.csv`, apply to the
#'   SBOM after the cross-checks, which compare what the sources say.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' x <- sbom(system.file("extdata", package = "sbom"), system = FALSE)
#' x
#' sbom_issues(x)
#' @export
sbom <- function(path = ".", ...) {
  args <- check_project_args(path, list(...))
  layout <- shiny_layout(path)
  if (!is.na(layout)) {
    return(do.call(sbom_shiny, c(list(path = path), args)))
  }
  sbom_project(path, args)
}

# The checks that every front door makes: `...` is named and known, the path
# is a folder, and `lib` is usable. Returns the arguments.
check_project_args <- function(path, dots, call = parent.frame()) {
  args <- check_sbom_dots(dots, call = call)
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    cli::cli_abort("{.arg path} must be a single string, not {.obj_type_friendly {path}}.", call = call)
  }
  if (!dir.exists(path)) {
    if (file.exists(path)) {
      cli::cli_abort("{.file {path}} is not a folder.", call = call)
    }
    cli::cli_abort("The folder {.file {path}} does not exist.", call = call)
  }
  if (!is.null(args$lib)) {
    check_lib(args$lib)
  }
  args
}

# The pipeline behind sbom() and sbom_shiny(): `args` are checked already.
# For a Shiny app, `layout` is its layout, and the app becomes the root.
sbom_project <- function(path, args, layout = NA, evaluate_ui = FALSE) {
  sources <- project_sources(path)
  primary <- sources[[1L]]
  x <- primary$build(args[intersect(names(args), setdiff(primary$args, "overrides"))])
  inputs <- source_inputs(x, primary)
  recorded <- drift_view(x, primary$records)

  cross_check_issue <- function(issues, code, message) {
    add_issue(issues, x$metadata$root, "dependencies", code, message, severity = "info")
  }
  for (src in sources[-1L]) {
    if (!is.null(src$skipped)) {
      x$issues <- cross_check_issue(x$issues, "cross-check-failed", src$skipped)
      next
    }
    # A cross-check compares packages only, so it looks neither inside them
    # nor at the operating system.
    quick <- list(embedded = FALSE, system = FALSE)
    other <- tryCatch(
      src$build(c(
        args[intersect(names(args), intersect(src$args, "lib"))],
        quick[intersect(names(quick), src$args)]
      )),
      error = function(e) e
    )
    if (inherits(other, "error")) {
      x$issues <- cross_check_issue(x$issues, "cross-check-failed", src$failed(other))
      next
    }
    if (!is.null(src$partial)) {
      x$issues <- cross_check_issue(x$issues, "cross-check-partial", src$partial)
    }
    found <- drift_issues(
      empty_issues(), recorded, drift_view(other, src$records, suggests = FALSE),
      primary$label, src$label
    )
    if (identical(src$records, "direct")) {
      found <- found[found$code == "drift-extra", , drop = FALSE]
    }
    x$issues <- rbind(x$issues, found)
    inputs <- rbind(inputs, source_inputs(other, src))
  }

  if (file.exists(file.path(path, "default.nix"))) {
    x$issues <- add_issue(
      x$issues, x$metadata$root, "dependencies", "nix-not-read",
      "default.nix is present but sbom does not read Nix files yet.",
      severity = "info"
    )
  }
  if (!is.na(layout)) {
    x <- apply_app_layout(
      x, path, layout, evaluate_ui = evaluate_ui,
      lib = if (is.null(args$lib)) .libPaths() else args$lib
    )
  }
  overrides <- args$overrides
  if (is.null(overrides) && file.exists(file.path(path, "sbom-overrides.csv"))) {
    overrides <- file.path(path, "sbom-overrides.csv")
  }
  if (is.character(overrides)) {
    inputs <- rbind(inputs, data.frame(kind = "overrides", path = overrides, stringsAsFactors = FALSE))
  }
  inputs <- inputs[!duplicated(inputs), , drop = FALSE]
  rownames(inputs) <- NULL
  x$metadata$inputs <- inputs
  rownames(x$issues) <- NULL
  apply_overrides(x, overrides)
}

# The arguments of sbom() that each reader takes: all of its own but the file
# or folder it reads, and for the code scan, `lib` and the shared ones.
reader_args <- function() {
  list(
    renv = setdiff(names(formals(sbom_renv)), "lockfile"),
    manifest = setdiff(names(formals(sbom_rsconnect)), "manifest"),
    package = setdiff(names(formals(sbom_package)), "path"),
    code = c("author", "organization", "regid", "timestamp", "overrides", "lib",
      "embedded", "system"),
    shiny = "evaluate_ui"
  )
}

check_sbom_dots <- function(args, call = parent.frame()) {
  nm <- names(args)
  if (length(args) > 0L && (is.null(nm) || any(is.na(nm) | !nzchar(nm)))) {
    cli::cli_abort("Every argument in {.arg ...} must be named.", call = call)
  }
  unknown <- setdiff(nm, unique(unlist(reader_args())))
  if (length(unknown) > 0L) {
    cli::cli_abort("{.fn sbom} has no argument{?s} {.arg {unknown}}.", call = call)
  }
  twice <- unique(nm[duplicated(nm)])
  if (length(twice) > 0L) {
    cli::cli_abort("{.arg {twice}} {?is/are} given more than once.", call = call)
  }
  args
}

# The sources in `path`, the one to build the SBOM from first and then the
# others to cross-check it, in order of strength. Each is a list:
# - `name`, its kind in metadata$inputs, and `label`, its name in drift issues;
# - `file`, its path (the folder, for the code);
# - `args`, the arguments of sbom() its reader takes, and `build`, a function
#   of those arguments that returns its <sbom>;
# - `records`, "all" when it lists every package with a version, or "direct"
#   when it names only the root's direct dependencies and no versions;
# - `failed`, a function of the error that gives the issue sentence when it
#   cannot be read for a cross-check;
# - `skipped`, the issue sentence when it is not read at all, and `partial`,
#   the one when only part of it is used, or NULL.
#
# A manifest.json that is not a Posit Connect manifest, and a DESCRIPTION
# without a Package field, are never the SBOM's source. Such a DESCRIPTION
# still cross-checks the packages its Depends and Imports name.
project_sources <- function(path) {
  takes <- reader_args()
  lock <- file.path(path, "renv.lock")
  manifest <- file.path(path, "manifest.json")
  desc <- file.path(path, "DESCRIPTION")
  failed <- function(name) {
    function(e) {
      reason <- condition_reason(e, path)
      paste0(
        name, " could not be read", if (nzchar(reason)) paste0(" (", reason, ")"),
        ", so it was not cross-checked."
      )
    }
  }
  is_file <- function(f) file.exists(f) && !dir.exists(f)
  manifest_kind <- if (is_file(manifest)) manifest_status(manifest) else "absent"
  desc_kind <- if (is_file(desc)) description_status(desc) else "absent"

  all <- list(
    list(
      name = "renv.lock", label = "renv.lock", file = lock, records = "all",
      args = takes$renv, failed = failed("renv.lock"),
      build = function(args) do.call(sbom_renv, c(list(lockfile = lock), args))
    ),
    list(
      name = "manifest.json", label = "manifest.json", file = manifest, records = "all",
      args = takes$manifest, failed = failed("manifest.json"),
      skipped = if (manifest_kind == "other") {
        "manifest.json is not a Posit Connect manifest, so it was not read."
      },
      build = function(args) do.call(sbom_rsconnect, c(list(manifest = manifest), args))
    ),
    if (desc_kind == "no-package") {
      list(
        name = "DESCRIPTION", label = "DESCRIPTION", file = desc, records = "direct",
        args = character(), failed = failed("DESCRIPTION"),
        partial = "DESCRIPTION has no Package field, so it was used only for the dependencies it declares.",
        build = function(args) description_deps(desc)
      )
    } else {
      list(
        name = "DESCRIPTION", label = "DESCRIPTION", file = desc, records = "direct",
        args = takes$package, failed = failed("DESCRIPTION"),
        build = function(args) do.call(sbom_package, c(list(path = path), args))
      )
    },
    list(
      name = "code", label = "the code", file = path, records = "direct",
      args = takes$code, failed = function(e) {
        reason <- condition_reason(e, path)
        paste0(
          "The R code could not be scanned", if (nzchar(reason)) paste0(" (", reason, ")"),
          ", so it was not cross-checked."
        )
      },
      build = function(args) do.call(code_scan, c(list(dir = path), args))
    )
  )
  present <- c(is_file(lock), manifest_kind != "absent", desc_kind != "absent", TRUE)
  usable <- present & c(TRUE, manifest_kind == "connect", desc_kind == "package", TRUE)
  primary <- which(usable)[[1L]]
  present[[primary]] <- FALSE
  c(all[primary], all[present])
}

# "connect" for a Posit Connect manifest, "other" for JSON that is not one,
# and "unreadable" for a file that is not JSON at all.
manifest_status <- function(file) {
  m <- tryCatch(jsonlite::read_json(file), error = function(e) e)
  if (inherits(m, "error")) {
    return("unreadable")
  }
  if (connect_shaped(m)) "connect" else "other"
}

# Whether `file` parses as a Posit Connect manifest.
is_connect_manifest <- function(file) {
  identical(manifest_status(file), "connect")
}

# Whether parsed JSON is shaped as a Posit Connect manifest: an object with
# `version` and `packages`, whose packages and files are objects.
connect_shaped <- function(m) {
  is.list(m) && !is.null(names(m)) && !is.null(m[["version"]]) &&
    is.list(m[["packages"]]) && is.null(manifest_problem(m))
}

# "package" for a DESCRIPTION with a Package field, "no-package" for one
# without, and "unreadable" for one that cannot be parsed.
description_status <- function(file) {
  d <- tryCatch(read_description(file), error = function(e) NULL)
  if (is.null(d)) {
    "unreadable"
  } else if (is.na(desc_field(d, "Package"))) {
    "no-package"
  } else {
    "package"
  }
}

# A throwaway <sbom> of the packages that a DESCRIPTION without a Package
# field names in Depends and Imports, as the root's direct dependencies, for
# a cross-check.
description_deps <- function(file) {
  d <- read_description(file)
  deps <- rbind(
    parse_dep_field(if ("Depends" %in% names(d)) d[["Depends"]] else NA_character_, "Depends"),
    parse_dep_field(if ("Imports" %in% names(d)) d[["Imports"]] else NA_character_, "Imports")
  )
  deps <- deps[!deps$name %in% c("R", base_packages()) & !duplicated(deps$name), , drop = FALSE]
  refs <- paste0("unknown/", deps$name)
  rows <- lapply(seq_len(nrow(deps)), function(i) {
    component_row(ref = refs[[i]], name = deps$name[[i]], type = "library", ecosystem = "unknown")
  })
  root <- component_row(ref = "description", name = ".description", type = "application", is_root = TRUE)
  new_sbom(
    list(
      root = "description", timestamp = NA, author = NA_character_,
      organization = NA_character_, tool_version = NA_character_, notes = character(),
      inputs = data.frame(kind = character(), path = character()), regid = NA_character_
    ),
    do.call(rbind, c(list(root), rows)),
    data.frame(
      from = rep("description", nrow(deps)), to = refs, field = deps$field,
      spec = deps$spec, evidence = rep("declared", nrow(deps)), stringsAsFactors = FALSE
    ),
    empty_issues()
  )
}

# The reason in an error for an issue sentence: the first line of the
# innermost cause's message, without colour, wrapping or a final full stop,
# and with the folder's path, quoted or not, as given or normalised, made
# relative to it, so that no machine path reaches the SBOM.
condition_reason <- function(e, path) {
  while (inherits(e$parent, "condition")) {
    e <- e$parent
  }
  old <- options(cli.width = 10000L, cli.num_colors = 1L)
  on.exit(options(old), add = TRUE)
  msg <- tryCatch(cli::ansi_strip(conditionMessage(e)), error = function(err) "")
  line <- enc2utf8_bytes(strsplit(paste0(msg, "\n"), "\n", fixed = TRUE)[[1L]][1L])
  dirs <- unique(sub("(?<=.)/+$", "", c(
    path, normalizePath(path, mustWork = FALSE),
    normalizePath(path, winslash = "/", mustWork = FALSE)
  ), perl = TRUE))
  # The longest first, so that one form never eats part of another.
  dirs <- dirs[order(-nchar(dirs))]
  for (dir in dirs) {
    line <- gsub(paste0(dir, "/"), "", line, fixed = TRUE)
    line <- gsub(dir, basename(dir), line, fixed = TRUE)
  }
  sub("[.]$", "", trimws(line))
}

# A source's rows for metadata$inputs: the source itself, then the libraries
# its reader read.
source_inputs <- function(x, src) {
  read <- x$metadata$inputs
  rbind(
    data.frame(kind = src$name, path = as.character(src$file), stringsAsFactors = FALSE),
    read[read$kind %in% "library", c("kind", "path"), drop = FALSE]
  )
}

# What a source records, to compare with another. A lockfile or manifest
# records the packages it lists, but not the unknown ones it only names, nor
# app files. A DESCRIPTION or the code names only the root's direct
# dependencies, and no versions. Suggests count only when `suggests` is TRUE:
# a lockfile or manifest leaves them out, so they are not drift from one.
drift_view <- function(x, records, suggests = TRUE) {
  comps <- x$components
  if (identical(records, "all")) {
    keep <- !comps$evidence %in% "unknown" & !comps$type %in% "file"
  } else {
    rel <- x$relationships
    skip <- c("contains", if (!suggests) "Suggests")
    direct <- rel$to[rel$from == x$metadata$root & !rel$field %in% skip]
    keep <- comps$is_root %in% TRUE | comps$ref %in% direct
    comps$version[!comps$is_root %in% TRUE] <- NA_character_
  }
  # Embedded and system components are not packages that a source lists.
  x$components <- comps[
    keep & !is_embedded_ref(comps$ref) & !comps$ecosystem %in% system_ecosystems, ,
    drop = FALSE
  ]
  x
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
  scan <- project_root_edges(dir, NULL, NULL)
  # A package's tests name the package itself, which is not a dependency.
  own <- tryCatch(desc_field(read_description(dir), "Package"), error = function(e) NA_character_)
  root_edges <- scan$edges[!scan$edges$to %in% own, , drop = FALSE]
  stand_in <- ".sbom-project-root"
  root_edges$from <- rep(stand_in, nrow(root_edges))

  # The packages found stand in for the root's Imports, which are then
  # replaced by the scan's own edges.
  follow <- c("Depends", "Imports", "LinkingTo")
  root_desc <- c(Package = stand_in)
  if (nrow(root_edges) > 0L) {
    root_desc[["Imports"]] <- paste(root_edges$to, collapse = ", ")
  }
  res <- resolve_dependencies(root_desc, lookup, follow)
  inner <- res$edges[res$edges$from != stand_in, , drop = FALSE]
  inner$evidence <- rep("declared", nrow(inner))
  res$edges <- rbind(root_edges, inner)

  root <- project_root_component(dir)
  inputs <- data.frame(
    kind = c("code", rep("library", length(lib))),
    path = c(as.character(dir), as.character(lib)),
    stringsAsFactors = FALSE
  )
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

# The commit checked out in the git repository that holds `dir`, read from
# the files in the nearest .git in `dir` or a folder above it, stopping
# before the home folder, or NA. Git itself is never run.
# - HEAD holds a commit (a detached HEAD) or names a branch ref, whose commit
#   is in a loose ref file or else in packed-refs. A ref that names another
#   ref is not followed.
# - .git may be a file naming the git directory, as in a worktree, where
#   `commondir` names the directory that holds the shared refs.
git_commit <- function(dir) {
  tryCatch(
    read_git_commit(dir),
    error = function(e) NA_character_,
    warning = function(w) NA_character_
  )
}

read_git_commit <- function(dir) {
  top <- git_root(dir)
  gitdir <- if (is.na(top)) NA_character_ else git_dir(top)
  head <- if (is.na(gitdir)) NA_character_ else first_line(file.path(gitdir, "HEAD"))
  sha <- if (!is.na(head) && startsWith(head, "ref:")) {
    git_ref(gitdir, trimws(sub("^ref:", "", head)))
  } else {
    head
  }
  if (is_sha(sha)) sha else NA_character_
}

# The nearest folder, `dir` or one above it, that holds a .git (a folder or,
# in a worktree, a file), or NA at the home folder or the filesystem root
# without one. The home folder's own .git is not looked at.
git_root <- function(dir) {
  d <- normalizePath(dir, winslash = "/", mustWork = FALSE)
  home <- normalizePath("~", winslash = "/", mustWork = FALSE)
  repeat {
    # A repository at the home folder is a dotfiles repository, not the
    # project's.
    if (identical(d, home)) {
      return(NA_character_)
    }
    if (file.exists(file.path(d, ".git"))) {
      return(d)
    }
    parent <- dirname(d)
    if (identical(parent, d)) {
      return(NA_character_)
    }
    d <- parent
  }
}

git_dir <- function(dir) {
  dotgit <- file.path(dir, ".git")
  if (dir.exists(dotgit)) {
    return(dotgit)
  }
  line <- first_line(dotgit)
  if (is.na(line) || !startsWith(line, "gitdir:")) {
    return(NA_character_)
  }
  target <- relative_to(dir, trimws(sub("^gitdir:", "", line)))
  if (dir.exists(target)) target else NA_character_
}

# The commit of `ref`, from the git directory or else the shared one: a loose
# ref file wins over packed-refs, as in git.
git_ref <- function(gitdir, ref) {
  parts <- strsplit(ref, "/", fixed = TRUE)[[1L]]
  if (!startsWith(ref, "refs/") || any(parts %in% c("", ".", ".."))) {
    return(NA_character_)
  }
  common <- first_line(file.path(gitdir, "commondir"))
  dirs <- unique(c(gitdir, if (!is.na(common)) relative_to(gitdir, common)))
  for (d in dirs) {
    loose <- file.path(d, ref)
    if (file.exists(loose) && !dir.exists(loose)) {
      return(first_line(loose))
    }
  }
  for (d in dirs) {
    packed <- file.path(d, "packed-refs")
    if (!file.exists(packed) || dir.exists(packed)) {
      next
    }
    lines <- trimws(readLines(packed, warn = FALSE))
    hit <- regmatches(lines, regexec("^([0-9a-f]{40}) (.+)$", lines))
    for (h in hit) {
      if (length(h) == 3L && identical(h[[3L]], ref)) {
        return(h[[2L]])
      }
    }
  }
  NA_character_
}

# The first line of a file, trimmed, or NA when there is none.
first_line <- function(file) {
  if (!file.exists(file) || dir.exists(file)) {
    return(NA_character_)
  }
  line <- readLines(file, n = 1L, warn = FALSE)
  if (length(line) == 0L) NA_character_ else trimws(line)
}

relative_to <- function(dir, path) {
  if (grepl("^(/|[A-Za-z]:[/\\\\]|\\\\\\\\)", path)) path else file.path(dir, path)
}

is_sha <- function(x) {
  length(x) == 1L && !is.na(x) && grepl("^[0-9a-f]{40}$", x)
}
