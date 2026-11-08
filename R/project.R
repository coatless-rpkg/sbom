# sbom(), the front door: it finds a folder's sources, builds the SBOM from
# the strongest and cross-checks it against the rest. Also the code scan, the
# source of last resort, and the git commit of a project folder.

#' Build an SBOM for a project folder
#'
#' `sbom()` looks at what a folder holds, builds the SBOM from the strongest
#' source it finds, and reads every other source to check it. It runs no code
#' from the project and makes no network requests, except that, with Nix
#' installed, a `default.nix` is read by running `nix-instantiate` (see
#' [sbom_nix()]), which may download nixpkgs, that `snapshot` looks up a
#' CRAN snapshot, and that `advisories = TRUE` downloads OSV's advisory data.
#'
#' The sources, from strongest to weakest:
#'
#' 1. `renv.lock`, read by [sbom_renv()].
#' 2. `manifest.json`, read by [sbom_rsconnect()], when it is a Posit Connect
#'    manifest: one with `version` and `packages`, whose packages and files
#'    are objects.
#' 3. `default.nix`, read by [sbom_nix()]. A file that rix wrote lists the
#'    packages it names, without versions, unless `snapshot` is given or Nix
#'    is installed and the environment is built: then it is read from the Nix
#'    store, with versions. With Nix installed but the environment not built,
#'    the file itself is read, with an issue. A hand-written file can be read
#'    only with Nix.
#' 4. `DESCRIPTION`, read by [sbom_package()], when it has a `Package` field.
#' 5. The R code itself, scanned with [renv::dependencies()]. Each package
#'    it uses is looked up in `lib` and listed at the version installed
#'    there, as inferred; one that is not installed is listed as unknown,
#'    with an issue. renv itself, which renv infers from a `renv.lock`, is
#'    left out, and so is the code in any subfolder that holds its own
#'    `renv.lock`, `DESCRIPTION` or `manifest.json`, a project of its own.
#'    In a package folder, so are test fixtures and snapshots,
#'    `inst/extdata` and the files `.Rbuildignore` excludes. The root is the
#'    folder, an application named after it, with its git commit as the
#'    version. This is the weakest evidence, and a note states that the
#'    packages come from a scan of the code, at their installed versions.
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
#' versions. A `DESCRIPTION`, the code, and a `default.nix` read without Nix
#' or a snapshot declare no versions, so they report only the packages they
#' use that the SBOM does not list. A `DESCRIPTION`
#' without a `Package` field is not a package, so it is used only to
#' cross-check the packages its `Depends` and `Imports` name. A source that
#' cannot be read for a cross-check, or a `manifest.json` that is not a
#' Posit Connect manifest, is an issue, not an error. So is a hand-written
#' `default.nix` that sbom cannot read, even when it is the strongest source:
#' one on a machine without Nix, or, under the default `nix = NA`, one that
#' Nix fails to evaluate or whose environment has not been built. The SBOM is
#' built from the next source, and a `cross-check-failed` issue of severity
#' `warning` gives the reason and names that source. Any other failure to
#' read the strongest source, such as `nix = TRUE` on a machine without Nix,
#' is an error. A cross-check reads `default.nix` with `nix` as given (by
#' default, Nix is used when it is installed, and `nix = FALSE` never calls
#' it) and without a snapshot. Under `nix = TRUE`, a `default.nix` that Nix
#' cannot read is an error even as a cross-check. When Nix runs for that
#' cross-check and cannot read the environment, its issue is carried into the
#' SBOM.
#'
#' A project folder's git commit is read from the files in the nearest
#' `.git` in it or a folder above it, without running git. A folder that is
#' not in a git repository, or whose commit cannot be read, has no version,
#' with an issue.
#'
#' When the folder holds `sbom-overrides.csv` and `overrides` is not given,
#' that file is applied as the overrides.
#'
#' Advisories, when asked for with `advisories`, are matched once, with the
#' SBOM, after the overrides (and, for a Shiny app, after the app's own
#' components are added). The cross-checks never read advisory data. See
#' [sbom_package()] for what is matched and what is sent.
#'
#' The `inputs` element of the SBOM's metadata lists every source read.
#'
#' @param path A project folder.
#' @param ... Named arguments for the reader that `sbom()` picks: any
#'   argument of [sbom_renv()], [sbom_rsconnect()], [sbom_nix()] (such as
#'   `nix` and `snapshot`) or [sbom_package()] other
#'   than the file or folder it reads, such as `library`, `lib`,
#'   `dependencies`, `r_version`, `author`, `overrides` or `advisories`. The
#'   code scan takes `lib`, `author`, `organization`, `regid`, `timestamp`,
#'   `overrides`, `embedded`, `system`, `advisories` and
#'   `advisories_on_error`. A Shiny app also takes
#'   `evaluate_ui` (see [sbom_shiny()]), which other folders ignore. A name
#'   that no reader takes is an error. The reader ignores those it does not
#'   take, except that the cross-checks of `DESCRIPTION` and the code also
#'   use `lib`. Overrides, given or from `sbom-overrides.csv`, apply to the
#'   SBOM after the cross-checks, which compare what the sources say, and
#'   advisories are matched after the overrides.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' x <- sbom(sbom_example("connect-app"), system = FALSE)
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
# is a folder, and `lib`, `nix`, `snapshot`, `advisories` and
# `advisories_on_error` are usable. Returns the arguments, with
# `advisories_on_error`, when given, as the error mode.
check_project_args <- function(path, dots, call = parent.frame()) {
  args <- check_sbom_dots(dots, call = call)
  given <- function(name, default) if (name %in% names(args)) args[[name]] else default
  on_error <- check_advisories_args(
    given("advisories", FALSE), given("advisories_on_error", "error"),
    call = call
  )
  if ("advisories_on_error" %in% names(args)) {
    args$advisories_on_error <- on_error
  }
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
  if ("nix" %in% names(args)) {
    check_nix_arg(args$nix, call = call)
  }
  check_snapshot_arg(args$snapshot, call = call)
  args
}

# The pipeline behind sbom() and sbom_shiny(): `args` are checked already.
# For a Shiny app, `layout` is its layout, and the app becomes the root.
# Errors name `call`.
sbom_project <- function(path, args, layout = NA, evaluate_ui = FALSE, call = parent.frame()) {
  sources <- project_sources(path)
  # Overrides and advisories apply once, to the SBOM, at the end, so the
  # reader of the strongest source does not take them; a cross-check takes
  # only `lib`, `nix`, `embedded` and `system`.
  at_end <- c("overrides", "advisories", "advisories_on_error")
  # A default.nix that cannot be read at all, as the strongest source, is an
  # issue, and the SBOM comes from the next source. Every other error is the
  # user's to see.
  unread <- NULL
  repeat {
    primary <- sources[[1L]]
    read <- tryCatch(
      read_source(primary, args[intersect(names(args), setdiff(primary$args, at_end))]),
      sbom_nix_unreadable = function(e) e
    )
    if (!inherits(read, "error")) {
      break
    }
    unread <- read
    sources <- project_sources(path, skip = "default.nix")
  }
  x <- read$sbom
  inputs <- source_inputs(x, primary)
  recorded <- drift_view(x, read$records)

  cross_check_issue <- function(issues, code, message, severity = "info") {
    add_issue(issues, x$metadata$root, "dependencies", code, message, severity = severity)
  }
  if (!is.null(unread)) {
    reason <- condition_reason(unread, path)
    # The SBOM comes from a weaker source than the folder holds.
    x$issues <- cross_check_issue(
      x$issues, "cross-check-failed",
      paste0(
        "sbom could not read default.nix", if (nzchar(reason)) paste0(" (", reason, ")"),
        ", so the SBOM was built from ", primary$label, "."
      ),
      severity = "warning"
    )
  }
  for (src in sources[-1L]) {
    if (!is.null(src$skipped)) {
      x$issues <- cross_check_issue(x$issues, "cross-check-failed", src$skipped)
      next
    }
    got <- tryCatch(cross_check_read(src, args), error = function(e) e)
    if (inherits(got, "error")) {
      # Asked for Nix, a default.nix that Nix cannot read is an error here too.
      if (src$name == "default.nix" && isTRUE(args$nix)) {
        stop(got)
      }
      x$issues <- cross_check_issue(x$issues, "cross-check-failed", src$failed(got))
      next
    }
    other <- got$sbom
    records <- got$records
    if (!is.null(src$partial)) {
      x$issues <- cross_check_issue(x$issues, "cross-check-partial", src$partial)
    }
    # That Nix ran and could not read default.nix is the user's to see.
    nix_ran <- other$issues[other$issues$code %in% c("nix-failed", "nix-not-built"), , drop = FALSE]
    nix_ran$ref <- rep(x$metadata$root, nrow(nix_ran))
    x$issues <- rbind(x$issues, nix_ran)
    found <- drift_issues(
      empty_issues(), recorded, drift_view(other, records, suggests = FALSE),
      primary$label, src$label
    )
    if (identical(records, "direct")) {
      found <- found[found$code == "drift-extra", , drop = FALSE]
    }
    x$issues <- rbind(x$issues, found)
    inputs <- rbind(inputs, source_inputs(other, src))
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
  x <- apply_overrides(x, overrides)
  advisories <- if (is.null(args$advisories)) FALSE else args$advisories
  on_error <- if (is.null(args$advisories_on_error)) "error" else args$advisories_on_error
  apply_advisories(x, advisories, on_error, call = call)
}

# The arguments of sbom() that each reader takes: all of its own but the file
# or folder it reads, and for the code scan, `lib` and the shared ones.
reader_args <- function() {
  list(
    renv = setdiff(names(formals(sbom_renv)), "lockfile"),
    manifest = setdiff(names(formals(sbom_rsconnect)), "manifest"),
    package = setdiff(names(formals(sbom_package)), "path"),
    nix = setdiff(names(formals(sbom_nix)), "path"),
    code = c("author", "organization", "regid", "timestamp", "overrides", "lib",
      "embedded", "system", "advisories", "advisories_on_error"),
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
#   when it names only the root's direct dependencies and no versions; for
#   default.nix it depends on how it was read, so its `build` returns
#   list(sbom, records) instead of the <sbom> (see read_source());
# - `failed`, a function of the error that gives the issue sentence when it
#   cannot be read for a cross-check;
# - `skipped`, the issue sentence when it is not read at all, and `partial`,
#   the one when only part of it is used, or NULL;
# - `check`, for DESCRIPTION and the code, a function of `lib` that reads it
#   for a cross-check (see cross_check_read()).
#
# A manifest.json that is not a Posit Connect manifest, and a DESCRIPTION
# without a Package field, are never the SBOM's source. Such a DESCRIPTION
# still cross-checks the packages its Depends and Imports name.
project_sources <- function(path, skip = character()) {
  takes <- reader_args()
  nix_file <- file.path(path, "default.nix")
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
    list(
      name = "default.nix", label = "default.nix", file = nix_file, records = "direct",
      args = takes$nix, failed = failed("default.nix"),
      build = function(args) do.call(read_nix_sbom, c(list(path = nix_file), args))
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
        build = function(args) do.call(sbom_package, c(list(path = path), args)),
        check = function(args) do.call(description_records, c(list(path = path), args))
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
      build = function(args) do.call(code_scan, c(list(dir = path), args)),
      check = function(args) do.call(code_records, c(list(dir = path), args))
    )
  )
  present <- c(
    is_file(lock), manifest_kind != "absent", is_file(nix_file) && !"default.nix" %in% skip,
    desc_kind != "absent", TRUE
  )
  usable <- present & c(TRUE, manifest_kind == "connect", TRUE, desc_kind == "package", TRUE)
  primary <- which(usable)[[1L]]
  present[[primary]] <- FALSE
  c(all[primary], all[present])
}

# A source read with `args`, as list(sbom, records): `records` is how its
# SBOM records the packages, "all" or "direct", which is the source's own
# setting unless its reader says (default.nix).
read_source <- function(src, args) {
  out <- src$build(args)
  if (inherits(out, "sbom")) list(sbom = out, records = src$records) else out
}

# A source read for a cross-check, as read_source() gives it. A cross-check
# compares packages only, so it looks neither inside them nor at the
# operating system: DESCRIPTION and the code, which name only the root's
# direct dependencies, are read by their `check`, which builds no SBOM, and
# any other source by its reader, given only `lib` and `nix` and told not to
# look.
cross_check_read <- function(src, args) {
  if (is.function(src$check)) {
    out <- src$check(args[intersect(names(args), "lib")])
    return(list(sbom = out, records = src$records))
  }
  quick <- list(embedded = FALSE, system = FALSE)
  read_source(src, c(
    args[intersect(names(args), intersect(src$args, c("lib", "nix")))],
    quick[intersect(names(quick), src$args)]
  ))
}

# What a cross-check of a "direct" source compares, which is all that
# drift_view() keeps of it: the root and the packages it names in `fields`
# of `root_desc`, each looked up through `lookup` as the full reader looks it
# up (resolve_dependencies()), but not followed. A package found is the
# component the full reader would list, with its ref, name, version and
# ecosystem and no more (no license, maintainer or anything inside it), and
# one not found the same unknown component. R and the base packages, which
# are never drift, are left out. `root` is the root's component row and
# `inputs` the full reader's.
direct_records <- function(root, root_desc, fields, lookup, inputs) {
  res <- resolve_dependencies(root_desc, lookup, fields, recurse = FALSE)
  rows <- c(
    lapply(res$packages, function(name) record_component(lookup$get(name))),
    lapply(res$missing, unknown_component)
  )
  ref_of <- stats::setNames(vapply(rows, function(row) row$ref, ""), c(res$packages, res$missing))
  own <- res$edges$from == root_desc[["Package"]] & res$edges$to %in% names(ref_of)
  edges <- res$edges[own, , drop = FALSE]
  new_sbom(
    list(
      root = root$ref, timestamp = NA, author = NA_character_,
      organization = NA_character_, tool_version = NA_character_, notes = character(),
      inputs = inputs, regid = NA_character_
    ),
    do.call(rbind, c(list(root), rows)),
    data.frame(
      from = rep(root$ref, nrow(edges)), to = unname(ref_of[edges$to]), field = edges$field,
      spec = edges$spec, evidence = rep("declared", nrow(edges)), stringsAsFactors = FALSE
    ),
    empty_issues()
  )
}

# The component of an installed package as a cross-check needs it: what
# package_component() gives for its ref, name, version and ecosystem.
record_component <- function(desc, evidence = "observed", is_root = FALSE) {
  name <- desc_field(desc, "Package")
  eco <- package_ecosystem(desc)
  component_row(
    ref = package_ref(eco, name), name = name, version = desc_field(desc, "Version"),
    version_is = "exact", type = "library", ecosystem = eco$ecosystem, is_root = is_root,
    purl = eco$purl, evidence = evidence
  )
}

# DESCRIPTION for a cross-check: the packages its Depends, Imports and
# LinkingTo name, read as sbom_package() reads them, with its errors.
description_records <- function(path, lib = .libPaths()) {
  check_lib(lib)
  root_desc <- read_package_description(path)
  direct_records(
    record_component(root_desc, "declared", is_root = TRUE), root_desc,
    c("Depends", "Imports", "LinkingTo"), library_lookup(lib),
    library_inputs("DESCRIPTION", path, lib)
  )
}

# The code for a cross-check: the packages it uses, found as code_scan()
# finds them, with its errors.
code_records <- function(dir, lib = .libPaths()) {
  check_lib(lib)
  direct_records(
    project_root_component(dir)$component, code_root(dir)$desc,
    c("Depends", "Imports", "LinkingTo"), library_lookup(lib), library_inputs("code", dir, lib)
  )
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
# innermost cause's message, without color, wrapping or a final full stop,
# and with the folder's path, quoted or not, as given or normalized, made
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

# A source's rows for metadata$inputs: the source itself, then the snapshot
# and the libraries its reader read.
source_inputs <- function(x, src) {
  read <- x$metadata$inputs
  rbind(
    data.frame(kind = src$name, path = as.character(src$file), stringsAsFactors = FALSE),
    read[read$kind %in% c("snapshot", "library"), c("kind", "path"), drop = FALSE]
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
  home <- home_folder()
  windows <- .Platform$OS.type == "windows"
  same <- function(a, b) if (windows) identical(tolower(a), tolower(b)) else identical(a, b)
  repeat {
    # A repository at the home folder is a dotfiles repository, not the
    # project's.
    if (same(d, home)) {
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

# The home folder as git finds it: HOME when it is set, also on Windows,
# where R's "~" is the Documents folder; else USERPROFILE on Windows; else "~".
home_folder <- function() {
  home <- Sys.getenv("HOME")
  if (!nzchar(home) && .Platform$OS.type == "windows") {
    home <- Sys.getenv("USERPROFILE")
  }
  if (!nzchar(home)) {
    home <- path.expand("~")
  }
  normalizePath(home, winslash = "/", mustWork = FALSE)
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
