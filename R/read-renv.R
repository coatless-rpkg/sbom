# Reading an renv.lock into an <sbom>.

#' Build an SBOM from an renv lockfile
#'
#' `sbom_renv()` describes the packages that an `renv.lock` pins. It reads the
#' lockfile with renv, and it runs no code from the project and makes no
#' network requests, except that `advisories = TRUE` downloads OSV's advisory
#' data.
#'
#' Every locked package is listed at its locked version, as declared, with its
#' source: CRAN or another repository, Bioconductor, GitHub, GitLab,
#' Bitbucket, another git repository, or a local source. A package whose
#' source the lockfile does not record is of ecosystem `"unknown"`, with an
#' issue. renv's `Hash` field is not a file checksum, so it is not recorded.
#' R is listed at the version the lockfile names.
#'
#' The project folder, the directory of the lockfile, is the root, with its
#' git commit as the version when it is in a git repository. A lockfile does
#' not say which packages the project uses directly. They are inferred: the
#' locked packages that [renv::dependencies()] finds in the project's code,
#' or, when it finds none, the locked packages that no other locked package
#' requires. Both are recorded as inferred. renv itself, which renv infers
#' from the lockfile, is left out, as is the code of a project nested in a
#' subfolder and, in a package folder, the files a package does not ship.
#'
#' Lockfiles from older versions of renv record only the names a package
#' requires, or nothing at all, and no licence or maintainer. What is missing
#' is read from the installed package, but only when its version is the
#' locked one. Otherwise it is recorded as unknown, with an issue. A package
#' whose dependencies are unknown gets no dependency entry in CycloneDX,
#' rather than an empty one.
#'
#' When `library` is given, the versions installed there are compared with
#' the lockfile, and each package missing on one side or installed at another
#' version is an issue. Without `library`, the project's renv library is
#' compared, together with the recommended packages in R's own library that
#' the lockfile locks, since renv leaves those there. Without either, an
#' issue says that nothing was compared. The SBOM still lists the locked
#' versions.
#'
#' @inheritParams sbom_package
#' @param lockfile The path to an `renv.lock` file.
#' @param library Library paths to compare with the lockfile and to read what
#'   the lockfile does not record from. Each must exist. `NULL` uses the
#'   project's renv library when there is one.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' sbom_renv(system.file("extdata", "renv.lock", package = "sbom"), system = FALSE)
#' @export
sbom_renv <- function(lockfile = "renv.lock", library = NULL,
                      author = getOption("sbom.author"),
                      organization = getOption("sbom.organization"),
                      regid = getOption("sbom.regid"),
                      timestamp = NULL, overrides = NULL,
                      embedded = TRUE, system = TRUE, advisories = FALSE,
                      advisories_on_error = c("error", "continue")) {
  on_error <- check_advisories_args(advisories, advisories_on_error)
  regid <- check_regid(regid)
  lock <- read_renv_lock(lockfile)
  project <- dirname(normalizePath(lockfile, mustWork = TRUE))
  given <- !is.null(library)
  if (given) {
    check_lib(library)
  } else {
    proj_lib <- tryCatch(renv::paths$library(project = project), error = function(e) "")
    library <- if (length(proj_lib) == 1L && nzchar(proj_lib) && dir.exists(proj_lib)) proj_lib
  }
  lookup <- if (!is.null(library)) library_lookup(library)
  recs <- renv_records(lock)
  filled <- list(
    records = recs, borrowed = list(), deps_known = renv_deps_recorded(lock),
    not_installed = character()
  )
  if (!is.null(lookup)) {
    filled <- fill_from_library(recs, lookup, filled$deps_known)
  }
  recs <- filled$records

  names_locked <- names(recs)
  edges <- renv_edges(recs, lock)
  scan <- project_root_edges(project, recs, lock)
  root_edges <- scan$edges
  edges <- rbind(root_edges, edges)
  stand_in <- ".sbom-project-root"
  edges$from[edges$from == ""] <- stand_in
  base <- base_packages()
  absent <- setdiff(edges$to, c(names_locked, base, "R"))
  resolved <- list(
    packages = sort(names_locked, method = "radix"),
    missing = sort(unique(absent), method = "radix"),
    edges = edges
  )

  root <- project_root_component(project)
  inputs <- data.frame(
    kind = c("renv.lock", rep("library", length(library))),
    path = c(as.character(lockfile), as.character(library)),
    stringsAsFactors = FALSE
  )
  r_version <- if (!is.null(lock$R$Version)) as.character(lock$R$Version)
  x <- build_sbom(
    root = root, lookup = list(get = function(name) recs[[name]]),
    root_desc = c(Package = stand_in), fields = character(),
    root_suggests = FALSE, lib = character(), r_version = r_version,
    author = author, organization = organization, regid = regid,
    timestamp = timestamp, inputs = inputs, resolved = resolved,
    embedded = embedded, system = system, detect_lib = library,
    package_evidence = "declared", package_source = "renv.lock",
    where = "recorded in renv.lock",
    missing_code = "dependency-not-locked", r_evidence = "declared", all_required = TRUE,
    not_installed = filled$not_installed
  )
  x <- mark_deps_unknown(x, names(filled$deps_known)[!filled$deps_known], "renv.lock")

  comps <- x$components
  for (name in names(filled$borrowed)) {
    i <- which(comps$name == name & comps$source_input %in% "renv.lock")[1L]
    x$issues <- borrowed_issue(
      x$issues, comps$ref[i], filled$borrowed[[name]], pkg_label(name, comps$version[i]), "renv.lock"
    )
  }
  x$issues <- scan_issue(x$issues, root, scan)
  if (!is.null(lookup)) {
    # A dependency that is not locked is already reported, and is not in
    # renv.lock to drift from.
    locked <- x
    locked$components <- comps[!comps$evidence %in% "unknown", , drop = FALSE]
    installed <- lookup$all()[, c("package", "version")]
    kept <- if (!given) system_recommended(installed$package, names_locked)
    from_r <- locked$components$name %in% kept$package
    here <- locked
    here$components <- locked$components[!from_r, , drop = FALSE]
    x$issues <- drift_issues(
      x$issues, here, library_stub(installed), "renv.lock",
      if (given) "the library" else "the project library"
    )
    if (!is.null(kept) && nrow(kept) > 0L) {
      # Recommended packages restore to R's own library, not the project's.
      there <- locked
      there$components <- locked$components[from_r, , drop = FALSE]
      x$issues <- drift_issues(x$issues, there, library_stub(kept), "renv.lock", "R's library")
      r_lib <- normalizePath(.Library, winslash = "/", mustWork = FALSE)
      listed <- normalizePath(as.character(library), winslash = "/", mustWork = FALSE)
      if (!r_lib %in% listed) {
        x$metadata$inputs <- rbind(
          x$metadata$inputs,
          data.frame(kind = "library", path = r_lib, stringsAsFactors = FALSE)
        )
      }
    }
  } else {
    x$issues <- add_issue(
      x$issues, root$component$ref, "library", "drift-not-checked",
      "No project library was found, so the installed packages were not compared with renv.lock.",
      severity = "info"
    )
  }
  rownames(x$issues) <- NULL
  apply_advisories(apply_overrides(x, overrides), advisories, on_error)
}

# The lockfile as a list, or an error that names the file. renv's own errors
# never reach the caller.
read_renv_lock <- function(lockfile, call = parent.frame()) {
  if (!is.character(lockfile) || length(lockfile) != 1L || is.na(lockfile) ||
    !file.exists(lockfile) || dir.exists(lockfile)) {
    cli::cli_abort(
      "The renv lockfile {.file {lockfile}} does not exist.", call = call
    )
  }
  raw <- tryCatch(jsonlite::read_json(lockfile), error = function(e) NULL)
  if (!is.list(raw) || is.null(names(raw))) {
    cli::cli_abort(
      "The renv lockfile {.file {lockfile}} is not valid JSON.", call = call
    )
  }
  if (!is.list(raw$Packages)) {
    cli::cli_abort(
      "The renv lockfile {.file {lockfile}} has no {.field Packages}.", call = call
    )
  }
  lock <- tryCatch(
    unclass(suppressWarnings(renv::lockfile_read(lockfile))),
    error = function(e) NULL
  )
  if (is.null(lock)) {
    cli::cli_abort(
      "The renv lockfile {.file {lockfile}} could not be read.", call = call
    )
  }
  lock
}

# One named character vector per locked package, in DESCRIPTION shape, named
# by package and sorted by name. Arrays are joined with ", ". renv's `Source`
# is kept, and is "unknown" when the lockfile does not record one; it gives
# a missing `RemoteType`, and for a Bioconductor package without `git_url`,
# the lockfile's Bioconductor release is added as `Bioconductor.Version`.
renv_records <- function(lock) {
  repos <- unlist(lock$R$Repositories)
  bioc <- lock$Bioconductor$Version
  bioc <- if (is.character(bioc) && length(bioc) == 1L) enc2utf8_bytes(bioc) else NA_character_
  pkgs <- lock$Packages
  out <- lapply(names(pkgs), function(key) {
    p <- pkgs[[key]]
    p$Package <- if (is.null(p$Package)) key else p$Package
    p$Hash <- NULL
    p$Requirements <- NULL
    fields <- vapply(p, function(v) {
      if (is.null(v) || length(v) == 0L) {
        NA_character_
      } else {
        paste(as.character(unlist(v)), collapse = ", ")
      }
    }, "")
    fields <- fields[!is.na(fields)]
    fields <- stats::setNames(enc2utf8_bytes(unname(fields)), enc2utf8_bytes(names(fields)))
    source <- desc_field(fields, "Source")
    if (is.na(source)) {
      source <- "unknown"
      fields[["Source"]] <- source
    }
    if (identical(source, "Local")) {
      fields <- fields[names(fields) != "Repository"]
    }
    remote <- c(github = "github", gitlab = "gitlab", bitbucket = "bitbucket", git = "git")
    if (tolower(source) %in% names(remote) && !"RemoteType" %in% names(fields)) {
      fields[["RemoteType"]] <- remote[[tolower(source)]]
    }
    if (identical(tolower(source), "bioconductor") && !"git_url" %in% names(fields) && !is.na(bioc)) {
      fields[["Bioconductor.Version"]] <- bioc
    }
    repo <- if ("Repository" %in% names(fields)) fields[["Repository"]] else NA_character_
    if (identical(source, "Repository") && !is.na(repo) && !"RemoteRepos" %in% names(fields) &&
      repo %in% names(repos)) {
      fields[["RemoteRepos"]] <- enc2utf8_bytes(unname(repos[[repo]]))
    }
    fields
  })
  names(out) <- vapply(out, function(f) f[["Package"]], "")
  out[order(names(out), method = "radix")]
}

# Whether each locked package's record says what it depends on: it is
# DESCRIPTION-shaped, so that absent dependency fields mean it has none, or
# it has an older lockfile's Requirements, even when empty. Named by
# package, as renv_records() names them.
renv_deps_recorded <- function(lock) {
  pkgs <- lock$Packages
  known <- vapply(names(pkgs), function(key) {
    fields <- names(pkgs[[key]])
    description_shaped(fields) || "Requirements" %in% fields
  }, NA)
  names(known) <- vapply(names(pkgs), function(key) {
    name <- pkgs[[key]]$Package
    enc2utf8_bytes(if (is.null(name)) key else paste(as.character(unlist(name)), collapse = ", "))
  }, "")
  known
}

# Whether a record with these field names carries DESCRIPTION fields beyond
# those that only say which package it is and where it came from (Package,
# Version, Source, Repository, Hash, Remote* and git_*, and the fields sbom
# adds to a record itself), such as Title, License, Maintainer or Imports.
# Such a record states its dependencies, if any.
description_shaped <- function(fields) {
  bare <- fields %in% c("Package", "Version", "Source", "Repository", "Hash",
                        "Requirements", "Bioconductor.Version") |
    startsWith(fields, "Remote") | startsWith(fields, "git_")
  any(!bare)
}

# What a record lacks (licence, maintainer, and dependencies when
# `deps_known` is FALSE for it), from the installed copy when its version is
# the locked one. Returns the records, what was borrowed for each (a list of
# "licence", "maintainer" and "dependencies"), the updated `deps_known`, and
# `not_installed`, the records that lacked something with no such copy.
fill_from_library <- function(records, lookup, deps_known) {
  borrowed <- list()
  not_installed <- character()
  for (name in names(records)) {
    rec <- records[[name]]
    need_license <- is.na(desc_field(rec, "License"))
    need_maint <- is.na(desc_field(rec, "Maintainer")) && is.na(desc_field(rec, "Authors@R"))
    need_deps <- !isTRUE(deps_known[name])
    if (!need_license && !need_maint && !need_deps) {
      next
    }
    inst <- lookup$get(name)
    if (is.null(inst) || !identical(trimws(inst[["Version"]]), desc_field(rec, "Version"))) {
      not_installed <- c(not_installed, name)
      next
    }
    got <- character()
    copy <- function(fields) {
      values <- vapply(fields, function(field) desc_field(inst, field), "")
      for (field in fields[!is.na(values)]) {
        rec[[field]] <<- enc2utf8_bytes(values[[field]])
      }
      any(!is.na(values))
    }
    if (need_license && copy("License")) {
      got <- c(got, "licence")
    }
    if (need_maint && copy(c("Maintainer", "Authors@R"))) {
      got <- c(got, "maintainer")
    }
    if (need_deps) {
      # The installed copy says what it depends on, even when that is nothing.
      copy(c("Depends", "Imports", "LinkingTo"))
      deps_known[[name]] <- TRUE
      got <- c(got, "dependencies")
    }
    records[[name]] <- rec
    if (length(got) > 0L) {
      borrowed[[name]] <- got
    }
  }
  list(
    records = records, borrowed = borrowed, deps_known = deps_known,
    not_installed = not_installed
  )
}

# The fields-from-library issue, naming only the fields borrowed.
borrowed_issue <- function(issues, ref, fields, label, source) {
  plural <- length(fields) > 1L || identical(fields, "dependencies")
  what <- if (length(fields) > 1L) {
    paste(paste(fields[-length(fields)], collapse = ", "), "and", fields[length(fields)])
  } else {
    fields
  }
  field <- c(licence = "license", maintainer = "maintainer", dependencies = "dependencies")
  add_issue(
    issues, ref, field[[fields[[1L]]]], "fields-from-library",
    paste0(
      "The ", what, " of ", label, if (plural) " come" else " comes",
      " from the installed library, because ", source, " does not record ",
      if (plural) "them" else "it", "."
    ),
    severity = "info"
  )
}

# Marks the packages from `source` named in `unknown` as having unknown
# dependencies, with one issue when there are any.
mark_deps_unknown <- function(x, unknown, source) {
  comps <- x$components
  hit <- !comps$is_root & comps$source_input %in% source & comps$name %in% unknown
  if (!any(hit)) {
    return(x)
  }
  comps$deps_known[hit] <- FALSE
  x$components <- comps
  x$issues <- add_issue(
    x$issues, x$metadata$root, "dependencies", "dependencies-not-recorded",
    paste0(
      source, " does not record what some of its packages depend on, so the ",
      "links between them are unknown."
    )
  )
  x
}

# Edges between locked packages, declared by each record: the dependency
# fields of a modern lockfile, or the names in `Requirements` of an older one,
# which carry no constraint.
renv_edges <- function(records, lock) {
  rows <- list()
  for (name in names(records)) {
    rec <- records[[name]]
    legacy <- lock$Packages[[name]]$Requirements
    dep_fields <- intersect(c("Depends", "Imports", "LinkingTo"), names(rec))
    if (length(dep_fields) == 0L && length(legacy) > 0L) {
      req <- enc2utf8_bytes(as.character(unlist(legacy)))
      rows[[length(rows) + 1L]] <- data.frame(
        from = name, to = req, field = "Requirements", spec = req,
        constraint = NA_character_, evidence = "declared", stringsAsFactors = FALSE
      )
    }
    for (field in dep_fields) {
      d <- parse_dep_field(rec[[field]], field)
      if (nrow(d) > 0L) {
        rows[[length(rows) + 1L]] <- data.frame(
          from = name, to = d$name, field = field, spec = d$spec,
          constraint = d$constraint, evidence = "declared", stringsAsFactors = FALSE
        )
      }
    }
  }
  bind_edges(rows)
}

# Shared by sbom_renv(), sbom_rsconnect() and code_scan(); `lock` is NULL for
# a manifest, and `records` is NULL for a code scan. The root's edges, with
# `from` left empty, and whether the scan of the code was complete. Packages
# the project's code uses and that are locked; else every locked package
# nothing else requires. A code scan takes every package found other than R
# and base packages, and nothing else.
#
# The project's own code excludes that of a project nested in a subfolder
# (nested_projects()) and, in a package folder, the files the package does
# not ship (unshipped_files()). renv infers renv itself from a renv.lock,
# which is infrastructure, not a dependency, so it is left out then.
#
# renv reports code it could not parse only on the console, and only when not
# quiet. So the scan runs once with its report captured and errors fatal; if
# that fails, once more quietly for what it can find.
project_root_edges <- function(project, records, lock) {
  complete <- TRUE
  scanned <- tryCatch(
    {
      utils::capture.output(
        utils::capture.output(
          out <- renv::dependencies(project, quiet = FALSE, progress = FALSE, errors = "fatal"),
          type = "message"
        )
      )
      out
    },
    error = function(e) {
      complete <<- FALSE
      tryCatch(
        suppressWarnings(renv::dependencies(project, quiet = TRUE, errors = "ignored")),
        error = function(e) NULL
      )
    }
  )
  if (is.data.frame(scanned) && nrow(scanned) > 0L) {
    paths <- as.character(scanned$Source)
    drop <- nested_projects(project)(paths)
    unshipped <- unshipped_files(project)
    if (!is.null(unshipped)) {
      drop <- drop | unshipped(paths)
    }
    scanned <- scanned[!drop, , drop = FALSE]
  }
  infrastructure <- if (file.exists(file.path(project, "renv.lock"))) "renv"
  found <- sort(unique(as.character(scanned$Package)), method = "radix")
  found <- found[!is.na(found) & nzchar(found) & !found %in% infrastructure]
  used <- if (is.null(records)) {
    setdiff(found, c(base_packages(), "R"))
  } else {
    intersect(found, names(records))
  }
  edges <- if (length(used) > 0L || is.null(records)) {
    n <- length(used)
    data.frame(
      from = rep("", n), to = used, field = rep("Imports", n), spec = used,
      constraint = rep(NA_character_, n), evidence = rep("inferred", n),
      stringsAsFactors = FALSE
    )
  } else {
    inner <- renv_edges(records, lock)
    top <- setdiff(names(records), c(unique(inner$to), infrastructure))
    data.frame(
      from = rep("", length(top)), to = top, field = rep("Requirements", length(top)),
      spec = top, constraint = rep(NA_character_, length(top)),
      evidence = rep("inferred", length(top)), stringsAsFactors = FALSE
    )
  }
  list(edges = edges, complete = complete)
}

# A function of file paths that is TRUE for those under a subfolder of
# `project` that holds its own renv.lock, DESCRIPTION or manifest.json: a
# project of its own, whose code is not the parent's.
nested_projects <- function(project) {
  root <- normalizePath(project, winslash = "/", mustWork = TRUE)
  marks <- c("renv.lock", "DESCRIPTION", "manifest.json")
  seen <- new.env(parent = emptyenv())
  is_project <- function(dir) {
    if (is.null(seen[[dir]])) {
      f <- file.path(dir, marks)
      seen[[dir]] <- any(file.exists(f) & !dir.exists(f))
    }
    seen[[dir]]
  }
  function(paths) {
    full <- normalizePath(paths, winslash = "/", mustWork = FALSE)
    vapply(dirname(full), function(dir) {
      while (startsWith(dir, paste0(root, "/"))) {
        if (is_project(dir)) {
          return(TRUE)
        }
        dir <- dirname(dir)
      }
      FALSE
    }, NA, USE.NAMES = FALSE)
  }
}

# The code-scan-incomplete issue, when the scan of the project's code was.
scan_issue <- function(issues, root, scan) {
  if (scan$complete) {
    return(issues)
  }
  add_issue(
    issues, root$component$ref, "dependencies", "code-scan-incomplete",
    paste0(
      "Some R code in ", root$component$name, " could not be parsed, so the ",
      "project's direct dependencies may be incomplete."
    ),
    severity = "info"
  )
}

bind_edges <- function(rows) {
  if (length(rows) == 0L) {
    return(data.frame(
      from = character(), to = character(), field = character(),
      spec = character(), constraint = character(), evidence = character(),
      stringsAsFactors = FALSE
    ))
  }
  do.call(rbind, rows)
}

# A throwaway <sbom> holding only the name and version of each installed
# non-base package in `db` (a data frame with columns package and version),
# for comparing with another SBOM.
library_stub <- function(db) {
  db <- db[!db$package %in% base_packages(), , drop = FALSE]
  rows <- lapply(seq_len(nrow(db)), function(i) {
    component_row(
      ref = db$package[[i]], name = db$package[[i]], version = db$version[[i]],
      version_is = "exact", type = "library", ecosystem = "library"
    )
  })
  root <- component_row(
    ref = "library", name = ".library", type = "platform", ecosystem = "library",
    is_root = TRUE
  )
  comps <- do.call(rbind, c(list(root), rows))
  new_sbom(
    list(
      root = "library", timestamp = NA, author = NA_character_,
      organization = NA_character_, tool_version = NA_character_,
      notes = character(), inputs = data.frame(), regid = NA_character_
    ),
    comps, empty_relationships(), empty_issues()
  )
}

# The recommended packages in R's own library that are locked (`locked`) but
# not installed (`have`), as a data frame of package and version. renv
# restores into the project library and leaves these where R installed them.
system_recommended <- function(have, locked) {
  system <- library_lookup(.Library)
  rows <- lapply(setdiff(locked, have), function(name) {
    desc <- system$get(name)
    if (!is.null(desc) && identical(desc_field(desc, "Priority"), "recommended")) {
      data.frame(package = name, version = desc_field(desc, "Version"), stringsAsFactors = FALSE)
    }
  })
  do.call(rbind, c(
    list(data.frame(package = character(), version = character(), stringsAsFactors = FALSE)),
    rows
  ))
}

# The project folder as the root component, and its issues. Its ref,
# project/<name>, is apart from any package's, including a locked package of
# the same name, such as a golem app's own.
project_root_component <- function(dir) {
  name <- enc2utf8_bytes(basename(normalizePath(dir, mustWork = TRUE)))
  version <- git_commit(dir)
  ref <- paste0("project/", name)
  row <- component_row(
    ref = ref, name = name, version = version,
    version_is = if (is.na(version)) NA_character_ else "exact",
    type = "application", ecosystem = "local", is_root = TRUE,
    scope = "required", evidence = "observed", source_input = "project"
  )
  issues <- empty_issues()
  if (is.na(version)) {
    why <- if (!is.na(git_root(dir))) {
      paste0("The git commit of the project folder ", name, " could not be read")
    } else {
      paste0("The project folder ", name, " is not a git repository")
    }
    issues <- add_issue(
      issues, ref, "version", "version-missing", paste0(why, ", so it has no version.")
    )
  }
  list(component = row, issues = issues)
}
