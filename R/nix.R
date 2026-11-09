# Reading a Nix environment file written by the rix package, as text. Without
# Nix the file is never evaluated; with Nix it is handed to nix-instantiate.
# The parser is in nix-parse.R, the CRAN snapshot lookup in nix-snapshot.R
# and Nix mode in nix-store.R.

#' Build an SBOM from a Nix environment file
#'
#' `sbom_nix()` describes the software that a `default.nix` written by the
#' rix package declares: R, R packages, packages from git or from the CRAN
#' archive, Nix system packages and TeX Live. Without Nix it reads the file as
#' text, runs no code from it and makes no network request unless you pass
#' `snapshot`. With Nix installed it reads the environment from the Nix store
#' instead; see Nix mode. `advisories = TRUE` also downloads OSV's advisory
#' data.
#'
#' ## Nix mode
#'
#' With Nix installed (`nix-instantiate` and `nix-store` on the path),
#' `sbom_nix()` evaluates the file, takes the inputs of its shell and reads
#' the runtime closure of their outputs from the Nix store. It is the only
#' way to read a hand-written Nix file. It runs `nix-instantiate`, which
#' evaluates the file and may download nixpkgs, so unlike the static read it
#' can use the network, through Nix. `snapshot` is not used. It records:
#'
#' * R, and each R package (every store path named `r-<name>`), labeled
#'   observed, at the version in its store path or, when the path has none,
#'   in its `DESCRIPTION` in the store. A package's license and maintainer
#'   come from that `DESCRIPTION` when it is readable.
#' * A package that a file written by rix fetches from git or from the CRAN
#'   archive is described as in the static read below (its package URL,
#'   download location and description), with the version from the store.
#'   Any other package comes from the repository its `DESCRIPTION` names. One
#'   whose `DESCRIPTION` names none, or cannot be read, is taken to be the
#'   CRAN package of that name, with no supplier, and an issue says that its
#'   package URL is inferred.
#' * Every other store path as a component `nix/<name>` of ecosystem `nix`,
#'   with the version in its store path and a description that names it.
#'   The outputs of one derivation (`curl`, `curl-lib` and `curl-dev`) are
#'   one component. One issue lists the store paths, and the R packages,
#'   that have no version.
#' * Dependencies from the references graph of the store: `Imports` to an R
#'   package, `Depends` to R, `dynamic_link` to a Nix library (one that has a
#'   `lib` output or a name starting with `lib`) and `system_requirement` to
#'   any other Nix package. The root points to the direct inputs of the
#'   shell. An issue counts any reference that sbom could not place.
#'
#' Nix mode is experimental. It is built on the output formats documented for
#' Nix 2.18 and later, and its tests use recorded examples of that output
#' rather than a Nix installation.
#'
#' `nix = NA` reads the store when Nix is installed and the file otherwise.
#' `nix = TRUE` requires Nix and is an error without it, or when Nix cannot
#' evaluate the file. `nix = FALSE` always reads the file, as below.
#'
#' If none of the outputs of an input of the shell is in the store, because the
#' environment has not been built, sbom reads the file instead and adds the issue `nix-not-built`:
#' build the environment with `nix-shell` or `nix-build` first. For a
#' hand-written file there is nothing to fall back to, and that is an error.
#' `library` is not read in Nix mode, and `system` has no effect, since the
#' closure already holds the system packages.
#'
#' ## Without Nix
#'
#' Without Nix, sbom reads only files that rix generated, which it knows by
#' their header comment. A hand-written Nix file is an error: it needs Nix.
#'
#' What the static mode records:
#'
#' * The project folder, the folder of the file, is the root.
#' * R, at the version of rix's `r_ver` when it is a version, as declared.
#'   Otherwise R has no version, and an issue records it as missing.
#' * Each R package that the file names, by name only. These come from a
#'   nixpkgs snapshot that the file pins, but the file does not say which
#'   version that snapshot holds, so their versions are unknown and one issue
#'   suggests passing `snapshot` to look them up. nixpkgs' `rPackages` holds Bioconductor packages as well as
#'   CRAN ones, so each is taken to be the CRAN package of that name, with no
#'   supplier, and one issue says that their package URLs are inferred.
#' * Packages that rix fetches from git, and from the CRAN archive. An archive
#'   package has the version in its file name, as declared. A git package has
#'   no version, but its URL and revision are recorded in its description,
#'   and a GitHub package has a package URL that names the revision. The R
#'   packages they depend on are listed as their dependencies. Their URLs are
#'   recorded without a user name, password, query string or fragment, which
#'   can hold tokens.
#' * Each Nix system package, such as `glibcLocales` or `nix`, as a component
#'   `nix/<name>` of ecosystem `nix` with no version and no package URL, since
#'   the package URL specification has no `nix` type. TeX Live is one
#'   component, `nix/texlive`, whose description names the TeX packages.
#'   These are recorded whatever `system` is, because the file declares them.
#' * A note on where the packages come from: the rstats-on-nix snapshot of a
#'   date, or a nixpkgs commit.
#'
#' The `sha256` values in the file are Nix's hashes of the unpacked source,
#' not hashes of a file, so they are written in a package's description and
#' never as a file hash. Python and Julia packages that the file installs are
#' not listed, and an issue names the kinds of software left out.
#'
#' ## Looking up versions
#'
#' Apart from `advisories`, `snapshot` is the only way `sbom_nix()` uses the
#' network, and it does so only when you pass it. It looks the versions up in
#' a CRAN `PACKAGES` file:
#'
#' * `NULL`, the default, looks nothing up and makes no network request.
#' * `"ppm"` reads the CRAN snapshot that Posit Package Manager keeps for the
#'   date of the pinned nixpkgs,
#'   `https://packagemanager.posit.co/cran/<date>/src/contrib/PACKAGES`. It
#'   works only when nixpkgs is pinned to a date; for a commit, an issue says
#'   so and nothing is looked up.
#' * A path or URL of a `PACKAGES` file reads that file instead.
#'
#' Each CRAN package that the file names without a version takes the version
#' the snapshot lists, and sbom follows `Depends`, `Imports` and `LinkingTo`
#' in the snapshot to add the packages that Nix would install with it. The
#' versions and the added packages and dependencies are labeled inferred,
#' since the snapshot is a stand-in for what Nix installed. R, base and
#' recommended packages are left to R's own handling. Archive packages keep
#' the version in their URL, and git packages stay without a version. A
#' package that the snapshot lists is a CRAN package. One that it lacks,
#' named by the file or by a snapshot package's dependencies, may not be one,
#' so it is listed without a version or package URL, with an issue. If the
#' snapshot cannot be read, the versions stay unknown and an issue gives the
#' reason. A snapshot given as a URL is
#' named in the notes by that URL, without its credentials, query string or
#' fragment, and a local file by its name.
#'
#' `library`, `embedded` and `system` apply as for [sbom_renv()], to the
#' packages whose version the file declares and that are installed in
#' `library` at that version. The installed copy fills in what the file
#' lacks: the license and maintainer. Without `library`, nothing is read from
#' an installed copy. One issue lists the packages left without a license or
#' maintainer.
#'
#' @inheritParams sbom_package
#' @param path The path to the Nix file, usually `default.nix`.
#' @param nix Whether to use Nix to read the file. `NA` uses Nix when it is
#'   installed, `TRUE` requires it and `FALSE` reads the file as text. See
#'   Details.
#' @param snapshot `NULL`, `"ppm"`, or the path or URL of a CRAN `PACKAGES`
#'   file, to look the package versions up in. The lookup uses the network
#'   only when `snapshot` is given. See Details.
#' @param library Library paths to read what the file does not record from.
#'   Each must exist. `NULL` reads none.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' nix <- file.path(tempdir(), "default.nix")
#' writeLines(c(
#'   "# This file was generated by the {rix} R package v0.18.6 on 2026-11-05",
#'   "# >rix(r_ver = \"4.4.1\")",
#'   "let",
#'   paste0(
#'     "  pkgs = import (fetchTarball ",
#'     "\"https://github.com/rstats-on-nix/nixpkgs/archive/2024-10-01.tar.gz\") {};"
#'   ),
#'   "  rpkgs = builtins.attrValues {",
#'   "    inherit (pkgs.rPackages) dplyr data_table;",
#'   "  };",
#'   "in rpkgs"
#' ), nix)
#' sbom_nix(nix, nix = FALSE, system = FALSE)
#' \dontrun{
#' # Needs the network: looks the package versions up in a CRAN snapshot.
#' sbom_nix(nix, nix = FALSE, system = FALSE, snapshot = "ppm")
#' }
#' @export
sbom_nix <- function(path = "default.nix", nix = NA, snapshot = NULL, library = NULL,
                     author = getOption("sbom.author"),
                     organization = getOption("sbom.organization"),
                     regid = getOption("sbom.regid"),
                     timestamp = NULL, overrides = NULL,
                     embedded = TRUE, system = TRUE, advisories = FALSE,
                     advisories_on_error = c("error", "continue")) {
  on_error <- check_advisories_args(advisories, advisories_on_error)
  x <- read_nix_sbom(
    path, nix = nix, snapshot = snapshot, library = library, author = author,
    organization = organization, regid = regid, timestamp = timestamp,
    overrides = overrides, embedded = embedded, system = system,
    call = environment()
  )$sbom
  apply_advisories(x, advisories, on_error)
}

# The checks of sbom_nix()'s `nix` and `snapshot`, which sbom() makes too.
check_nix_arg <- function(nix, call = parent.frame()) {
  if (!is.logical(nix) || length(nix) != 1L) {
    cli::cli_abort("{.arg nix} must be {.code TRUE}, {.code FALSE} or {.code NA}.", call = call)
  }
}

# Aborts, with errors named for `call`, unless `snapshot` is NULL or one
# non-empty string.
check_snapshot_arg <- function(snapshot, call = parent.frame()) {
  if (!is.null(snapshot) && (!is.character(snapshot) || length(snapshot) != 1L ||
    is.na(snapshot) || !nzchar(snapshot))) {
    cli::cli_abort(
      "{.arg snapshot} must be {.code NULL}, {.code \"ppm\"}, or the path or URL of a {.file PACKAGES} file.",
      call = call
    )
  }
}

# What sbom_nix() does, as list(sbom, records). `records` says how the file
# was read, for sbom(): "all" when the SBOM lists every package with a version
# (Nix mode or a snapshot), "direct" when it names only the packages the file
# lists. Errors name `call`. A file that sbom cannot read at all, without Nix,
# or under `nix = NA` when Nix failed or the environment is not built, is an
# error of class `sbom_nix_unreadable`, which sbom() turns into an issue.
read_nix_sbom <- function(path, nix = NA, snapshot = NULL, library = NULL,
                          author = getOption("sbom.author"),
                          organization = getOption("sbom.organization"),
                          regid = getOption("sbom.regid"),
                          timestamp = NULL, overrides = NULL,
                          embedded = TRUE, system = TRUE, call = parent.frame()) {
  regid <- check_regid(regid, call = call)
  check_nix_arg(nix, call = call)
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
    !file.exists(path) || dir.exists(path)) {
    cli::cli_abort("The Nix file {.file {path}} does not exist.", call = call)
  }
  if (isTRUE(nix) && !sys_nix_available()) {
    cli::cli_abort(paste0(
      "Nix is not installed, so sbom cannot read the Nix store; ",
      "use {.code nix = FALSE} to read the file instead."
    ), call = call)
  }
  if (!is.null(library)) {
    check_lib(library, call = call)
  }
  check_snapshot_arg(snapshot, call = call)
  file <- enc2utf8_bytes(basename(path))
  text <- read_nix_file(path, call = call)
  fallback <- NULL
  if (isTRUE(nix) || (is.na(nix) && sys_nix_available())) {
    rix <- if (nix_is_rix(text)) parse_rix(text, path, call = call)
    closure <- nix_closure(path, rix)
    if (closure$status == "ok") {
      return(list(sbom = nix_store_sbom(
        path, closure, file, author, organization, regid, timestamp, overrides,
        embedded, rix
      ), records = "all"))
    }
    fallback <- closure$status
    if (!nix_is_rix(text) || (isTRUE(nix) && fallback == "failed")) {
      cli::cli_abort(
        if (fallback == "not-built") {
          nix_not_built_message("{.file {file}}")
        } else {
          paste0(
            "Nix could not read the environment in {.file {path}}",
            if (nix_is_rix(text)) "; use {.code nix = FALSE} to read the file instead." else "."
          )
        },
        # Under nix = NA, a file that Nix could not read, or has not built,
        # and that the text cannot stand in for.
        class = if (is.na(nix)) "sbom_nix_unreadable",
        call = call
      )
    }
  }
  p <- parse_rix(text, path, call = call)
  lookup <- if (!is.null(library)) library_lookup(library)

  snap <- nix_snapshot_source(snapshot, p$nixpkgs)
  found <- nix_snapshot_records(nix_records(p), snap)
  recs <- found$recs
  looked <- found$looked
  snap_reason <- found$reason
  filled <- list(
    records = recs$records, borrowed = list(), deps_known = recs$deps_known,
    not_installed = character()
  )
  if (!is.null(lookup)) {
    filled <- fill_from_library(recs$records, lookup, recs$deps_known)
  }
  recs_filled <- filled$records
  stand_in <- ".sbom-project-root"
  edges <- nix_edges(p, stand_in)
  if (!is.null(looked)) {
    edges <- rbind(edges, looked$edges)
    edges <- edges[!duplicated(edges[c("from", "to")]), , drop = FALSE]
  }
  base <- base_packages()
  resolved <- list(
    packages = sort(setdiff(as.character(names(recs_filled)), base), method = "radix"),
    missing = character(), edges = edges
  )
  root <- project_root_component(dirname(path))
  inputs <- data.frame(
    kind = c("default.nix", if (!is.na(snap$location)) "snapshot", rep("library", length(library))),
    path = c(as.character(path), if (!is.na(snap$location)) snap$shown, as.character(library)),
    stringsAsFactors = FALSE
  )
  x <- build_sbom(
    root = root, lookup = list(get = function(name) recs_filled[[name]]),
    root_desc = c(Package = stand_in), fields = character(),
    root_suggests = FALSE, lib = character(),
    r_version = if (!is.na(p$r_version)) p$r_version,
    author = author, organization = organization, regid = regid,
    timestamp = timestamp, inputs = inputs, resolved = resolved,
    embedded = embedded, system = system, detect_lib = library,
    package_evidence = "declared", package_source = "default.nix",
    where = paste0("recorded in ", file), r_evidence = "declared",
    all_required = TRUE, not_installed = filled$not_installed
  )

  comps <- x$components
  mine <- !comps$is_root & comps$source_input %in% "default.nix"
  comps$deps_known[mine & comps$name %in% names(filled$deps_known)[!filled$deps_known]] <- FALSE
  comps <- nix_describe(comps, p)
  if (!is.null(looked)) {
    comps$evidence[mine & comps$name %in% looked$inferred] <- "inferred"
  }
  # What Nix does not say is one issue below, not one per package.
  x$issues <- x$issues[!(x$issues$code %in% c("version-missing", "license-missing", "maintainer-missing", "source-unknown") &
    x$issues$ref %in% comps$ref[mine]), , drop = FALSE]
  # Without a snapshot, a name from rPackages is taken to be from CRAN.
  assumed <- if (is.null(looked)) comps$ref[mine & comps$name %in% recs$cran] else character()
  for (name in names(filled$borrowed)) {
    i <- which(comps$name == name & comps$source_input %in% "default.nix")[1L]
    x$issues <- borrowed_issue(
      x$issues, comps$ref[i], filled$borrowed[[name]],
      pkg_label(name, comps$version[i]), "default.nix"
    )
  }

  root_ref <- root$component$ref
  sys <- nix_system_components(p, file)
  comps <- rbind(comps, sys$components)
  comps <- comps[order(comps$ref, method = "radix"), , drop = FALSE]
  rownames(comps) <- NULL
  rels <- rbind(x$relationships, nix_system_relationships(root_ref, sys$components$ref))
  rels <- rels[!duplicated(rels[c("from", "to", "field")]), , drop = FALSE]
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL
  x$components <- comps
  x$relationships <- rels
  x <- nix_assume_cran(x, assumed, function(names, one) {
    paste0(
      length(names), if (one) " package that " else " packages that ", file,
      if (one) " names comes" else " names come", " from nixpkgs without a recorded repository (",
      capped_list(names), "), so ",
      if (one) "its package URL assumes it is the CRAN package of that name." else
        "their package URLs assume they are the CRAN packages of those names."
    )
  })

  x$issues <- nix_file_issues(
    x$issues, comps, root_ref, p, file, snap, snap_reason, looked, fallback,
    has_library = !is.null(library)
  )
  x$metadata$notes <- c(x$metadata$notes, nix_source_note(p$nixpkgs))
  if (!is.null(looked)) {
    old <- "Download locations are not recorded, since sbom did not look up any package repository."
    x$metadata$notes[x$metadata$notes == old] <- paste0(
      "Download locations are not recorded; versions were looked up in ", snap$label, " only."
    )
    x$metadata$notes <- c(x$metadata$notes, paste0(
      "Versions were looked up in ", snap$label, ", not read from Nix."
    ))
  }
  rownames(x$issues) <- NULL
  # A failed snapshot lookup leaves the versions unknown, so it is a direct read.
  list(
    sbom = apply_overrides(x, overrides),
    records = if (is.null(looked)) "direct" else "all"
  )
}

# `issues` with those about what the rix file `file` leaves unsaid, at the
# root `root_ref`: licenses and maintainers, the R version and the package
# versions it does not record, a snapshot that is not dated, could not be
# read or lacks packages, a block it does not close, the other software it
# installs, and that Nix could not read it (`fallback`, NULL when Nix was not
# tried). `comps` are the SBOM's components, `p` is parse_rix()'s list,
# `snap`, `snap_reason` and `looked` come from nix_snapshot_records(), and
# `has_library` says whether a library was given to look packages up in.
nix_file_issues <- function(issues, comps, root_ref, p, file, snap, snap_reason, looked,
                            fallback, has_library) {
  read_how <- if (is.null(fallback)) "without Nix" else "instead of the Nix store"
  # The licenses and maintainers that neither the file nor an installed copy
  # gives are one issue.
  pkgs <- comps[!comps$is_root & comps$source_input %in% "default.nix" & is.na(comps$parent_ref) &
    !comps$ecosystem %in% "nix", , drop = FALSE]
  unknown <- sort(unique(pkgs$name[is.na(pkgs$license_as_written) | is.na(pkgs$maintainer)]), method = "radix")
  if (length(unknown) > 0L) {
    one <- length(unknown) == 1L
    issues <- add_issue(
      issues, root_ref, "license", "nix-licenses-unknown",
      paste0(
        length(unknown), if (one) " package that " else " packages that ", file,
        if (one) " names has" else " names have", " no license or maintainer on record (",
        capped_list(unknown), "), because sbom read the file ", read_how,
        if (!has_library) {
          paste0(" and was given no library to look ", if (one) "it" else "them", " up in.")
        } else {
          paste0(" and found no installed copy of ", if (one) "it" else "them", " at the same version.")
        }
      )
    )
  }
  if (is.na(p$r_version)) {
    issues <- add_issue(
      issues, "R", "version", "r-version-unknown",
      paste0("The R version is not recorded in ", file, ", so R is listed without a version.")
    )
  }
  if (isTRUE(snap$undated)) {
    issues <- add_issue(
      issues, root_ref, "version", "nix-snapshot-not-dated",
      paste0(
        "nixpkgs is pinned to a commit, not a date, so sbom could not look up its CRAN snapshot; ",
        "pass the path or URL of a PACKAGES file instead."
      )
    )
  }
  if (!is.na(snap_reason)) {
    issues <- add_issue(
      issues, root_ref, "version", "nix-snapshot-failed",
      paste0("sbom could not read the CRAN snapshot (", snap_reason, "), so the package versions are unknown.")
    )
  }
  if (!is.null(looked) && length(looked$missing) > 0L) {
    issues <- add_issue(
      issues, root_ref, "version", "nix-not-in-snapshot",
      nix_not_in_snapshot_sentence(file, looked$missing)
    )
  }
  if (!is.null(looked) && nrow(p$git) > 0L) {
    issues <- add_issue(
      issues, root_ref, "version", "nix-git-versions-unknown",
      nix_git_versions_sentence(file, p$git$name)
    )
  }
  versionless <- comps$is_root %in% FALSE & comps$source_input %in% "default.nix" &
    comps$ecosystem %in% c("cran", "github", "git") & is.na(comps$version)
  if ((is.na(snap$location) || isTRUE(snap$undated)) && any(versionless)) {
    source <- if (is.na(p$nixpkgs$value)) "." else paste0(" for nixpkgs ", p$nixpkgs$value, ".")
    issues <- add_issue(
      issues, root_ref, "version", "nix-versions-unknown",
      paste0(
        "The versions of the packages in ", file, " are not recorded, because sbom read it ",
        read_how, "; pass snapshot to look them up", source
      )
    )
  }
  if (!is.na(p$incomplete)) {
    issues <- add_issue(
      issues, root_ref, "dependencies", "nix-parse-incomplete",
      paste0(
        "sbom could not read all of ", file, ", because a block that starts with ",
        p$incomplete, " is not closed, so the packages it names are not listed."
      )
    )
  }
  if (length(p$other) > 0L) {
    issues <- add_issue(
      issues, root_ref, "dependencies", "nix-other-software",
      paste0(file, " also installs ", and_list(p$other), ", which this SBOM does not list."),
      severity = "info"
    )
  }
  if (!is.null(fallback)) {
    issues <- add_issue(
      issues, root_ref, "dependencies",
      if (fallback == "not-built") "nix-not-built" else "nix-failed",
      if (fallback == "not-built") {
        nix_not_built_message(file)
      } else {
        paste0("Nix could not read ", file, ", so sbom read the file instead of the Nix store.")
      }
    )
  }
  issues
}

# A data frame of the rows in `rows` (lists), with the character columns
# `cols` and a list column `inputs`.
nix_package_frame <- function(rows, cols) {
  out <- lapply(cols, function(col) {
    vapply(rows, function(r) as.character(r[[col]]), "")
  })
  names(out) <- cols
  out <- as.data.frame(out, stringsAsFactors = FALSE)
  out$inputs <- lapply(rows, function(r) r$inputs[[1L]])
  out
}

# The records, DESCRIPTION-shaped, of every R package the file installs,
# named by package, and whether each one's dependencies are known: those of a
# git or archive package are, since the file lists them. A CRAN package named
# only by an input of another is a record too. list(records, deps_known,
# cran): `cran` names the packages taken to be from CRAN only because they
# come from rPackages.
nix_records <- function(p) {
  records <- list()
  known <- logical()
  for (i in seq_len(nrow(p$archive))) {
    name <- p$archive$name[[i]]
    records[[name]] <- nix_record(
      c(Package = name, Version = p$archive$version[[i]], Repository = "CRAN"),
      p$archive$inputs[[i]]
    )
    known[[name]] <- TRUE
  }
  for (i in seq_len(nrow(p$git))) {
    name <- p$git$name[[i]]
    fields <- nix_git_fields(name, p$git$url[[i]], p$git$rev[[i]])
    records[[name]] <- nix_record(fields, p$git$inputs[[i]])
    known[[name]] <- TRUE
  }
  cran <- setdiff(
    unique(c(p$packages, unlist(p$git$inputs), unlist(p$archive$inputs))),
    names(records)
  )
  for (name in cran) {
    records[[name]] <- c(Package = name, Repository = "CRAN")
    known[[name]] <- FALSE
  }
  if (length(records) == 0L) {
    return(list(records = list(), deps_known = logical(), cran = character()))
  }
  records <- records[order(names(records), method = "radix")]
  list(records = records, deps_known = known[names(records)], cran = cran)
}

# The DESCRIPTION fields that say where a package rix fetches from git comes
# from: a GitHub repository at a revision, or else any git URL.
nix_git_fields <- function(name, url, rev) {
  forge <- regmatches(url, regexec("^https://github\\.com/([^/]+)/([^/]+?)(\\.git)?/*$", url))[[1L]]
  if (length(forge) > 0L && !is.na(rev)) {
    c(
      Package = name, RemoteType = "github", RemoteUsername = forge[[2L]],
      RemoteRepo = forge[[3L]], RemoteSha = rev
    )
  } else {
    c(Package = name, RemoteType = "git", RemoteUrl = url)
  }
}

# The DESCRIPTION-style record of one package from `fields`, with `inputs` as
# its Imports and the names and values converted to UTF-8.
nix_record <- function(fields, inputs) {
  if (length(inputs) > 0L) {
    fields[["Imports"]] <- paste(inputs, collapse = ", ")
  }
  stats::setNames(enc2utf8_bytes(unname(fields)), enc2utf8_bytes(names(fields)))
}

# Edges from the root to each package the file names, and from each git and
# archive package to the packages it needs.
nix_edges <- function(p, stand_in) {
  top <- unique(c(p$packages, p$git$name, p$archive$name))
  rows <- list(data.frame(
    from = rep("", length(top)), to = top, field = rep("Imports", length(top)),
    spec = top, constraint = rep(NA_character_, length(top)),
    evidence = rep("declared", length(top)), stringsAsFactors = FALSE
  ))
  built <- rbind(
    data.frame(name = p$git$name, stringsAsFactors = FALSE),
    data.frame(name = p$archive$name, stringsAsFactors = FALSE)
  )
  inputs <- c(p$git$inputs, p$archive$inputs)
  for (i in seq_along(inputs)) {
    need <- unique(inputs[[i]])
    rows[[length(rows) + 1L]] <- data.frame(
      from = rep(built$name[[i]], length(need)), to = need,
      field = rep("Imports", length(need)), spec = need,
      constraint = rep(NA_character_, length(need)),
      evidence = rep("declared", length(need)), stringsAsFactors = FALSE
    )
  }
  edges <- do.call(rbind, rows)
  edges$from[edges$from == ""] <- stand_in
  edges[!duplicated(edges[c("from", "to")]), , drop = FALSE]
}

# Where Nix fetches a git or archive package from, and the hash it checks it
# with, as the package's description. `source` is the source_input of the
# package components: "default.nix" for the file, "nix-store" for the store.
nix_describe <- function(comps, p, source = "default.nix") {
  built <- list(
    git = p$git, archive = p$archive
  )
  for (kind in names(built)) {
    d <- built[[kind]]
    for (i in seq_len(nrow(d))) {
      row <- which(comps$name == d$name[[i]] & comps$source_input %in% source & !comps$is_root &
        is.na(comps$parent_ref))
      if (length(row) == 0L) {
        next
      }
      comps$download_location[row[[1L]]] <- if (kind == "git") {
        paste0(
          "git+", sub("/+$", "", d$url[[i]]),
          if (!is.na(d$rev[[i]])) paste0("@", d$rev[[i]])
        )
      } else {
        d$url[[i]]
      }
      comps$description[row[[1L]]] <- paste0(
        "Fetched by Nix from ", d$url[[i]],
        if (kind == "git" && !is.na(d$rev[[i]])) paste0(" at revision ", d$rev[[i]]),
        ".",
        if (!is.na(d$sha256[[i]])) paste0(" Nix checks it with the hash ", d$sha256[[i]], ".")
      )
    }
  }
  comps
}

# One component per Nix system package, and one for TeX Live. They have no
# package URL, since the purl specification has no nix type.
nix_system_components <- function(p, file) {
  names <- sort(unique(p$system), method = "radix")
  rows <- lapply(names, function(name) {
    component_row(
      ref = paste0("nix/", name), name = name, type = "library", ecosystem = "nix",
      scope = "required", evidence = "declared", source_input = "default.nix",
      description = paste0("A Nix package that ", file, " installs.")
    )
  })
  if (length(p$tex) > 0L) {
    rows[[length(rows) + 1L]] <- component_row(
      ref = "nix/texlive", name = "texlive", type = "library", ecosystem = "nix",
      scope = "required", evidence = "declared", source_input = "default.nix",
      description = paste0("TeX Live with ", and_list(p$tex), ".")
    )
  }
  list(components = do.call(rbind, c(list(empty_components()), rows)))
}

# Relationships from `root` to each of `refs` as system requirements, with the
# "nix/" prefix removed for the spec; none when `refs` is empty.
nix_system_relationships <- function(root, refs) {
  if (length(refs) == 0L) {
    return(empty_relationships())
  }
  data.frame(
    from = root, to = refs, field = "system_requirement",
    spec = sub("^nix/", "", refs), evidence = "declared", stringsAsFactors = FALSE
  )
}

# The note on where the packages come from, or nothing.
nix_source_note <- function(nixpkgs) {
  if (identical(nixpkgs$kind, "date")) {
    paste0("The packages come from the rstats-on-nix snapshot of nixpkgs for ", nixpkgs$value, ".")
  } else if (identical(nixpkgs$kind, "commit")) {
    paste0("The packages come from nixpkgs at commit ", nixpkgs$value, ".")
  }
}

# The recommended packages that ship with R. The snapshot's graph stops at
# them, as it does at the base packages.
nix_recommended_packages <- function() {
  c(
    "boot", "class", "cluster", "codetools", "foreign", "KernSmooth", "lattice",
    "MASS", "Matrix", "mgcv", "nlme", "nnet", "rpart", "spatial", "survival"
  )
}

# The message of the issue (or error) for an environment that is not built.
# `file` is how the file is named in the text: the plain name for an issue,
# and a cli expression for an error.
nix_not_built_message <- function(file) {
  paste0(
    "The environment in ", file, " has not been built on this machine, so sbom read the file ",
    "instead of the Nix store; build it with nix-shell or nix-build first."
  )
}

# Whether the text of a Nix file starts with rix's header comment.
nix_is_rix <- function(text) {
  grepl("^\\s*#\\s*This file was generated by the \\{rix\\} R package", sub("^\uFEFF", "", text))
}

# `x` with the packages at `refs` marked as assumed to be CRAN packages: their
# package URL stays pkg:cran, but nothing else that only CRAN would give
# (supplier, homepage, DOI) is recorded, and one issue, `purl-inferred`, says
# that the package URLs are inferred. `sentence` is a function of the names
# and whether there is one that gives its text.
nix_assume_cran <- function(x, refs, sentence) {
  refs <- unname(refs[!is.na(refs)])
  if (length(refs) == 0L) {
    return(x)
  }
  hit <- x$components$ref %in% refs & x$components$ecosystem %in% "cran"
  for (col in c("supplier_name", "supplier_url", "homepage", "doi")) {
    x$components[[col]][hit] <- NA_character_
  }
  names <- sort(unique(x$components$name[hit]), method = "radix")
  if (length(names) == 0L) {
    return(x)
  }
  x$issues <- add_issue(
    x$issues, x$metadata$root, "purl", "purl-inferred", sentence(names, length(names) == 1L)
  )
  x
}

# The sentence of the nix-git-versions-unknown issue: the packages `names`
# that `file` fetches from git. apply_overrides() builds it again after an
# override asserts some of their versions.
nix_git_versions_sentence <- function(file, names) {
  git <- sort(unique(names), method = "radix")
  one <- length(git) == 1L
  paste0(
    "The version", if (one) " of the package that " else "s of the packages that ", file,
    " fetches from git ", if (one) "is" else "are", " not recorded (", and_list(git), "); ",
    if (one) "it is" else "each is", " identified by its revision instead."
  )
}

# The sentence of the nix-not-in-snapshot issue: the packages `names`, in
# radix order, that `file` needs and the CRAN snapshot lacks. With
# `asserted`, an override asserts their versions, which are therefore not
# unknown. apply_overrides() builds it again after an override asserts some
# of those versions (override_nix_snapshot()).
nix_not_in_snapshot_sentence <- function(file, names, asserted = FALSE) {
  one <- length(names) == 1L
  paste0(
    length(names), if (one) " package that " else " packages that ", file,
    if (one) " needs is" else " needs are", " not in the CRAN snapshot sbom read (", and_list(names), ")",
    if (asserted) {
      if (one) "; its version is asserted by an override." else "; their versions are asserted by an override."
    } else {
      paste0(", so ", if (one) "its version is" else "their versions are", " unknown.")
    }
  )
}
