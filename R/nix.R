# Reading a Nix environment file written by the rix package, as text. Without
# Nix the file is never evaluated; with Nix it is handed to nix-instantiate.

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
#' * R, and each R package (every store path named `r-<name>`), labelled
#'   observed, at the version in its store path or, when the path has none,
#'   in its `DESCRIPTION` in the store. A package's licence and maintainer
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
#'   Otherwise R has no version, and an issue says so.
#' * Each R package that the file names, by name only. These come from a
#'   nixpkgs snapshot that the file pins, but the file does not say which
#'   version that snapshot holds, so their versions are unknown and one issue
#'   says so. nixpkgs' `rPackages` holds Bioconductor packages as well as
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
#' not listed, and an issue says so.
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
#' versions and the added packages and dependencies are labelled inferred,
#' since the snapshot is a stand-in for what Nix installed. R, base and
#' recommended packages are left to R's own handling. Archive packages keep
#' the version in their URL, and git packages stay without a version. A
#' package that the snapshot lists is a CRAN package. One that it lacks,
#' named by the file or by a snapshot package's dependencies, may not be one,
#' so it is listed without a version or package URL, with an issue. If the
#' snapshot cannot be read, an issue says so. A snapshot given as a URL is
#' named in the notes by that URL, without its credentials, query string or
#' fragment, and a local file by its name.
#'
#' `library`, `embedded` and `system` apply as for [sbom_renv()], to the
#' packages whose version the file declares and that are installed in
#' `library` at that version. The installed copy fills in what the file
#' lacks: the licence and maintainer. Without `library`, nothing is read from
#' an installed copy. One issue lists the packages left without a licence or
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

  recs <- nix_records(p)
  snap <- nix_snapshot_source(snapshot, p$nixpkgs)
  looked <- NULL
  snap_reason <- NA_character_
  if (!is.na(snap$location)) {
    data <- read_packages_file(snap$location)
    if (is.data.frame(data)) {
      looked <- nix_snapshot(recs$records, recs$deps_known, data)
      recs$records <- looked$records
      recs$deps_known <- looked$deps_known
      # nixpkgs' rPackages holds Bioconductor packages too, so a name that
      # the CRAN snapshot lacks is not known to be a CRAN package.
      for (name in looked$missing) {
        recs$records[[name]] <- c(Package = name, Source = "unknown")
      }
    } else {
      snap_reason <- attr(data, "reason")
      if (!is.character(snap_reason) || length(snap_reason) != 1L || is.na(snap_reason)) {
        snap_reason <- "the snapshot could not be read"
      }
    }
  }
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

  # The licences and maintainers that neither the file nor an installed copy
  # gives are one issue.
  pkgs <- comps[!comps$is_root & comps$source_input %in% "default.nix" & is.na(comps$parent_ref) &
    !comps$ecosystem %in% "nix", , drop = FALSE]
  unknown <- sort(unique(pkgs$name[is.na(pkgs$license_as_written) | is.na(pkgs$maintainer)]), method = "radix")
  if (length(unknown) > 0L) {
    one <- length(unknown) == 1L
    x$issues <- add_issue(
      x$issues, root_ref, "license", "nix-licenses-unknown",
      paste0(
        length(unknown), if (one) " package that " else " packages that ", file,
        if (one) " names has" else " names have", " no licence or maintainer on record (",
        capped_list(unknown), "), because sbom read the file ",
        if (is.null(fallback)) "without Nix" else "instead of the Nix store",
        " and found no installed copy of ", if (one) "it" else "them", " at the same version."
      )
    )
  }

  if (is.na(p$r_version)) {
    x$issues <- add_issue(
      x$issues, "R", "version", "r-version-unknown",
      paste0("The R version is not recorded in ", file, ", so R is listed without a version.")
    )
  }
  if (isTRUE(snap$undated)) {
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-snapshot-not-dated",
      paste0(
        "nixpkgs is pinned to a commit, not a date, so sbom could not look up its CRAN snapshot; ",
        "pass the path or URL of a PACKAGES file instead."
      )
    )
  }
  if (!is.na(snap_reason)) {
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-snapshot-failed",
      paste0("sbom could not read the CRAN snapshot (", snap_reason, "), so the package versions are unknown.")
    )
  }
  if (!is.null(looked) && length(looked$missing) > 0L) {
    one <- length(looked$missing) == 1L
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-not-in-snapshot",
      paste0(
        length(looked$missing), if (one) " package that " else " packages that ", file,
        if (one) " needs is" else " needs are", " not in the CRAN snapshot sbom read (",
        and_list(looked$missing), "), so ", if (one) "its version is" else "their versions are", " unknown."
      )
    )
  }
  if (!is.null(looked) && nrow(p$git) > 0L) {
    git <- sort(unique(p$git$name), method = "radix")
    one <- length(git) == 1L
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-git-versions-unknown",
      paste0(
        "The version", if (one) " of the package that " else "s of the packages that ", file,
        " fetches from git ", if (one) "is" else "are", " not recorded (", and_list(git), "); ",
        if (one) "it is" else "each is", " identified by its revision instead."
      )
    )
  }
  if (is.na(snap$location) || isTRUE(snap$undated)) {
  if (any(comps$is_root %in% FALSE & comps$source_input %in% "default.nix" &
    comps$ecosystem %in% c("cran", "github", "git") & is.na(comps$version))) {
    source <- if (is.na(p$nixpkgs$value)) {
      "."
    } else {
      paste0(" for nixpkgs ", p$nixpkgs$value, ".")
    }
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-versions-unknown",
      paste0(
        "The versions of the packages in ", file, " are not recorded, because sbom read it ",
        if (is.null(fallback)) "without Nix" else "instead of the Nix store",
        "; pass snapshot to look them up", source
      )
    )
  }
  }
  if (!is.na(p$incomplete)) {
    x$issues <- add_issue(
      x$issues, root_ref, "dependencies", "nix-parse-incomplete",
      paste0(
        "sbom could not read all of ", file, ", because a block that starts with ",
        p$incomplete, " is not closed, so the packages it names are not listed."
      )
    )
  }
  if (length(p$other) > 0L) {
    x$issues <- add_issue(
      x$issues, root_ref, "dependencies", "nix-other-software",
      paste0(file, " also installs ", and_list(p$other), ", which this SBOM does not list."),
      severity = "info"
    )
  }
  if (!is.null(fallback)) {
    x$issues <- add_issue(
      x$issues, root_ref, "dependencies",
      if (fallback == "not-built") "nix-not-built" else "nix-failed",
      if (fallback == "not-built") {
        nix_not_built_message(file)
      } else {
        paste0("Nix could not read ", file, ", so sbom read the file instead of the Nix store.")
      }
    )
  }
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

# The text of a Nix file, from its bytes. Nix files for rix are a few
# kilobytes, so a large one is not one.
read_nix_file <- function(path, call = parent.frame()) {
  if (isTRUE(file.size(path) > 1024^2)) {
    cli::cli_abort(
      "The Nix file {.file {path}} is too large to be one that rix wrote.", call = call
    )
  }
  raw <- readBin(path, "raw", n = file.size(path))
  enc2utf8_bytes(rawToChar(raw[raw != as.raw(0L)]))
}

# What rix declared in a Nix file's text, with no Nix and no evaluation:
# list(nixpkgs, r_version, packages, git, archive, system, tex, other). See
# sbom_nix() for what each holds. `path` names the file in the error for a
# file that rix did not write.
parse_rix <- function(text, path = "The Nix file", call = parent.frame()) {
  text <- gsub("\r\n?", "\n", enc2utf8_bytes(paste(text, collapse = "\n")))
  if (startsWith(text, "\uFEFF")) {
    text <- substring(text, 2L)
  }
  if (!grepl("^\\s*#\\s*This file was generated by the \\{rix\\} R package", text)) {
    cli::cli_abort(
      paste0(
        "{.file {path}} was not generated by rix, and sbom can read other Nix ",
        "files only with Nix installed."
      ),
      class = "sbom_nix_unreadable",
      call = call
    )
  }
  lines <- strsplit(text, "\n", fixed = TRUE)[[1L]]
  comments <- lines[startsWith(trimws(lines), "#")]
  m <- regmatches(comments, regexec('r_ver\\s*=\\s*"([0-9]+(\\.[0-9]+)+)"', comments))
  m <- m[lengths(m) > 0L]
  r_version <- if (length(m) > 0L) m[[1L]][[2L]] else NA_character_

  scanned <- nix_scan(text)
  clean <- scanned$clean
  mask <- scanned$mask

  built <- nix_built_packages(clean, mask)
  rpkgs <- nix_block(mask, "\\brpkgs\\s*=\\s*builtins\\.attrValues\\s*\\{")
  system_pkgs <- nix_block(mask, "\\bsystem_packages\\s*=\\s*builtins\\.attrValues\\s*\\{")
  tex <- nix_block(mask, "\\btex\\s*=\\s*\\(", open = "(", close = ")")

  other <- c(
    character(),
    if (grepl("\\bpyconf\\s*=", mask)) "Python packages",
    if (grepl("\\bjlconf\\s*=", mask)) "Julia packages",
    if (grepl("\\blocal_r_pkgs\\s*=", mask)) "local R packages",
    if (built$other) "R packages from other sources"
  )
  tex_names <- if (!is.null(tex)) {
    inherited <- nix_inherited(clean, mask, tex, "pkgs\\.texlive")
    if (length(inherited) > 0L) inherited else nix_list_names(clean, mask, tex)
  }
  list(
    nixpkgs = nix_nixpkgs(clean, mask),
    r_version = r_version,
    packages = sort(unique(gsub("_", ".", nix_inherited(clean, mask, rpkgs, "pkgs\\.rPackages"), fixed = TRUE)), method = "radix"),
    git = built$git, archive = built$archive,
    system = setdiff(nix_inherited(clean, mask, system_pkgs, "pkgs"), "R"),
    tex = if (is.null(tex_names)) character() else tex_names,
    other = other,
    incomplete = nix_unclosed(mask)
  )
}

# The label of the first recognised block that starts but is not closed, or
# NA when every one is closed. The labels are fixed words, never file text.
nix_unclosed <- function(mask) {
  starts <- c(
    rpkgs = "\\brpkgs\\s*=\\s*builtins\\.attrValues\\s*\\{",
    system_packages = "\\bsystem_packages\\s*=\\s*builtins\\.attrValues\\s*\\{",
    buildRPackage = "\\(\\s*pkgs\\.rPackages\\.buildRPackage\\s*\\{",
    pkgs.fetchgit = "\\bpkgs\\.fetchgit\\s*\\{",
    pkgs.fetchzip = "\\bpkgs\\.fetchzip\\s*\\{",
    builtins.fetchGit = "\\bbuiltins\\.fetchGit\\s*\\{",
    tex = "\\btex\\s*=\\s*\\("
  )
  at <- integer()
  for (label in names(starts)) {
    hits <- gregexpr(starts[[label]], mask, perl = TRUE)[[1L]]
    if (hits[[1L]] < 0L) {
      next
    }
    open <- label == "tex"
    for (k in seq_along(hits)) {
      bracket <- hits[[k]] + attr(hits, "match.length")[[k]] - 1L
      closed <- if (open) {
        nix_close(mask, bracket, "(", ")")
      } else {
        nix_close(mask, bracket, "{", "}")
      }
      if (is.na(closed)) {
        at[[label]] <- if (label %in% names(at)) min(at[[label]], hits[[k]]) else hits[[k]]
      }
    }
  }
  if (length(at) == 0L) NA_character_ else names(at)[[which.min(at)]]
}

# The text with its comments blanked (`clean`) and, as well, the inside of
# each string blanked (`mask`), both the same length as the text. `mask` can
# be searched for structure, and `clean` read for values at the same
# positions. Strings are "..." and ''...''; # starts a comment and /* */
# is one too.
nix_scan <- function(text) {
  chars <- strsplit(text, "", fixed = TRUE)[[1L]]
  n <- length(chars)
  clean <- chars
  mask <- chars
  state <- "code"
  i <- 1L
  while (i <= n) {
    ch <- chars[[i]]
    nxt <- if (i < n) chars[[i + 1L]] else ""
    if (state == "code") {
      if (ch == "#") {
        state <- "line"
        clean[[i]] <- " "; mask[[i]] <- " "
      } else if (ch == "/" && nxt == "*") {
        state <- "block"
        clean[i:(i + 1L)] <- " "; mask[i:(i + 1L)] <- " "
        i <- i + 1L
      } else if (ch == "\"") {
        state <- "dq"
      } else if (ch == "'" && nxt == "'") {
        state <- "sq"
        i <- i + 1L
      }
    } else if (state == "line") {
      if (ch == "\n") {
        state <- "code"
      } else {
        clean[[i]] <- " "; mask[[i]] <- " "
      }
    } else if (state == "block") {
      if (ch == "*" && nxt == "/") {
        clean[i:(i + 1L)] <- " "; mask[i:(i + 1L)] <- " "
        i <- i + 1L
        state <- "code"
      } else if (ch != "\n") {
        clean[[i]] <- " "; mask[[i]] <- " "
      }
    } else if (state == "dq") {
      if (ch == "\\" && i < n) {
        mask[i:(i + 1L)] <- "x"
        i <- i + 1L
      } else if (ch == "\"") {
        state <- "code"
      } else {
        mask[[i]] <- "x"
      }
    } else {
      # An indented string ends at '' unless it escapes: ''', ''$ and ''\.
      if (ch == "'" && nxt == "'") {
        after <- if (i + 1L < n) chars[[i + 2L]] else ""
        if (after %in% c("'", "$", "\\")) {
          mask[i:(i + 2L)] <- "x"
          i <- i + 2L
        } else {
          state <- "code"
          i <- i + 1L
        }
      } else if (ch != "\n") {
        mask[[i]] <- "x"
      }
    }
    i <- i + 1L
  }
  list(clean = paste(clean, collapse = ""), mask = paste(mask, collapse = ""))
}

# The start and end of the bracketed block whose opening follows the first
# match of `pattern` in `mask` (the pattern ends at the opening bracket), as
# c(start, end) positions of the text between the brackets; NULL when there
# is none or it is not closed.
nix_block <- function(mask, pattern, open = "{", close = "}", from = 1L) {
  hit <- regexpr(pattern, substring(mask, from), perl = TRUE)
  if (hit < 0L) {
    return(NULL)
  }
  start <- from + as.integer(hit) + attr(hit, "match.length") - 2L
  close_at <- nix_close(mask, start, open, close)
  if (is.na(close_at)) {
    return(NULL)
  }
  c(start + 1L, close_at - 1L)
}

# The position of the bracket that closes the one at `start`, or NA.
nix_close <- function(mask, start, open, close) {
  chars <- strsplit(substring(mask, start), "", fixed = TRUE)[[1L]]
  depth <- cumsum((chars == open) - (chars == close))
  end <- which(depth == 0L)[1L]
  if (is.na(end)) NA_integer_ else start + end - 1L
}

# The names of `inherit (<from>) a b c;`, from the clean text, inside the
# `block` of positions, in order and without duplicates.
nix_inherited <- function(clean, mask, block, from) {
  if (is.null(block)) {
    return(character())
  }
  inner <- substr(mask, block[[1L]], block[[2L]])
  pattern <- paste0("\\binherit\\s*\\(\\s*", from, "\\s*\\)([^;]*);")
  hits <- gregexpr(pattern, inner, perl = TRUE)[[1L]]
  if (hits[[1L]] < 0L) {
    return(character())
  }
  starts <- as.integer(hits) + block[[1L]] - 1L
  names <- unlist(lapply(seq_along(starts), function(k) {
    seg <- substr(clean, starts[[k]], starts[[k]] + attr(hits, "match.length")[[k]] - 1L)
    seg <- sub(pattern, "\\1", seg, perl = TRUE)
    strsplit(trimws(seg), "\\s+")[[1L]]
  }))
  unique(names[nzchar(names)])
}

# The names in the first `[ ... ]` of the block, as in `with ps; [ a b ]`.
nix_list_names <- function(clean, mask, block) {
  inner <- substr(mask, block[[1L]], block[[2L]])
  at <- regexpr("\\[[^]]*\\]", inner)
  if (at < 0L) {
    return(character())
  }
  seg <- substr(clean, block[[1L]] + at - 1L, block[[1L]] + at - 1L + attr(at, "match.length") - 1L)
  names <- strsplit(trimws(gsub("[][]", " ", seg)), "\\s+")[[1L]]
  unique(names[nzchar(names)])
}

# The value of the string attribute `attr` (`attr = "value";`) in `block`, or NA.
nix_string_attr <- function(clean, mask, block, attr) {
  inner <- substr(mask, block[[1L]], block[[2L]])
  at <- regexpr(paste0("(?<![A-Za-z0-9_.-])", attr, "\\s*=\\s*\""), inner, perl = TRUE)
  if (at < 0L) {
    return(NA_character_)
  }
  open <- block[[1L]] + at - 1L + attr(at, "match.length") - 1L
  close <- regexpr("\"", substring(mask, open + 1L), fixed = TRUE)
  if (close < 0L) {
    return(NA_character_)
  }
  substr(clean, open + 1L, open + close - 1L)
}

# The nixpkgs the file imports: list(kind, value, url). kind is "date" for an
# rstats-on-nix snapshot, "commit" for a nixpkgs commit, and NA for any other
# URL. NULL values become NA.
nix_nixpkgs <- function(clean, mask) {
  none <- list(kind = NA_character_, value = NA_character_, url = NA_character_)
  hit <- regexpr("\\bfetchTarball\\s*", mask, perl = TRUE)
  if (hit < 0L) {
    return(none)
  }
  at <- as.integer(hit) + attr(hit, "match.length")
  url <- if (substr(mask, at, at) == "\"") {
    close <- regexpr("\"", substring(mask, at + 1L), fixed = TRUE)
    if (close > 0L) substr(clean, at + 1L, at + close - 1L) else NA_character_
  } else if (substr(mask, at, at) == "{") {
    end <- nix_close(mask, at, "{", "}")
    if (!is.na(end)) nix_string_attr(clean, mask, c(at + 1L, end - 1L), "url") else NA_character_
  } else {
    NA_character_
  }
  if (is.na(url)) {
    return(none)
  }
  date <- regmatches(url, regexec("/rstats-on-nix/nixpkgs/archive/([0-9]{4}-[0-9]{2}-[0-9]{2})\\.tar\\.gz$", url))[[1L]]
  commit <- regmatches(url, regexec("/nixpkgs/archive/([0-9a-f]{40})\\.tar\\.gz$", url))[[1L]]
  if (length(date) > 0L) {
    list(kind = "date", value = date[[2L]], url = url)
  } else if (length(commit) > 0L) {
    list(kind = "commit", value = commit[[2L]], url = url)
  } else {
    list(kind = NA_character_, value = NA_character_, url = url)
  }
}

# The `x = (pkgs.rPackages.buildRPackage { ... })` packages: git packages
# (fetchgit and builtins.fetchGit) and CRAN archive packages (fetchzip), as
# list(git, archive, other); `other` is TRUE when one has another source.
nix_built_packages <- function(clean, mask) {
  git <- list()
  archive <- list()
  other <- FALSE
  pattern <- "\\(\\s*pkgs\\.rPackages\\.buildRPackage\\s*\\{"
  from <- 1L
  repeat {
    block <- nix_block(mask, pattern, from = from)
    if (is.null(block)) {
      break
    }
    from <- block[[2L]] + 1L
    name <- nix_string_attr(clean, mask, block, "name")
    inner <- substr(mask, block[[1L]], block[[2L]])
    src <- regmatches(inner, regexpr("\\b(pkgs\\.fetchgit|pkgs\\.fetchzip|builtins\\.fetchGit)\\b", inner))
    inputs <- c(
      nix_inherited(clean, mask, block, "pkgs\\.rPackages"),
      nix_remote_names(clean, mask, block)
    )
    inputs <- gsub("_", ".", inputs, fixed = TRUE)
    # Credentials and tokens in a URL never reach the SBOM.
    url <- strip_url(nix_string_attr(clean, mask, block, "url"))
    if (is.na(name) || length(src) == 0L) {
      other <- TRUE
    } else if (src == "pkgs.fetchzip") {
      file <- regmatches(url, regexec("/([A-Za-z][A-Za-z0-9.]*)_([0-9][^/_]*)\\.tar\\.gz$", url))[[1L]]
      archive[[length(archive) + 1L]] <- list(
        name = name, url = url, rev = NA_character_,
        sha256 = nix_string_attr(clean, mask, block, "sha256"),
        inputs = list(inputs),
        version = if (length(file) > 0L) file[[3L]] else NA_character_
      )
    } else {
      git[[length(git) + 1L]] <- list(
        name = name, url = url, rev = nix_string_attr(clean, mask, block, "rev"),
        sha256 = nix_string_attr(clean, mask, block, "sha256"), inputs = list(inputs)
      )
    }
  }
  list(
    git = nix_package_frame(git, c("name", "url", "rev", "sha256")),
    archive = nix_package_frame(archive, c("name", "url", "rev", "sha256", "version")),
    other = other
  )
}

# The packages after `++ [ a b ]` in a block: the other packages it builds.
nix_remote_names <- function(clean, mask, block) {
  inner <- substr(mask, block[[1L]], block[[2L]])
  at <- regexpr("\\+\\+\\s*\\[[^]]*\\]", inner)
  if (at < 0L) {
    return(character())
  }
  seg <- substr(clean, block[[1L]] + at - 1L, block[[1L]] + at - 1L + attr(at, "match.length") - 1L)
  names <- strsplit(trimws(gsub("[][+]", " ", seg)), "\\s+")[[1L]]
  names[nzchar(names)]
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

# Where the snapshot comes from: list(location, label, undated). `location` is
# NA when there is nothing to read; `undated` is TRUE for "ppm" with a
# nixpkgs that is not pinned to a date.
nix_snapshot_source <- function(snapshot, nixpkgs) {
  none <- list(location = NA_character_, shown = NA_character_, label = NA_character_, undated = FALSE)
  if (is.null(snapshot)) {
    return(none)
  }
  if (identical(snapshot, "ppm")) {
    if (!identical(nixpkgs$kind, "date")) {
      none$undated <- TRUE
      return(none)
    }
    return(list(
      location = paste0("https://packagemanager.posit.co/cran/", nixpkgs$value, "/src/contrib/PACKAGES"),
      shown = paste0("https://packagemanager.posit.co/cran/", nixpkgs$value, "/src/contrib/PACKAGES"),
      label = paste0("the Posit Package Manager CRAN snapshot of ", nixpkgs$value),
      undated = FALSE
    ))
  }
  # A URL is named by itself, without its credentials, query string and
  # fragment; a local path, a machine path, by its file name.
  url <- is_url(snapshot)
  shown <- if (url) strip_url(snapshot) else snapshot
  list(
    location = snapshot, shown = shown,
    label = enc2utf8_bytes(if (url) shown else basename(shown)), undated = FALSE
  )
}

is_url <- function(x) {
  !is.na(x) & grepl("^[A-Za-z][A-Za-z0-9+.-]*://", x)
}

# A URL without its credentials (user and password), query string and
# fragment, which can hold tokens. Anything that is not a URL is unchanged.
strip_url <- function(x) {
  url <- is_url(x)
  x[url] <- sub("[?#].*$", "", sub("^([A-Za-z][A-Za-z0-9+.-]*://)[^/]*@", "\\1", x[url]))
  x
}

# Fills the CRAN packages that have no version from `snap` (a data frame from
# read_packages_file()) and follows Depends, Imports and LinkingTo from them.
# Returns list(records, deps_known, edges, inferred, missing): the records
# with the new ones, the edges the snapshot adds (evidence inferred), the
# names whose version came from it, and the names it lacks.
nix_snapshot <- function(records, deps_known, snap) {
  snap <- snap[!is.na(snap$Package) & !is.na(snap$Version), , drop = FALSE]
  if (anyDuplicated(snap$Package) > 0L) {
    ord <- order(snap$Package, numeric_version(snap$Version, strict = FALSE), decreasing = c(FALSE, TRUE), method = "radix")
    snap <- snap[ord, , drop = FALSE]
    snap <- snap[!duplicated(snap$Package), , drop = FALSE]
  }
  row_of <- function(name) match(name, snap$Package)
  skip <- c("R", base_packages(), nix_recommended_packages())
  fixed <- names(records)[vapply(records, function(r) any(c("RemoteType", "RemoteUrl") %in% names(r)) ||
    "Version" %in% names(r), NA)]
  open <- names(records)[vapply(records, function(r) {
    !any(c("Version", "RemoteType", "RemoteUrl") %in% names(r))
  }, NA)]
  queue <- open
  seen <- character()
  inferred <- character()
  missing <- character()
  edges <- list()
  while (length(queue) > 0L) {
    name <- queue[[1L]]
    queue <- queue[-1L]
    if (name %in% seen) {
      next
    }
    seen <- c(seen, name)
    if (name %in% fixed) {
      # A git or archive package has the dependencies its Nix file lists.
      next
    }
    i <- row_of(name)
    if (is.na(i)) {
      if (name %in% open) {
        missing <- c(missing, name)
      }
      next
    }
    deps <- do.call(rbind, lapply(c("Depends", "Imports", "LinkingTo"), function(field) {
      parse_dep_field(snap[[field]][[i]], field)
    }))
    deps <- deps[!deps$name %in% skip, , drop = FALSE]
    for (dep in setdiff(deps$name[is.na(row_of(deps$name))], names(records))) {
      records[[dep]] <- c(Package = dep, Repository = "CRAN")
      deps_known[[dep]] <- FALSE
      inferred <- c(inferred, dep)
      missing <- c(missing, dep)
    }
    fields <- c(Package = name, Repository = "CRAN", Version = snap$Version[[i]])
    for (field in c("Depends", "Imports", "LinkingTo")) {
      if (!is.na(snap[[field]][[i]]) && nzchar(trimws(snap[[field]][[i]]))) {
        fields[[field]] <- snap[[field]][[i]]
      }
    }
    if (name %in% open || !name %in% names(records)) {
      records[[name]] <- stats::setNames(enc2utf8_bytes(unname(fields)), enc2utf8_bytes(names(fields)))
      deps_known[[name]] <- TRUE
      inferred <- c(inferred, name)
    }
    if (nrow(deps) > 0L) {
      edges[[length(edges) + 1L]] <- data.frame(
        from = name, to = deps$name, field = deps$field, spec = deps$spec,
        constraint = deps$constraint, evidence = "inferred", stringsAsFactors = FALSE
      )
      queue <- c(queue, deps$name)
    }
  }
  edges <- if (length(edges) > 0L) {
    do.call(rbind, edges)
  } else {
    data.frame(
      from = character(), to = character(), field = character(), spec = character(),
      constraint = character(), evidence = character(), stringsAsFactors = FALSE
    )
  }
  records <- records[order(names(records), method = "radix")]
  list(
    records = records, deps_known = deps_known[names(records)], edges = edges,
    inferred = inferred, missing = sort(missing, method = "radix")
  )
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

# Splits a store path, /nix/store/<hash>-<name>-<version>[-<output>], into
# list(hash, name, version, output). The name ends at the first dash that is
# followed by something other than a letter (builtins.parseDrvName's rule),
# and a trailing output name is taken off the version; the default output is
# "out". Every element is NA for a path that is not in the store.
parse_store_path <- function(path) {
  m <- regmatches(path, regexec("^/nix/store/([0-9a-df-np-sv-z]{32})-(.+)$", path))[[1L]]
  if (length(m) == 0L) {
    return(list(hash = NA_character_, name = NA_character_, version = NA_character_, output = NA_character_))
  }
  rest <- sub("\\.drv$", "", m[[3L]])
  at <- regexpr("-(?=[^A-Za-z])", rest, perl = TRUE)
  name <- if (at > 0L) substr(rest, 1L, at - 1L) else rest
  version <- if (at > 0L) substr(rest, at + 1L, nchar(rest)) else ""
  outputs <- c("lib", "dev", "bin", "man", "devdoc", "doc", "info", "out", "debug", "static")
  output <- "out"
  tail <- regmatches(version, regexec("^(.+)-([a-z]+)$", version))[[1L]]
  if (length(tail) > 0L && tail[[3L]] %in% outputs) {
    version <- tail[[2L]]
    output <- tail[[3L]]
  }
  list(hash = m[[2L]], name = name, version = version, output = output)
}

# The runtime closure of the environment that the Nix file describes, from
# Nix: list(status, ...). `status` is "ok", "not-built" (an output of a direct
# input is not in the store) or "failed" (Nix gave no answer); only "ok" has
# more:
# * records: the DESCRIPTION-shaped record of each R package, by name. Every
#   store path named r-<name> is one, at the version in its path or else in
#   its DESCRIPTION. A package that `rix` (parse_rix() of the file, or NULL)
#   fetches from git or the CRAN archive takes its source from there;
# * no_description: the packages whose DESCRIPTION could not be read;
# * assumed_cran: the packages taken to be from CRAN because nothing says
#   where they come from;
# * versionless: the store names of the paths that carry no version;
# * r_version: the version of R, or NULL;
# * edges: Imports between R packages and from the root ("") to the
#   packages the shell names;
# * components: the `nix/` components;
# * relationships: every other edge. `from` and `to` are refs, "" for the
#   root, "R", or "pkg:<name>" for an R package, whose ref is known only
#   once it is built;
# * dropped: the number of edges whose ends are not in the closure.
nix_closure <- function(file, rix = NULL) {
  failed <- list(status = "failed")
  drv <- sys_nix_instantiate(file)
  if (length(drv) != 1L || is.na(drv) || !nzchar(drv)) {
    return(failed)
  }
  refs <- sys_nix_query(c("--references", drv))
  if (is.null(refs)) {
    return(failed)
  }
  inputs <- sort(unique(refs[grepl("\\.drv$", refs)]), method = "radix")
  direct <- if (length(inputs) > 0L) sys_nix_query(c("--outputs", inputs))
  direct <- unique(direct[nzchar(direct)])
  if (length(direct) == 0L) {
    return(failed)
  }
  # A derivation is built when one of its outputs is in the store: --outputs
  # lists all of them, and Nix does not fetch the ones nobody uses (man,
  # devdoc). Outputs belong to the derivation of the same name and version.
  have <- nix_store_exists(direct)
  key <- function(paths) {
    p <- lapply(paths, parse_store_path)
    paste(vapply(p, function(x) x$name, ""), vapply(p, function(x) x$version, ""))
  }
  out_key <- key(direct)
  for (k in unique(key(inputs))) {
    if (k %in% out_key && !any(have[out_key == k])) {
      return(list(status = "not-built"))
    }
  }
  direct <- direct[have]
  if (length(direct) == 0L) {
    return(list(status = "not-built"))
  }
  req <- sys_nix_query(c("--requisites", direct))
  graph <- sys_nix_query(c("--graph", direct))
  if (is.null(req) || is.null(graph)) {
    return(failed)
  }
  paths <- sort(unique(c(req[nzchar(req)], direct)), method = "radix")
  parsed <- lapply(paths, parse_store_path)
  tab <- data.frame(
    path = paths, base = basename(paths),
    name = vapply(parsed, function(p) p$name, ""),
    version = vapply(parsed, function(p) p$version, ""),
    output = vapply(parsed, function(p) p$output, ""),
    stringsAsFactors = FALSE
  )
  tab <- tab[!is.na(tab$name), , drop = FALSE]
  # nixpkgs names every R package r-<name>, and a package built from git or an
  # archive by rix has no version in its name.
  tab$kind <- ifelse(tab$name == "R", "r",
    ifelse(startsWith(tab$name, "r-") & nchar(tab$name) > 2L, "pkg", "nix"))
  tab$pkg <- ifelse(tab$kind == "pkg", sub("^r-", "", tab$name), NA_character_)
  # Outputs of one name and version are one component.
  tab$id <- ifelse(tab$kind == "pkg", paste0("pkg:", tab$pkg),
    ifelse(tab$kind == "r", "R", paste0("nix:", tab$name, "@", tab$version)))
  nix_names <- unique(tab[tab$kind == "nix", c("name", "version")])
  dup <- nix_names$name[duplicated(nix_names$name)]
  tab$ref <- ifelse(tab$kind == "nix",
    ifelse(tab$name %in% dup, paste0("nix/", tab$name, "@", tab$version), paste0("nix/", tab$name)),
    NA_character_)

  git <- if (is.null(rix)) data.frame(name = character()) else rix$git
  archive <- if (is.null(rix)) data.frame(name = character()) else rix$archive
  records <- list()
  no_description <- character()
  assumed <- character()
  versionless <- character()
  for (pkg in sort(unique(tab$pkg[tab$kind == "pkg"]), method = "radix")) {
    rows <- tab[tab$kind %in% "pkg" & tab$pkg %in% pkg, , drop = FALSE]
    version <- rows$version[[1L]]
    desc <- NULL
    for (out in rows$path[order(rows$output != "out")]) {
      desc <- nix_store_description(out, pkg)
      if (!is.null(desc)) break
    }
    if (is.null(desc)) {
      no_description <- c(no_description, pkg)
      desc <- c(Package = pkg)
    }
    if (!nzchar(version)) {
      version <- desc_field(desc, "Version")
    }
    desc <- desc[!names(desc) %in% c("Package", "Version")]
    desc <- c(Package = pkg, if (!is.na(version)) c(Version = version), desc)
    if (is.na(version)) {
      versionless <- c(versionless, rows$name[[1L]])
    }
    if (pkg %in% git$name) {
      # Where rix fetches it from, and never a repository its DESCRIPTION names.
      i <- match(pkg, git$name)
      source_fields <- c("Repository", "Source", "git_url", "git_branch", grep("^Remote", names(desc), value = TRUE))
      desc <- desc[!names(desc) %in% source_fields]
      desc <- c(desc, nix_git_fields(pkg, git$url[[i]], git$rev[[i]])[-1L])
    } else if (pkg %in% archive$name) {
      desc[["Repository"]] <- "CRAN"
    } else if (is.na(desc_field(desc, "Repository")) &&
      package_ecosystem(desc)$ecosystem %in% c("local", "unknown")) {
      desc[["Repository"]] <- "CRAN"
      assumed <- c(assumed, pkg)
    }
    records[[pkg]] <- desc
  }

  comps <- lapply(split(tab[tab$kind == "nix", , drop = FALSE], tab$ref[tab$kind == "nix"]), function(rows) {
    rows <- rows[order(rows$output != "out", rows$path, method = "radix"), , drop = FALSE]
    component_row(
      ref = rows$ref[[1L]], name = rows$name[[1L]], version = if (nzchar(rows$version[[1L]])) rows$version[[1L]],
      version_is = if (nzchar(rows$version[[1L]])) "exact",
      type = "library", ecosystem = "nix", scope = "required", evidence = "observed",
      source_input = "nix-store",
      description = paste0("Nix store path ", rows$path[[1L]], ".")
    )
  })
  nix_comps <- do.call(rbind, c(list(empty_components()), unname(comps)))
  versionless <- c(versionless, nix_comps$name[is.na(nix_comps$version)])
  is_lib <- vapply(split(tab[tab$kind == "nix", , drop = FALSE], tab$ref[tab$kind == "nix"]), function(rows) {
    any(rows$output == "lib") || startsWith(rows$name[[1L]], "lib")
  }, NA)

  node <- function(base) {
    i <- match(base, tab$base)
    if (is.na(i)) NULL else tab[i, , drop = FALSE]
  }
  id_of <- function(row) switch(row$kind, pkg = paste0("pkg:", row$pkg), r = "R", row$ref)
  edge_rows <- list()
  rel_rows <- list()
  rel <- function(from, to, field, spec) {
    data.frame(from = from, to = to, field = field, spec = spec, evidence = "observed", stringsAsFactors = FALSE)
  }
  dropped <- 0L
  # An edge "a" -> "b" in the DOT graph says that b references a. Each one is
  # a relationship: Imports to an R package, Depends to R, and dynamic_link or
  # system_requirement to a Nix package.
  m <- regmatches(graph, regexec('^\\s*"([^"]+)"\\s*->\\s*"([^"]+)"', graph))
  for (e in m[lengths(m) == 3L]) {
    dep <- node(e[[2L]])
    user <- node(e[[3L]])
    if (is.null(dep) || is.null(user)) {
      dropped <- dropped + 1L
      next
    }
    if (identical(dep$id, user$id)) next
    if (dep$kind == "pkg" && user$kind == "pkg") {
      edge_rows[[length(edge_rows) + 1L]] <- data.frame(
        from = user$pkg, to = dep$pkg, field = "Imports", spec = dep$pkg,
        constraint = NA_character_, evidence = "observed", stringsAsFactors = FALSE
      )
    } else if (dep$kind == "nix") {
      field <- if (isTRUE(is_lib[[dep$ref]])) "dynamic_link" else "system_requirement"
      rel_rows[[length(rel_rows) + 1L]] <- rel(id_of(user), dep$ref, field, dep$name)
    } else if (dep$kind == "pkg") {
      rel_rows[[length(rel_rows) + 1L]] <- rel(id_of(user), id_of(dep), "Imports", dep$pkg)
    } else {
      rel_rows[[length(rel_rows) + 1L]] <- rel(id_of(user), "R", "Depends", "R")
    }
  }
  for (path in direct) {
    d <- node(basename(path))
    if (is.null(d)) next
    if (d$kind == "pkg") {
      edge_rows[[length(edge_rows) + 1L]] <- data.frame(
        from = "", to = d$pkg, field = "Imports", spec = d$pkg,
        constraint = NA_character_, evidence = "observed", stringsAsFactors = FALSE
      )
    } else if (d$kind == "nix") {
      rel_rows[[length(rel_rows) + 1L]] <- rel("", d$ref, "system_requirement", d$name)
    }
  }
  bind <- function(rows, empty) {
    out <- if (length(rows) > 0L) do.call(rbind, rows) else empty
    out[!duplicated(out[setdiff(names(out), c("spec", "evidence", "constraint"))]), , drop = FALSE]
  }
  r_rows <- tab[tab$kind == "r", , drop = FALSE]
  list(
    status = "ok", records = records, no_description = no_description,
    assumed_cran = assumed,
    versionless = sort(unique(versionless), method = "radix"),
    r_version = if (nrow(r_rows) > 0L && nzchar(r_rows$version[[1L]])) r_rows$version[[1L]],
    edges = bind(edge_rows, data.frame(
      from = character(), to = character(), field = character(), spec = character(),
      constraint = character(), evidence = character(), stringsAsFactors = FALSE
    )),
    components = nix_comps,
    relationships = bind(rel_rows, empty_relationships()),
    dropped = dropped
  )
}

# The SBOM of an environment that nix_closure() read from the Nix store.
# `rix` is parse_rix() of the file, or NULL for a file rix did not write.
nix_store_sbom <- function(path, closure, file, author, organization, regid,
                           timestamp, overrides, embedded, rix = NULL) {
  stand_in <- ".sbom-project-root"
  recs <- closure$records
  edges <- closure$edges
  edges$from[edges$from == ""] <- stand_in
  resolved <- list(
    packages = sort(names(recs), method = "radix"), missing = character(), edges = edges
  )
  root <- project_root_component(dirname(path))
  x <- build_sbom(
    root = root, lookup = list(get = function(name) recs[[name]]),
    root_desc = c(Package = stand_in), fields = character(),
    root_suggests = FALSE, lib = character(), r_version = closure$r_version,
    author = author, organization = organization, regid = regid,
    timestamp = timestamp,
    inputs = data.frame(kind = "default.nix", path = as.character(path), stringsAsFactors = FALSE),
    resolved = resolved, embedded = embedded, system = FALSE, detect_lib = NULL,
    package_evidence = "observed", package_source = "nix-store",
    where = "in the Nix store", r_evidence = "observed", all_required = TRUE
  )
  comps <- x$components
  if (!is.null(rix)) {
    comps <- nix_describe(comps, rix, source = "nix-store")
  }
  root_ref <- root$component$ref
  pkg_rows <- !comps$is_root & is.na(comps$parent_ref) & comps$name %in% names(recs) &
    comps$source_input %in% "nix-store"
  ref_of <- stats::setNames(comps$ref[pkg_rows], comps$name[pkg_rows])

  rels <- closure$relationships
  place <- function(id) {
    out <- id
    out[id == ""] <- root_ref
    is_pkg <- startsWith(id, "pkg:")
    out[is_pkg] <- unname(ref_of[sub("^pkg:", "", id[is_pkg])])
    out
  }
  rels$from <- place(rels$from)
  rels$to <- place(rels$to)
  lost <- is.na(rels$from) | is.na(rels$to)
  dropped <- closure$dropped + sum(lost)
  rels <- rels[!lost, , drop = FALSE]

  x$components <- comps
  x <- nix_assume_cran(
    x, ref_of[closure$assumed_cran],
    function(names, one) {
      paste0(
        length(names), if (one) " R package in the Nix store has" else " R packages in the Nix store have",
        " no recorded repository (", capped_list(names), "), so ",
        if (one) "its package URL assumes it is the CRAN package of that name." else
          "their package URLs assume they are the CRAN packages of those names."
      )
    }
  )
  comps <- rbind(x$components, closure$components)
  comps <- comps[order(comps$ref, method = "radix"), , drop = FALSE]
  rownames(comps) <- NULL
  rels <- rbind(x$relationships, rels)
  rels <- rels[!duplicated(rels[c("from", "to", "field")]), , drop = FALSE]
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL
  x$components <- comps
  x$relationships <- rels

  # What a package without a readable DESCRIPTION lacks is one issue.
  none <- closure$no_description
  if (length(none) > 0L) {
    refs <- unname(ref_of[none])
    x$issues <- x$issues[!(x$issues$code %in% c("license-missing", "maintainer-missing", "source-unknown") &
      x$issues$ref %in% refs), , drop = FALSE]
    one <- length(none) == 1L
    x$issues <- add_issue(
      x$issues, root_ref, "license", "nix-description-unreadable",
      paste0(
        "The DESCRIPTION of ", and_list(none), " could not be read from the Nix store, so ",
        if (one) "its licence and maintainer are" else "their licences and maintainers are", " unknown."
      )
    )
  }
  # So is a version that neither the store path nor the DESCRIPTION gives.
  x$issues <- x$issues[!(x$issues$code %in% "version-missing" & x$issues$ref %in% unname(ref_of)), , drop = FALSE]
  unversioned <- closure$versionless
  if (length(unversioned) > 0L) {
    one <- length(unversioned) == 1L
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-store-versions-unknown",
      paste0(
        length(unversioned), if (one) " store path in the environment carries" else
          " store paths in the environment carry",
        " no version (", capped_list(unversioned), "), so ",
        if (one) "its version is" else "their versions are", " unknown."
      ),
      severity = "info"
    )
  }
  if (dropped > 0L) {
    x$issues <- add_issue(
      x$issues, root_ref, "dependencies", "nix-edges-dropped",
      paste0(
        "sbom could not place ", dropped, if (dropped == 1L) " reference" else " references",
        " between store paths in the SBOM, so ", if (dropped == 1L) "it is" else "they are",
        " not recorded."
      ),
      severity = "info"
    )
  }
  if (is.null(closure$r_version)) {
    x$issues <- add_issue(
      x$issues, "R", "version", "r-version-unknown",
      paste0("R is not in the Nix store closure of ", file, ", so R is listed without a version.")
    )
  }
  x$metadata$notes <- c(x$metadata$notes, "The components were read from the Nix store.")
  rownames(x$issues) <- NULL
  apply_overrides(x, overrides)
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

# Items for a sentence, in the order given, with at most `cap` of them shown:
# "a, b and c", or "a, b, ..., t, and 5 more".
capped_list <- function(x, cap = 20L) {
  if (length(x) <= cap) {
    return(and_list(x))
  }
  paste0(paste(x[seq_len(cap)], collapse = ", "), ", and ", length(x) - cap, " more")
}
