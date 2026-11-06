# Reading a Posit Connect manifest.json into an <sbom>.

#' Build an SBOM from a Posit Connect manifest
#'
#' `sbom_rsconnect()` describes a content item that is deployed, or ready to
#' deploy, to Posit Connect. It reads the `manifest.json` that
#' `rsconnect::writeManifest()` writes, and it runs no code from the project
#' and makes no network requests, except that `advisories = TRUE` downloads
#' OSV's advisory data.
#'
#' Every package in the manifest is listed at the version the manifest
#' records, as declared, with its source (CRAN or another repository,
#' Bioconductor, GitHub, GitLab, Bitbucket, another git repository or a local
#' source), read from its `description` or, when that names no repository,
#' from the entry's own `Source` and `Repository`. A package whose source the
#' manifest does not record is of ecosystem `"unknown"`, with an issue. R is
#' listed at the version in `platform`. A package that a recorded package
#' depends on, but that the manifest does not record, is listed as unknown,
#' with an issue. A package whose `description` records only its name,
#' version and source says nothing of its dependencies, so it gets no
#' dependency entry in CycloneDX, rather than an empty one, with an issue.
#'
#' The folder of the manifest is the root, an application, with its git commit
#' as the version when it is in a git repository. Each entry of the
#' manifest's `files` is a component of type `"file"`, contained by the root,
#' with the MD5 checksum the manifest records; sbom does not read the files.
#' As for [sbom_renv()], the packages the root uses directly are inferred from
#' the code in the folder, or, when none are found, from the recorded packages
#' that no other recorded package requires.
#'
#' @inheritParams sbom_package
#' @param manifest The path to a `manifest.json` file.
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' sbom_rsconnect(system.file("extdata", "manifest.json", package = "sbom"), system = FALSE)
#' @export
sbom_rsconnect <- function(manifest = "manifest.json",
                           author = getOption("sbom.author"),
                           organization = getOption("sbom.organization"),
                           regid = getOption("sbom.regid"),
                           timestamp = NULL, overrides = NULL,
                           embedded = TRUE, system = TRUE, advisories = FALSE,
                           advisories_on_error = c("error", "continue")) {
  on_error <- check_advisories_args(advisories, advisories_on_error)
  regid <- check_regid(regid)
  m <- read_manifest(manifest)
  project <- dirname(normalizePath(manifest, mustWork = TRUE))
  recs <- manifest_records(m)
  deps_known <- vapply(recs, function(r) description_shaped(names(r)), NA)

  names_recorded <- names(recs)
  edges <- renv_edges(recs, NULL)
  scan <- project_root_edges(project, recs, NULL)
  edges <- rbind(scan$edges, edges)
  stand_in <- ".sbom-project-root"
  edges$from[edges$from == ""] <- stand_in
  absent <- setdiff(edges$to, c(names_recorded, base_packages(), "R"))
  resolved <- list(
    packages = sort(names_recorded, method = "radix"),
    missing = sort(unique(absent), method = "radix"),
    edges = edges
  )

  root <- project_root_component(project)
  appmode <- if (is.list(m$metadata)) m$metadata$appmode
  root$component$description <- enc2utf8_bytes(connect_sentence(m))
  inputs <- data.frame(
    kind = "manifest.json", path = as.character(manifest), stringsAsFactors = FALSE
  )
  r_version <- if (is.character(m$platform) && length(m$platform) == 1L && nzchar(m$platform)) {
    m$platform
  }
  x <- build_sbom(
    root = root, lookup = list(get = function(name) recs[[name]]),
    root_desc = c(Package = stand_in), fields = character(),
    root_suggests = FALSE, lib = character(), r_version = r_version,
    author = author, organization = organization, regid = regid,
    timestamp = timestamp, inputs = inputs, resolved = resolved,
    embedded = embedded, system = system, detect_lib = .libPaths(),
    package_evidence = "declared", package_source = "manifest.json",
    where = "recorded in manifest.json",
    missing_code = "dependency-not-recorded", r_evidence = "declared",
    all_required = TRUE
  )

  x <- mark_deps_unknown(x, names(deps_known)[!deps_known], "manifest.json")
  x <- add_app_files(x, m$files, root$component$ref)
  x$issues <- scan_issue(x$issues, root, scan)
  x$metadata$notes[x$metadata$notes == checksum_note()] <- paste0(
    "The MD5 checksums of the app files are those recorded in manifest.json; ",
    "sbom did not read the files."
  )
  rownames(x$issues) <- NULL
  apply_advisories(apply_overrides(x, overrides), advisories, on_error)
}

# "Deployed to Posit Connect as a {appmode} application.", or without the
# appmode when the manifest names none, for the parsed manifest `m`.
connect_sentence <- function(m) {
  appmode <- if (is.list(m$metadata)) m$metadata$appmode
  if (is.character(appmode) && length(appmode) == 1L && !is.na(appmode) && nzchar(appmode)) {
    paste0("Deployed to Posit Connect as a ", appmode, " application.")
  } else {
    "Deployed to Posit Connect."
  }
}

# The manifest as a list, or an error that names the file.
read_manifest <- function(manifest, call = parent.frame()) {
  if (!is.character(manifest) || length(manifest) != 1L || is.na(manifest) ||
    !file.exists(manifest) || dir.exists(manifest)) {
    cli::cli_abort("The manifest {.file {manifest}} does not exist.", call = call)
  }
  m <- tryCatch(jsonlite::read_json(manifest), error = function(e) NULL)
  if (!is.list(m) || is.null(names(m))) {
    cli::cli_abort("The manifest {.file {manifest}} is not valid JSON.", call = call)
  }
  if (!is.list(m$packages)) {
    cli::cli_abort("The manifest {.file {manifest}} has no {.field packages}.", call = call)
  }
  problem <- manifest_problem(m)
  if (!is.null(problem)) {
    where <- problem$where
    entry <- problem$entry
    cli::cli_abort(
      c(
        "The manifest {.file {manifest}} is malformed.",
        x = if (is.na(entry)) {
          "Its {.field {where}} entry is not an object."
        } else {
          "The entry for {.val {entry}} in {.field {where}} is not an object."
        }
      ),
      call = call
    )
  }
  m
}

# What is wrong with the shape of a parsed manifest whose `packages` is a
# list, or NULL: list(where, entry), the part ("packages" or "files") and
# the name of its entry that is not an object, or NA when the part itself is
# not. Both are objects of objects; an empty one may be written as [].
manifest_problem <- function(m) {
  is_object <- function(v) is.list(v) && (length(v) == 0L || !is.null(names(v)))
  for (where in c("packages", "files")) {
    part <- m[[where]]
    if (is.null(part) && where == "files") {
      next
    }
    if (!is_object(part)) {
      return(list(where = where, entry = NA_character_))
    }
    bad <- !vapply(part, is_object, NA)
    if (any(bad)) {
      return(list(where = where, entry = enc2utf8_bytes(names(part)[which(bad)[1L]])))
    }
  }
  NULL
}

# One named character vector per manifest package, in DESCRIPTION shape,
# named by package and sorted by name. Arrays are joined with ", ". The
# entry's `Repository` URL stands in for a missing `RemoteRepos`, and when
# the description names no repository or remote, the entry's `Source` and
# `Repository` say where the package came from (manifest_source()).
manifest_records <- function(m) {
  pkgs <- m$packages
  out <- lapply(names(pkgs), function(key) {
    entry <- pkgs[[key]]
    d <- if (is.list(entry$description)) entry$description else list()
    if (is.null(d$Package)) d$Package <- key
    fields <- vapply(d, function(v) {
      if (is.null(v) || length(v) == 0L) {
        NA_character_
      } else {
        paste(as.character(unlist(v)), collapse = ", ")
      }
    }, "")
    fields <- fields[!is.na(fields)]
    fields <- stats::setNames(enc2utf8_bytes(unname(fields)), enc2utf8_bytes(names(fields)))
    one <- function(v) {
      if (is.character(v) && length(v) == 1L && !is.na(v) && nzchar(v)) enc2utf8_bytes(v) else NA_character_
    }
    repo <- one(entry$Repository)
    url <- if (!is.na(repo) && grepl("^https?://", repo)) repo else NA_character_
    if (!"RemoteRepos" %in% names(fields) && !is.na(url)) {
      fields[["RemoteRepos"]] <- url
    }
    named <- names(fields)[!is.na(fields) & nzchar(trimws(fields))]
    if (!any(named %in% c("Repository", "git_url") | startsWith(named, "Remote") & named != "RemoteRepos")) {
      fields <- manifest_source(fields, one(entry$Source), url)
    }
    fields
  })
  names(out) <- vapply(out, function(f) f[["Package"]], "")
  out[order(names(out), method = "radix")]
}

# A record's source from its manifest entry's `Source` and `Repository` URL,
# as the fields package_ecosystem() reads: a repository named CRAN for CRAN
# or one of its mirrors, Posit Package Manager or another repository with
# its URL, Bioconductor with the release in its URL, a remote type for
# GitHub, GitLab and Bitbucket, and "unknown" when the entry has no Source.
manifest_source <- function(fields, source, url) {
  src <- tolower(source)
  if (is.na(src) || src == "unknown") {
    fields[["Source"]] <- "unknown"
  } else if (src == "bioconductor") {
    fields[["Source"]] <- "Bioconductor"
    rel <- if (is.na(url)) NA_character_ else sub("^.*/packages/([0-9]+\\.[0-9]+)/.*$", "\\1", url)
    if (!is.na(bioc_version(rel))) fields[["Bioconductor.Version"]] <- rel
  } else if (src %in% c("github", "gitlab", "bitbucket", "git")) {
    fields[["RemoteType"]] <- src
  } else if (src != "local") {
    cran <- !is.na(url) && grepl("^https?://([^/]+\\.)?(r-project\\.org|cran\\.rstudio\\.(com|org))(/|$)", url)
    fields[["Repository"]] <- if (is.na(url) && src == "cran" || cran) {
      "CRAN"
    } else if (src == "rspm" || grepl("^https?://packagemanager\\.", url)) {
      "RSPM"
    } else if (!is.na(url)) {
      url
    } else {
      source
    }
  }
  fields
}

# The app's own files as components that the root contains, each with its MD5
# checksum, and an issue for each without one.
add_app_files <- function(x, files, root_ref) {
  if (!is.list(files) || length(files) == 0L) {
    return(x)
  }
  paths <- enc2utf8_bytes(names(files))
  rows <- list()
  for (i in seq_along(files)) {
    sum <- files[[i]]$checksum
    has_sum <- is.character(sum) && length(sum) == 1L && !is.na(sum) && nzchar(sum)
    ref <- paste0("file/", paths[[i]])
    rows[[i]] <- component_row(
      ref = ref, name = paths[[i]], type = "file", ecosystem = "file",
      scope = "required", evidence = "declared", source_input = "manifest.json",
      hashes = if (has_sum) {
        data.frame(
          alg = "MD5", content = tolower(sum), of = "app file",
          stringsAsFactors = FALSE
        )
      } else {
        empty_hashes()
      }
    )
    if (!has_sum) {
      x$issues <- add_issue(
        x$issues, ref, "hashes", "checksum-missing",
        paste0("manifest.json records no checksum for ", paths[[i]], ".")
      )
    }
  }
  comps <- do.call(rbind, c(list(x$components), rows))
  check_unique_refs(comps$ref)
  comps <- comps[order(comps$ref, method = "radix"), , drop = FALSE]
  rownames(comps) <- NULL
  x$components <- comps
  refs <- paste0("file/", paths)
  rels <- rbind(x$relationships, data.frame(
    from = root_ref, to = refs, field = "contains", spec = NA_character_,
    evidence = "declared", stringsAsFactors = FALSE
  ))
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL
  x$relationships <- rels
  x
}
