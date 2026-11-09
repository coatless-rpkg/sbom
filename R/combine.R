# combine_sbom(): several SBOMs under one new root, for a document that
# covers more than one app, project or package.

#' Combine several SBOMs into one
#'
#' `combine_sbom()` puts several SBOMs under one new root component, for a
#' single document that covers more than one app, project or package. Each
#' SBOM's root becomes a component that the new root depends on, and every
#' component, relationship and issue of each SBOM comes along.
#' `sbom(c(path1, path2), name = ...)` builds an SBOM for each path and
#' combines them with this function.
#'
#' A component that is in more than one SBOM, with the same ref, name,
#' version, kind of version (exact or minimum), type, ecosystem and package
#' URL, is listed once. Two versions of
#' a package are both listed. When two SBOMs use the same ref for components
#' that differ, such as `R` at two versions or two project folders with the
#' same name, the later one gets a ref of its own: the ref followed by
#' `@<version>`, or by `~2`, `~3` and so on when that is taken too or there
#' is no version. Its relationships, issues, advisories and nested
#' components follow. The SBOMs' roots are never merged.
#'
#' The combined SBOM states its own author, organization, regid and
#' timestamp, so the issues and notes about those of each SBOM are left out.
#' Overrides already applied to an SBOM stay, with who asserted each, and
#' `overrides` applies more, to the combined SBOM.
#'
#' Advisories are kept when every SBOM lists them from the same advisory
#' data. Otherwise the combined SBOM lists none, with an
#' `advisories-not-combined` issue, unless `advisories` asks for them: then
#' they are looked up again for every component.
#'
#' @param ... `<sbom>` objects, or a single list of them, as made by
#'   [sbom()], the other builders or [read_sbom()].
#' @param name The name of the new root component, such as the name of the
#'   system or the release that the SBOMs make up together. Its ref is
#'   `combined/<name>`.
#' @param version The version of the new root, or `NULL` for none, which
#'   adds a `version-missing` issue.
#' @inheritParams sbom_package
#' @return An `<sbom>` object whose root is a component of type
#'   `application` called `name`.
#' @examples
#' ts <- as.POSIXct("2026-01-01", tz = "UTC")
#' study <- file.path(sbom_example("study"), "renv.lock")
#' analysis <- file.path(sbom_example("analysis"), "renv.lock")
#' x <- combine_sbom(
#'   sbom_renv(study, system = FALSE, timestamp = ts),
#'   sbom_renv(analysis, system = FALSE, timestamp = ts),
#'   name = "research", version = "2026.1", timestamp = ts
#' )
#' sbom_tree(x, max_depth = 2)
#' @export
combine_sbom <- function(..., name, version = NULL,
                         author = getOption("sbom.author"),
                         organization = getOption("sbom.organization"),
                         regid = getOption("sbom.regid"),
                         timestamp = NULL, overrides = NULL,
                         advisories = FALSE, advisories_on_error = c("error", "continue")) {
  xs <- list(...)
  if (length(xs) == 1L && is.list(xs[[1L]]) && !inherits(xs[[1L]], "sbom")) {
    xs <- xs[[1L]]
  }
  if (length(xs) == 0L) {
    cli::cli_abort("{.fn combine_sbom} needs at least one {.cls sbom} object.")
  }
  not_sbom <- !vapply(xs, inherits, NA, what = "sbom")
  if (any(not_sbom)) {
    cli::cli_abort(c(
      "Every SBOM to combine must be an {.cls sbom} object.",
      "x" = "Argument {which(not_sbom)} {?is/are} not."
    ))
  }
  if (missing(name)) {
    cli::cli_abort("Give the combined SBOM a {.arg name}.")
  }
  if (!is_string(name) || !nzchar(trimws(name))) {
    cli::cli_abort("{.arg name} must be a single string, not {.obj_type_friendly {name}}.")
  }
  if (!is.null(version) && (!is_string(version) || !nzchar(trimws(version)))) {
    cli::cli_abort("{.arg version} must be a single string or {.code NULL}, not {.obj_type_friendly {version}}.")
  }
  on_error <- check_advisories_args(advisories, advisories_on_error)
  regid <- check_regid(regid)
  name <- enc2utf8_bytes(trimws(name))
  version <- if (is.null(version)) NA_character_ else enc2utf8_bytes(trimws(version))

  taken <- unlist(lapply(xs, function(x) x$components$ref), use.names = FALSE)
  root <- combined_root(name, version, taken)
  made <- unique_refs(xs, root$component)
  xs <- made$xs
  x <- combine_tables(xs, made$merged, root$component)

  who <- sbom_authorship(author, organization, regid, rbind(root$issues, x$issues), root$component$ref)
  kept <- if (isFALSE(advisories)) {
    combined_advisories(xs, root$component$ref)
  } else {
    # Looked up again below, for every component.
    list(
      listed = FALSE, advisories = empty_advisories(), metadata = advisories_metadata(),
      notes = character(), issues = empty_issues()
    )
  }
  issues <- rbind(who$issues, kept$issues)
  issues <- issues[!duplicated(issues), , drop = FALSE]
  rownames(issues) <- NULL

  notes <- c(x$notes, kept$notes, timestamp_notes(timestamp))
  inputs <- x$inputs
  if (!kept$listed) {
    inputs <- inputs[inputs$kind != "advisories", , drop = FALSE]
  }
  if (is.character(overrides)) {
    inputs <- rbind(inputs, data.frame(kind = "overrides", path = overrides, stringsAsFactors = FALSE))
  }
  inputs <- inputs[!duplicated(inputs), , drop = FALSE]
  rownames(inputs) <- NULL

  out <- new_sbom(
    list(
      root = root$component$ref,
      timestamp = resolve_timestamp(timestamp),
      author = who$author,
      organization = who$organization,
      tool_version = as.character(utils::packageVersion("sbom")),
      notes = unique(notes),
      inputs = inputs,
      regid = who$regid,
      advisories = kept$metadata
    ),
    x$components, x$relationships, issues, kept$advisories
  )
  out <- apply_overrides(out, overrides)
  if (!isFALSE(advisories)) {
    out <- apply_advisories(out, advisories, on_error)
  }
  out
}

# The new root component, with a ref that none of `taken` has, and its issue
# when it has no version.
combined_root <- function(name, version, taken) {
  ref <- unique_ref(paste0("combined/", name), NA_character_, taken)
  component <- component_row(
    ref = ref, name = name, version = version,
    version_is = if (is.na(version)) NA_character_ else "exact",
    type = "application", ecosystem = "local", is_root = TRUE,
    scope = "required", evidence = "declared", source_input = "combined"
  )
  issues <- empty_issues()
  if (is.na(version)) {
    issues <- add_issue(
      issues, ref, "version", "version-missing",
      paste0("No version was given for the combined SBOM ", name, ", so it has none.")
    )
  }
  list(component = component, issues = issues)
}

# `ref` when none of `taken` is, otherwise `ref@version` when there is a
# version and `ref` does not end with it, otherwise `ref~2`, `ref~3` and so
# on.
unique_ref <- function(ref, version, taken) {
  if (!ref %in% taken) {
    return(ref)
  }
  if (!is.na(version) && !endsWith(ref, paste0("@", version))) {
    at <- paste0(ref, "@", version)
    if (!at %in% taken) {
      return(at)
    }
  }
  k <- 2L
  while (paste0(ref, "~", k) %in% taken) {
    k <- k + 1L
  }
  paste0(ref, "~", k)
}

# Whether row `i` of components `a` and row `j` of components `b` are the
# same component, given the same ref: the same name, version, kind of
# version (exact or minimum), type, ecosystem and package URL.
same_component <- function(a, i, b, j) {
  cols <- c("name", "version", "version_is", "type", "ecosystem", "purl")
  all(vapply(cols, function(col) identical(a[[col]][[i]], b[[col]][[j]]), NA))
}

# The notes of an SBOM that describe that document, not its components, and
# so do not belong in a combination of it: where its timestamp came from,
# and what it says about advisories.
document_note <- function(notes) {
  timestamp <- grepl(
    paste0(
      "^The timestamp (comes from the SOURCE_DATE_EPOCH|is 1980-01-01T00:00:00Z, the placeholder)",
      "|^The document has no timestamp, so the time "
    ),
    notes
  )
  advisory <- notes %in% unlist(advisory_notes) |
    grepl(paste(unlist(advisory_sentences), collapse = "|"), notes, perl = TRUE)
  timestamp | advisory
}

# The SBOMs to combine, `xs`, with their refs made unique: a ref that
# clashes with one of an earlier SBOM, or of the new root `root`, is given a
# new one (unique_ref()) and followed everywhere (rewrite_refs()), unless
# the two are the same component. `merged` holds, for each SBOM, which of
# its components are the same as an earlier one's and so are listed once.
unique_refs <- function(xs, root) {
  refs <- root$ref
  merged <- vector("list", length(xs))
  for (i in seq_along(xs)) {
    own <- xs[[i]]$components
    seen_comps <- do.call(rbind, c(list(root), lapply(xs[seq_len(i - 1L)], `[[`, "components")))
    map <- stats::setNames(own$ref, own$ref)
    same <- rep(FALSE, nrow(own))
    assigned <- character()
    # A nested ref ("<parent>#embedded/..."), after the refs it is nested in.
    depth <- lengths(regmatches(own$ref, gregexpr("#", own$ref, fixed = TRUE)))
    for (j in order(depth, seq_along(depth))) {
      old <- own$ref[[j]]
      wanted <- old
      at <- regexpr("#", old, fixed = TRUE)
      if (at > 0L && substr(old, 1L, at - 1L) %in% names(map)) {
        wanted <- paste0(map[[substr(old, 1L, at - 1L)]], substring(old, at))
      }
      seen <- match(wanted, seen_comps$ref)
      if (!own$is_root[[j]] && !is.na(seen) && !seen_comps$is_root[[seen]] &&
        same_component(own, j, seen_comps, seen)) {
        map[[old]] <- wanted
        same[[j]] <- TRUE
        next
      }
      map[[old]] <- unique_ref(wanted, own$version[[j]], c(refs, assigned, own$ref[-j]))
      assigned <- c(assigned, map[[old]])
    }
    xs[[i]] <- rewrite_refs(xs[[i]], function(ref) {
      hit <- !is.na(ref) & ref %in% names(map)
      ref[hit] <- unname(map[ref[hit]])
      ref
    })
    refs <- c(refs, assigned)
    merged[[i]] <- same
  }
  list(xs = xs, merged = merged)
}

# The components, relationships, issues, notes and inputs of `xs`, the SBOMs
# to combine, with refs already made unique (unique_refs()), under the root
# component `root`. The components in `merged` are listed once, as the first
# SBOM that has them records them, but required when any SBOM requires them.
# Each SBOM's root becomes a component that `root` depends on. Issues about
# each SBOM's own author and advisories are left out, and so are notes about
# its timestamp and advisories.
combine_tables <- function(xs, merged, root) {
  comps <- root
  for (i in seq_along(xs)) {
    own <- xs[[i]]$components
    required <- own$ref[merged[[i]] & own$scope %in% "required"]
    comps$scope[comps$ref %in% required] <- "required"
    add <- own[!merged[[i]], , drop = FALSE]
    add$is_root <- rep(FALSE, nrow(add))
    comps <- rbind(comps, add)
  }
  rownames(comps) <- NULL
  under <- data.frame(
    from = root$ref, to = vapply(xs, function(x) x$metadata$root, ""),
    field = "depends_on", spec = NA_character_, evidence = "declared", stringsAsFactors = FALSE
  )
  rels <- do.call(rbind, c(list(empty_relationships()), lapply(xs, `[[`, "relationships"), list(under)))
  rels <- rels[!duplicated(rels[c("from", "to", "field")]), , drop = FALSE]
  rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
  rownames(rels) <- NULL
  issues <- do.call(rbind, c(list(empty_issues()), lapply(xs, `[[`, "issues")))
  issues <- issues[!issues$code %in% c("no-sbom-author", "regid-missing") &
    !startsWith(issues$code, "advisories-"), , drop = FALSE]
  issues <- issues[!duplicated(issues), , drop = FALSE]
  notes <- unlist(lapply(xs, function(x) as.character(x$metadata$notes)))
  list(
    components = comps, relationships = rels, issues = issues,
    notes = unique(notes[!document_note(notes)]),
    inputs = do.call(rbind, lapply(xs, function(x) x$metadata$inputs))
  )
}

# The advisories of the combined SBOM, from `xs`, the SBOMs with refs made
# unique, and `root`, the new root's ref: when every SBOM lists advisories
# from the same data, all of them, with those of one advisory in several
# SBOMs joined, their notes and their issues, at the root. Otherwise none,
# the note that none is listed, and, when any SBOM listed some, an issue
# saying that they were left out. `listed` says which.
combined_advisories <- function(xs, root) {
  status <- vapply(xs, advisories_status, "")
  source_of <- function(x) {
    m <- x$metadata$advisories
    paste(m$source, m$newest_modified)
  }
  same <- all(status == "listed") && length(unique(vapply(xs, source_of, ""))) == 1L
  if (!same) {
    issues <- empty_issues()
    if (any(status != "not-requested")) {
      issues <- add_issue(
        issues, root, "advisories", "advisories-not-combined",
        paste0(
          "The SBOMs combined here do not all list advisories from the same ",
          "advisory data, so this SBOM lists none; ask for advisories when ",
          "combining them to look them up for every component."
        ),
        severity = "info"
      )
    }
    return(list(
      listed = FALSE, advisories = empty_advisories(), metadata = advisories_metadata(),
      notes = advisory_notes$no_data, issues = issues
    ))
  }
  adv <- do.call(rbind, lapply(xs, `[[`, "advisories"))
  issues <- do.call(rbind, lapply(xs, function(x) x$issues[startsWith(x$issues$code, "advisories-"), , drop = FALSE]))
  issues$ref <- rep(root, nrow(issues))
  notes <- unlist(lapply(xs, function(x) as.character(x$metadata$notes)))
  notes <- notes[document_note(notes) & !notes %in% advisory_notes$no_data]
  joined <- adv[!duplicated(adv$id), , drop = FALSE]
  joined$affects <- lapply(joined$id, function(id) {
    df <- do.call(rbind, adv$affects[adv$id == id])
    df <- df[!duplicated(df$ref), , drop = FALSE]
    rownames(df) <- NULL
    df
  })
  rownames(joined) <- NULL
  list(
    listed = TRUE, advisories = joined, metadata = xs[[1L]]$metadata$advisories,
    notes = unique(notes), issues = issues[!duplicated(issues), , drop = FALSE]
  )
}
