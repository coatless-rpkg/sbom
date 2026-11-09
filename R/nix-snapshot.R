# The CRAN snapshot that a Nix file pins, for the versions and dependencies
# that a rix file does not record.

# The records of the packages a rix file names (nix_records()), with their
# versions and dependencies looked up in the CRAN snapshot `snap`
# (nix_snapshot_source()) when it has a location, as list(recs, looked,
# reason): `looked` is nix_snapshot()'s list, or NULL when nothing was looked
# up, and `reason` why the snapshot could not be read, or NA.
nix_snapshot_records <- function(recs, snap) {
  out <- list(recs = recs, looked = NULL, reason = NA_character_)
  if (is.na(snap$location)) {
    return(out)
  }
  data <- read_packages_file(snap$location)
  if (!is.data.frame(data)) {
    reason <- attr(data, "reason")
    if (!is.character(reason) || length(reason) != 1L || is.na(reason)) {
      reason <- "the snapshot could not be read"
    }
    out$reason <- reason
    return(out)
  }
  looked <- nix_snapshot(recs$records, recs$deps_known, data)
  recs$records <- looked$records
  recs$deps_known <- looked$deps_known
  # nixpkgs' rPackages holds Bioconductor packages too, so a name that the
  # CRAN snapshot lacks is not known to be a CRAN package.
  for (name in looked$missing) {
    recs$records[[name]] <- c(Package = name, Source = "unknown")
  }
  out$recs <- recs
  out$looked <- looked
  out
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
