# Base packages that ship with R. They are never looked up in a library.
base_packages <- function() {
  c(
    "base", "compiler", "datasets", "graphics", "grDevices", "grid",
    "methods", "parallel", "splines", "stats", "stats4", "tcltk", "tools",
    "utils"
  )
}

# Reads every DESCRIPTION in the library paths. The first path that holds a
# package wins, as it does when R loads it. Lock directories and entries
# without a readable Package and Version are skipped.
read_library <- function(lib = .libPaths()) {
  rows <- list()
  seen <- character()
  for (path in unique(as.character(lib))) {
    if (is.na(path) || !dir.exists(path)) {
      next
    }
    dirs <- sort(list.dirs(path, full.names = FALSE, recursive = FALSE), method = "radix")
    dirs <- dirs[!grepl("^00LOCK", dirs)]
    for (dir in dirs) {
      desc <- tryCatch(read_description(file.path(path, dir)), error = function(e) NULL)
      if (is.null(desc) || !all(c("Package", "Version") %in% names(desc))) {
        next
      }
      package <- trimws(desc[["Package"]])
      version <- trimws(desc[["Version"]])
      if (!nzchar(package) || !nzchar(version) || package %in% seen) {
        next
      }
      seen <- c(seen, package)
      rows[[length(rows) + 1L]] <- list(
        package = package, version = version, libpath = path, desc = desc
      )
    }
  }
  out <- data.frame(
    package = vapply(rows, `[[`, "", "package"),
    version = vapply(rows, `[[`, "", "version"),
    libpath = vapply(rows, `[[`, "", "libpath"),
    stringsAsFactors = FALSE
  )
  out$desc <- lapply(rows, `[[`, "desc")
  out
}

# Every directory in the library paths that could hold a package, as
# (package, path) rows in path order and then name order. Lists directories
# only: no DESCRIPTION is read. Lock directories, directories without a
# DESCRIPTION file and non-existent paths are skipped. A package in several
# paths has one row for each.
library_candidates <- function(lib = .libPaths()) {
  package <- character()
  path_of <- character()
  for (path in unique(as.character(lib))) {
    if (is.na(path) || !dir.exists(path)) {
      next
    }
    dirs <- sort(list.dirs(path, full.names = FALSE, recursive = FALSE), method = "radix")
    dirs <- dirs[!grepl("^00LOCK", dirs)]
    dirs <- dirs[file.exists(file.path(path, dirs, "DESCRIPTION"))]
    package <- c(package, dirs)
    path_of <- c(path_of, rep(path, length(dirs)))
  }
  data.frame(package = package, path = path_of, stringsAsFactors = FALSE)
}

# One row per package directory name, the first library path winning. Reads
# no DESCRIPTION contents.
library_index <- function(lib = .libPaths()) {
  cand <- library_candidates(lib)
  cand <- cand[!duplicated(cand$package), , drop = FALSE]
  rownames(cand) <- NULL
  cand
}

# A lazy view of the library. `$get(name)` reads and caches one DESCRIPTION,
# and `$all()` is read_library() (which also fills the cache). The cache lives
# in the returned environment, so separate lookups never share it.
#
# `$get()` matches read_library() on a bad copy: when the first path's
# DESCRIPTION is unreadable, or lacks Package or Version, that copy is skipped
# and the next path that holds a usable one wins.
library_lookup <- function(lib = .libPaths()) {
  env <- new.env(parent = emptyenv())
  cand <- library_candidates(lib)
  cache <- new.env(parent = emptyenv())
  env$get <- function(name) {
    if (!is.character(name) || length(name) != 1L || is.na(name) || !nzchar(name)) {
      return(NULL)
    }
    if (!is.null(hit <- cache[[name]])) {
      return(if (is.na(hit[[1L]][1L])) NULL else hit)
    }
    desc <- NULL
    for (path in cand$path[cand$package == name]) {
      desc <- read_usable_description(file.path(path, name))
      if (!is.null(desc)) {
        break
      }
    }
    cache[[name]] <- if (is.null(desc)) NA_character_ else desc
    desc
  }
  env$all <- function() {
    db <- read_library(lib)
    for (i in seq_len(nrow(db))) {
      cache[[db$package[[i]]]] <- db$desc[[i]]
    }
    db
  }
  env
}

# The DESCRIPTION at `dir`, or NULL when it can't be read or lacks a Package
# or Version.
read_usable_description <- function(dir) {
  desc <- tryCatch(read_description(dir), error = function(e) NULL)
  if (is.null(desc) || !all(c("Package", "Version") %in% names(desc))) {
    return(NULL)
  }
  if (!nzchar(trimws(desc[["Package"]])) || !nzchar(trimws(desc[["Version"]]))) {
    return(NULL)
  }
  desc
}

# Breadth-first walk from a root DESCRIPTION through the lookup. Required fields are
# followed to exhaustion first. Suggests are then read from the root only:
# their edges are recorded, and packages not already reached are listed but
# not followed.
resolve_dependencies <- function(root_desc, lookup,
                                 fields = c("Depends", "Imports", "LinkingTo"),
                                 root_suggests = FALSE) {
  root_name <- if ("Package" %in% names(root_desc)) root_desc[["Package"]] else NA_character_
  skip <- c(base_packages(), "R")
  edge_list <- list()
  found <- character()
  missing <- character()
  visited <- root_name

  add_edges <- function(from, desc, use) {
    out <- character()
    for (field in use) {
      value <- if (field %in% names(desc)) desc[[field]] else NA_character_
      deps <- parse_dep_field(value, field)
      if (nrow(deps) == 0L) {
        next
      }
      edge_list[[length(edge_list) + 1L]] <<- data.frame(
        from = rep(from, nrow(deps)), to = deps$name, field = deps$field,
        spec = deps$spec, constraint = deps$constraint, stringsAsFactors = FALSE
      )
      out <- c(out, deps$name)
    }
    out
  }
  visit <- function(dep) {
    visited <<- c(visited, dep)
    desc <- lookup$get(dep)
    if (is.null(desc)) {
      missing <<- c(missing, dep)
      NULL
    } else {
      found <<- c(found, dep)
      desc
    }
  }

  queue <- list(list(name = root_name, desc = root_desc))
  while (length(queue) > 0L) {
    item <- queue[[1L]]
    queue <- queue[-1L]
    for (dep in add_edges(item$name, item$desc, fields)) {
      if (dep %in% skip || dep %in% visited) {
        next
      }
      desc <- visit(dep)
      if (!is.null(desc)) {
        queue[[length(queue) + 1L]] <- list(name = dep, desc = desc)
      }
    }
  }
  if (root_suggests) {
    for (dep in add_edges(root_name, root_desc, "Suggests")) {
      if (!dep %in% skip && !dep %in% visited) {
        visit(dep)
      }
    }
  }
  edges <- if (length(edge_list)) {
    do.call(rbind, edge_list)
  } else {
    data.frame(
      from = character(), to = character(), field = character(),
      spec = character(), constraint = character(), stringsAsFactors = FALSE
    )
  }
  edges <- edges[!duplicated(edges[c("from", "to", "field")]), , drop = FALSE]
  rownames(edges) <- NULL
  list(
    packages = sort(found, method = "radix"),
    missing = sort(missing, method = "radix"),
    edges = edges
  )
}

# Vectorised check of "op version" constraints. NA when either side is NA or
# can't be parsed.
constraint_satisfied <- function(version, constraint) {
  n <- max(length(version), length(constraint))
  if (length(version) == 0L || length(constraint) == 0L) {
    return(logical())
  }
  version <- rep_len(as.character(version), n)
  constraint <- rep_len(as.character(constraint), n)
  vapply(seq_len(n), function(i) {
    v <- version[[i]]
    parts <- regmatches(
      constraint[[i]],
      regexec("^\\s*(>=|<=|==|!=|>|<)\\s*(\\S+)\\s*$", constraint[[i]])
    )[[1L]]
    if (is.na(v) || is.na(constraint[[i]]) || length(parts) != 3L) {
      return(NA)
    }
    have <- tryCatch(package_version(v), error = function(e) NULL)
    want <- tryCatch(package_version(parts[[3L]]), error = function(e) NULL)
    if (is.null(have) || is.null(want)) {
      return(NA)
    }
    switch(parts[[2L]],
      ">=" = have >= want, ">" = have > want, "<=" = have <= want,
      "<" = have < want, "==" = have == want, "!=" = have != want
    )
  }, logical(1L))
}
