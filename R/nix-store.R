# Nix mode (experimental): the environment that a Nix file describes, read
# from the Nix store with nix-instantiate and nix-store.

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

  found <- nix_store_records(tab, rix)
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
  versionless <- c(found$versionless, nix_comps$name[is.na(nix_comps$version)])
  is_lib <- vapply(split(tab[tab$kind == "nix", , drop = FALSE], tab$ref[tab$kind == "nix"]), function(rows) {
    any(rows$output == "lib") || startsWith(rows$name[[1L]], "lib")
  }, NA)

  linked <- nix_graph_edges(tab, graph, direct, is_lib)
  r_rows <- tab[tab$kind == "r", , drop = FALSE]
  list(
    status = "ok", records = found$records, no_description = found$no_description,
    assumed_cran = found$assumed,
    versionless = sort(unique(versionless), method = "radix"),
    r_version = if (nrow(r_rows) > 0L && nzchar(r_rows$version[[1L]])) r_rows$version[[1L]],
    edges = linked$edges,
    components = nix_comps,
    relationships = linked$relationships,
    dropped = linked$dropped
  )
}

# The DESCRIPTION-shaped record of each R package in `tab`, nix_closure()'s
# table of store paths, by name, as list(records, no_description, assumed,
# versionless): the packages whose DESCRIPTION could not be read, those
# taken to be from CRAN because nothing says where they come from, and the
# store names of the paths without a version. A package that `rix`
# (parse_rix()'s list, or NULL) fetches from git or the CRAN archive takes
# its source from there.
nix_store_records <- function(tab, rix) {
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
  list(records = records, no_description = no_description, assumed = assumed, versionless = versionless)
}

# The edges of the DOT `graph` of the store paths in `tab` (nix_closure()'s
# table), and of the root to the `direct` paths, as list(edges,
# relationships, dropped): Imports between R packages, for build_sbom(), the
# other relationships, and the number of edges whose ends are not in `tab`.
# `is_lib` says, by ref, which Nix packages are libraries, linked
# dynamically; the others are system requirements.
nix_graph_edges <- function(tab, graph, direct, is_lib) {
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
  list(
    edges = bind(edge_rows, data.frame(
      from = character(), to = character(), field = character(), spec = character(),
      constraint = character(), evidence = character(), stringsAsFactors = FALSE
    )),
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
        if (one) "its license and maintainer are" else "their licenses and maintainers are", " unknown."
      )
    )
  }
  # So is a version that neither the store path nor the DESCRIPTION gives.
  x$issues <- x$issues[!(x$issues$code %in% "version-missing" & x$issues$ref %in% unname(ref_of)), , drop = FALSE]
  unversioned <- closure$versionless
  if (length(unversioned) > 0L) {
    x$issues <- add_issue(
      x$issues, root_ref, "version", "nix-store-versions-unknown",
      nix_store_versions_sentence(unversioned),
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

# The sentence of the nix-store-versions-unknown issue: the store names of
# the paths without a version, sorted and unique, as the closure gives them.
# apply_overrides() builds it again after an override asserts some of those
# versions.
nix_store_versions_sentence <- function(names) {
  one <- length(names) == 1L
  paste0(
    length(names), if (one) " store path in the environment carries" else
      " store paths in the environment carry",
    " no version (", capped_list(names), "), so ",
    if (one) "its version is" else "their versions are", " unknown."
  )
}
