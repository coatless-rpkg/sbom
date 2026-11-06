# Overrides: values a person asserts where sbom found nothing (or something
# different). Each applied value is recorded in the component's `asserted`
# table with who asserted it and why.

override_columns <- function() c("component", "field", "value", "asserted_by", "reason")

override_fields <- function() {
  c(
    "version", "license_spdx", "supplier_name", "supplier_url", "maintainer",
    "purl", "download_location"
  )
}

# Row numbers count data rows, so row 1 is line 2 of a CSV file.
read_overrides <- function(overrides, call = parent.frame()) {
  if (is.character(overrides) && length(overrides) == 1 && !is.na(overrides)) {
    if (!file.exists(overrides)) {
      cli::cli_abort("The overrides file {.file {overrides}} does not exist.", call = call)
    }
    overrides <- utils::read.csv(
      overrides, colClasses = "character", na.strings = "",
      stringsAsFactors = FALSE, encoding = "UTF-8", check.names = FALSE
    )
  } else if (!is.data.frame(overrides)) {
    cli::cli_abort(
      "{.arg overrides} must be {.code NULL}, a data frame or a path to a CSV file.",
      call = call
    )
  }
  missing <- setdiff(override_columns(), names(overrides))
  if (length(missing) > 0) {
    cli::cli_abort(
      c(
        "{.arg overrides} must have the columns {.val {override_columns()}}.",
        "x" = "Missing {cli::qty(length(missing))}column{?s}: {.val {missing}}."
      ),
      call = call
    )
  }
  out <- overrides[, override_columns(), drop = FALSE]
  out[] <- lapply(out, as.character)
  rownames(out) <- NULL
  out
}

match_component <- function(comps, value, row, call) {
  # An embedded component shares its name with the package it copies, and a
  # system component may share its name with an R package (openssl), so only
  # their refs name them.
  by_ref_only <- is_embedded_ref(comps$ref) | comps$ecosystem %in% system_ecosystems
  hits <- which(comps$ref %in% value | (comps$name %in% value & !by_ref_only))
  if (length(hits) == 0) {
    cli::cli_abort(
      c(
        "Override row {row} names an unknown component, {.val {value}}.",
        "i" = "{.field component} must equal the {.field name} or {.field ref} of a component."
      ),
      call = call
    )
  }
  if (length(hits) > 1) {
    refs <- comps$ref[hits]
    cli::cli_abort(
      c(
        "Override row {row} names an ambiguous component, {.val {value}}.",
        "i" = "It matches {length(refs)} components: {.val {refs}}.",
        "i" = "Use the {.field ref} to choose one."
      ),
      call = call
    )
  }
  hits
}

# The issues an asserted field answers, by code: asserting the field removes
# the component's issues with these codes and keeps the rest. They come from
# every add_issue() under R/ whose subject is that field, on the component's
# own ref:
# * an unsatisfied constraint, drift and an override conflict are findings
#   about the value found, which an assertion does not answer;
# * source-unknown says that a package's source does not record where it came
#   from, which stays true whatever supplier is asserted;
# * fields-from-library says where a license, maintainer or dependencies
#   came from, which stays true until each license and maintainer it names is
#   asserted (override_borrowed());
# * an issue that also states a fact that stays true is reworded instead:
#   source-git (override_reworded), the issues that a dependency is missing
#   (override_reworded_together) and the aggregate issues about versions
#   (override_aggregates, override_embedded(), override_nix_snapshot());
# * no builder gives an issue about a supplier URL or a download location.
override_answers <- list(
  version = c("version-missing", "javascript-version-missing", "r-version-unknown"),
  license_spdx = c("license-missing", "license-no-spdx"),
  supplier_name = "supplier-unknown",
  supplier_url = character(),
  maintainer = "maintainer-missing",
  purl = "purl-inferred",
  download_location = character()
)

# The issues an asserted field rewords, by field and code: what follows the
# component's name in the new sentence, which is info.
override_reworded <- list(
  purl = c(`source-git` = "was installed from a git repository; its package URL is asserted by an override.")
)

# The issues that a dependency is missing, from each builder, which say that
# its version and source are unknown: a version and a package URL asserted
# together reword them as info, with what the new sentence says of the
# source.
override_reworded_together <- c(
  `dependency-not-installed` = "is not installed",
  `dependency-not-locked` = "is not in renv.lock",
  `dependency-not-recorded` = "is not in manifest.json"
)

# The aggregate issues that the builders put on the root about components
# whose version sbom did not find: for each code, the components it names
# (`named(comps, rels)`, as the builder chose them) and its sentence for them
# (`sentence(named, message)`, from the builder's own sentence and, where the
# sentence names a file, the issue's message). apply_overrides() builds the
# issue again when an override changes what it names, and removes it when it
# names nothing more. embedded-not-installed and nix-not-in-snapshot, which
# also state a fact that stays true, are reworded instead
# (override_embedded(), override_nix_snapshot()).
override_aggregates <- list(
  `system-version-unknown` = list(
    named = function(comps, rels) {
      hit <- comps$ecosystem %in% "system" & !comps$version_is %in% "exact" &
        comps$ref %in% rels$to[rels$field %in% "dynamic_link"]
      comps$name[hit][order(comps$ref[hit], method = "radix")]
    },
    sentence = function(named, message) system_version_unknown_sentence(named)
  ),
  `vendored-version-unknown` = list(
    named = function(comps, rels) {
      hit <- comps$ecosystem %in% "vendored" & is.na(comps$version)
      if (!any(hit)) {
        return(character())
      }
      at <- match(comps$parent_ref[hit], comps$ref)
      sort(unique(paste(comps$name[hit], "in", pkg_label(comps$name[at], comps$version[at]))), method = "radix")
    },
    sentence = function(named, message) vendored_version_unknown_sentence(named)
  ),
  `nix-versions-unknown` = list(
    named = function(comps, rels) {
      hit <- comps$is_root %in% FALSE & comps$source_input %in% "default.nix" &
        comps$ecosystem %in% c("cran", "github", "git") & is.na(comps$version)
      sort(comps$ref[hit], method = "radix")
    },
    # It names no package, so it stays as it is while one is left.
    sentence = function(named, message) message
  ),
  `nix-git-versions-unknown` = list(
    named = function(comps, rels) {
      hit <- comps$is_root %in% FALSE & comps$source_input %in% "default.nix" & is.na(comps$parent_ref) &
        startsWith(comps$download_location, "git+") %in% TRUE & is.na(comps$version)
      sort(unique(comps$name[hit]), method = "radix")
    },
    sentence = function(named, message) {
      file <- regmatches(message, regexec("^The versions? of the packages? that (.+) fetches from git ", message))[[1L]]
      if (length(file) == 2L) nix_git_versions_sentence(file[[2L]], named) else NA_character_
    }
  ),
  `nix-store-versions-unknown` = list(
    named = function(comps, rels) {
      store <- comps$is_root %in% FALSE & comps$source_input %in% "nix-store" & is.na(comps$parent_ref) &
        is.na(comps$version)
      # nixpkgs names each R package r-<name>.
      names <- ifelse(comps$ecosystem %in% "nix", comps$name, paste0("r-", comps$name))
      sort(unique(names[store]), method = "radix")
    },
    sentence = function(named, message) nix_store_versions_sentence(named)
  )
)

# The purl types whose version sbom writes as the package's version, so that
# a purl of one of them without a version gains an asserted one.
override_versioned_types <- c("cran", "github", "gitlab", "bitbucket")

# The component each override row names, after checking the row, as indices
# into `comps`. Every row names a component as sbom built it, so a row finds
# a component by its ref even after an earlier row moved it.
override_targets <- function(ov, comps, call = parent.frame()) {
  vapply(seq_len(nrow(ov)), function(i) {
    row <- ov[i, ]
    for (col in override_columns()) {
      # A blank value is missing, as a CSV file reads it.
      if (is.na(row[[col]]) || !nzchar(trimws(row[[col]]))) {
        cli::cli_abort(
          "Override row {i} has no {.field {col}}, and an override must assert something.",
          call = call
        )
      }
    }
    if (!row$field %in% override_fields()) {
      cli::cli_abort(c(
        "Override row {i} names an unknown field, {.val {row$field}}.",
        "i" = "{.field field} must be one of {.val {override_fields()}}."
      ), call = call)
    }
    match_component(comps, row$component, i, call = NULL)
  }, integer(1))
}

# `purl` with its version, when that is `old`, replaced by `new`, or with
# `new` added when it has no version and its type is one of
# override_versioned_types. Otherwise `purl` as it is: NA, invalid, of
# another type, or with another version, such as the commit of a GitHub
# package. Its qualifiers and subpath are kept.
override_purl_version <- function(purl, old, new) {
  parsed <- purl_parse(purl)
  if (!parsed$valid %in% TRUE) {
    return(purl)
  }
  has_version <- !is.na(parsed$version)
  if (has_version && !identical(parsed$version, old)) {
    return(purl)
  }
  if (!has_version && !tolower(parsed$type) %in% override_versioned_types) {
    return(purl)
  }
  rest <- if (grepl("[?#]", purl)) sub("^[^?#]*", "", purl) else ""
  head <- sub("[?#].*$", "", purl)
  if (has_version) {
    head <- sub("@[^@]*$", "", head)
  }
  paste0(head, "@", utils::URLencode(new, reserved = TRUE), rest)
}

# `x` with the component whose ref is `old` given the ref `new`, and every
# reference to it moved with it: the refs of the components inside it, which
# start with "<old>#", parent refs, relationships, issues, advisory targets
# and metadata$root. A ref that another component already has is an error
# that names both refs. The tables are sorted again at the end of
# apply_overrides().
override_move_ref <- function(x, old, new, row) {
  inside <- paste0(old, "#")
  rewrite <- function(ref) {
    hit <- !is.na(ref) & (ref == old | startsWith(ref, inside))
    ref[hit] <- paste0(new, substring(ref[hit], nchar(old) + 1L))
    ref
  }
  comps <- x$components
  moving <- comps$ref == old | startsWith(comps$ref, inside)
  to <- rewrite(comps$ref[moving])
  taken <- which(to %in% comps$ref[!moving])
  if (length(taken) > 0L) {
    from <- comps$ref[moving][[taken[[1L]]]]
    cli::cli_abort(
      paste0(
        "Override row {row} would change the ref of {.val {from}} to {.val {to[[taken[[1L]]]]}}, ",
        "which is already the ref of another component."
      ),
      call = NULL
    )
  }
  comps$ref <- rewrite(comps$ref)
  comps$parent_ref <- rewrite(comps$parent_ref)
  x$components <- comps
  x$relationships$from <- rewrite(x$relationships$from)
  x$relationships$to <- rewrite(x$relationships$to)
  x$issues$ref <- rewrite(x$issues$ref)
  if (is.data.frame(x$advisories) && nrow(x$advisories) > 0L) {
    x$advisories$affects <- lapply(x$advisories$affects, function(a) {
      a$ref <- rewrite(a$ref)
      a
    })
  }
  x$metadata$root <- rewrite(x$metadata$root)
  x
}

# The file name of a package whose version an override changes from `old` to
# `new`: <name>_<old>.tar.gz, .tgz or .zip takes the new version, and any
# other name, which is not known to be the file of the new version, is NA.
override_file_name <- function(file, name, old, new) {
  if (is.na(file) || identical(old, new)) {
    return(file)
  }
  for (ext in c(".tar.gz", ".tgz", ".zip")) {
    if (!is.na(old) && identical(file, paste0(name, "_", old, ext))) {
      return(paste0(name, "_", new, ext))
    }
  }
  NA_character_
}

# `prior`, a component's asserted records, with `record` added.
override_record <- function(prior, record) {
  if (is.data.frame(prior) && all(names(record) %in% names(prior))) {
    rbind(prior[, names(record), drop = FALSE], record)
  } else {
    record
  }
}

# `issues` with the rows `at` given `message` as info.
override_reword <- function(issues, at, message) {
  issues$message[at] <- message
  issues$severity[at] <- "info"
  issues
}

# `x` with each aggregate issue of override_aggregates built again from its
# components, `before` being the components as built and `rels` the
# relationships as built: unchanged when the overrides changed nothing it
# names, removed when it names nothing more, and otherwise rebuilt.
override_rebuild_aggregates <- function(x, before, rels) {
  for (code in names(override_aggregates)) {
    at <- which(x$issues$code == code)
    if (length(at) != 1L) {
      next
    }
    spec <- override_aggregates[[code]]
    was <- spec$named(before, rels)
    now <- spec$named(x$components, x$relationships)
    if (identical(was, now)) {
      next
    }
    if (length(now) == 0L) {
      x$issues <- x$issues[-at, , drop = FALSE]
      next
    }
    message <- spec$sentence(now, x$issues$message[[at]])
    if (!is.na(message)) {
      x$issues$message[[at]] <- message
    }
  }
  x
}

# `x` with the embedded-not-installed issue saying which of the LinkingTo
# packages that are not installed have an asserted version: one issue for
# those still without a version, as built, and one, reworded, for those an
# override gave one. `before` is the components as built, row for row.
override_embedded <- function(x, before) {
  at <- which(x$issues$code == "embedded-not-installed")
  if (length(at) != 1L) {
    return(x)
  }
  issue <- x$issues[at, , drop = FALSE]
  where <- regmatches(issue$message, regexec(
    " through LinkingTo, but (?:is|are) not (.+), so (?:its version is|their versions are) unknown\\.$",
    issue$message
  ))[[1L]]
  if (length(where) != 2L) {
    return(x)
  }
  comps <- x$components
  absent <- grepl("#embedded/", before$ref, fixed = TRUE) & is.na(before$version)
  asserted <- absent & !is.na(comps$version)
  sentence <- function(comps, hit, asserted = FALSE) {
    parent <- match(comps$parent_ref[hit], comps$ref)
    embedded_not_installed_sentence(
      comps$name[hit], pkg_label(comps$name[parent], comps$version[parent]), where[[2L]], asserted
    )
  }
  messages <- c(
    if (any(absent & !asserted)) sentence(comps, absent & !asserted),
    if (any(asserted)) sentence(comps, asserted, asserted = TRUE)
  )
  # Unchanged when the overrides changed nothing it names.
  if (!any(absent) || identical(messages, sentence(before, absent))) {
    return(x)
  }
  rows <- issue[rep(1L, length(messages)), , drop = FALSE]
  rows$message <- messages
  x$issues <- rbind(x$issues[seq_len(at - 1L), , drop = FALSE], rows, x$issues[-seq_len(at), , drop = FALSE])
  x
}

# `x` with the nix-not-in-snapshot issue saying which of the packages that
# the CRAN snapshot lacks have an asserted version: the issue as built for
# those still without a version, removed when none is left, and one,
# reworded as info, for those an override gave one, which are still not in
# the snapshot. `before` is the components as built, row for row. The issue
# names R packages, as an and list; an issue whose names cannot be read
# back from it is left as it is.
override_nix_snapshot <- function(x, before) {
  at <- which(x$issues$code == "nix-not-in-snapshot")
  if (length(at) != 1L) {
    return(x)
  }
  issue <- x$issues[at, , drop = FALSE]
  parts <- regmatches(issue$message, regexec(
    paste0(
      "^[0-9]+ packages? that (.+) needs? (?:is|are) not in the CRAN snapshot sbom read \\((.+)\\), ",
      "so (?:its version is|their versions are) unknown\\.$"
    ),
    issue$message
  ))[[1L]]
  if (length(parts) != 3L) {
    return(x)
  }
  file <- parts[[2L]]
  names <- strsplit(sub(" and ([^ ]+)$", ", \\1", parts[[3L]]), ", ", fixed = TRUE)[[1L]]
  if (!identical(nix_not_in_snapshot_sentence(file, names), issue$message)) {
    return(x)
  }
  # The R packages the issue names, as built.
  named <- !before$is_root %in% TRUE & before$source_input %in% "default.nix" & is.na(before$parent_ref) &
    !before$ecosystem %in% system_ecosystems & before$name %in% names
  given <- named & is.na(before$version) & !is.na(x$components$version)
  if (!any(given)) {
    return(x)
  }
  asserted <- names[names %in% before$name[given]]
  # Those still without a version, and any the issue names that matches no
  # component, which stays as built.
  left <- names[names %in% before$name[named & is.na(x$components$version)] | !names %in% before$name[named]]
  messages <- c(
    if (length(left) > 0L) nix_not_in_snapshot_sentence(file, left),
    nix_not_in_snapshot_sentence(file, asserted, asserted = TRUE)
  )
  rows <- issue[rep(1L, length(messages)), , drop = FALSE]
  rows$message <- messages
  rows$severity[length(messages)] <- "info"
  x$issues <- rbind(x$issues[seq_len(at - 1L), , drop = FALSE], rows, x$issues[-seq_len(at), , drop = FALSE])
  x
}

# `x` without the fields-from-library issue of the components `at` whose
# license and maintainer it names are all asserted (`fields`, the fields
# asserted for each). When it also names their dependencies, which still
# come from the library, it names only them.
override_borrowed <- function(x, at, fields) {
  drop <- integer()
  for (i in seq_along(at)) {
    hit <- which(x$issues$code == "fields-from-library" & x$issues$ref == x$components$ref[at[[i]]])
    for (j in hit) {
      what <- sub("^The (.*?) of .*$", "\\1", x$issues$message[[j]])
      named <- c(license = "license_spdx", maintainer = "maintainer")
      named <- named[vapply(names(named), grepl, NA, what, fixed = TRUE)]
      if (length(named) == 0L || !all(named %in% fields[[i]])) {
        next
      }
      if (grepl("dependencies", what, fixed = TRUE)) {
        x$issues$message[[j]] <- sub("^The .*? of ", "The dependencies of ", x$issues$message[[j]])
        x$issues$field[[j]] <- "dependencies"
      } else {
        drop <- c(drop, j)
      }
    }
  }
  if (length(drop) > 0L) {
    x$issues <- x$issues[-drop, , drop = FALSE]
  }
  x
}

# Applies the overrides to `x` in order. An asserted version is exact, moves
# the component's purl to the new version unless a row asserts the purl
# itself, renames its package file and drops its hashes; an asserted version
# of R is also the version of the base packages. A component whose ref was
# its purl keeps its ref equal to its purl, whichever row changes the purl,
# and every reference to the ref moves with it; any other ref stays. An
# asserted CRAN purl sets the ecosystem. Each asserted field removes or
# rewords the issues it answers, and the aggregate issues about versions are
# built again from the components.
apply_overrides <- function(x, overrides) {
  if (is.null(overrides)) {
    return(x)
  }
  ov <- read_overrides(overrides)
  ov[] <- lapply(ov, enc2utf8_bytes)
  targets <- override_targets(ov, x$components)
  purl_rows <- targets[ov$field == "purl"]
  follows <- !is.na(x$components$purl) & x$components$ref == x$components$purl
  before <- x$components
  rels_before <- x$relationships
  moved <- FALSE
  for (i in seq_len(nrow(ov))) {
    row <- ov[i, ]
    field <- row$field
    at <- targets[[i]]
    ref <- x$components$ref[at]
    name <- x$components$name[at]
    old <- x$components[[field]][at]
    new <- row$value
    if (!is.na(old) && !identical(old, new)) {
      x$issues <- add_issue(
        x$issues, ref, field, "override-conflict",
        paste0(
          "The ", field, " of ", name, " was ", old, " as found and is ", new,
          " as asserted by ", row$asserted_by, "."
        ),
        severity = "info"
      )
    }
    x$components[[field]][at] <- new
    # An asserted version is the version, not a minimum, and the purl and the
    # package file follow it; the hashes, of what was found, do not. An
    # asserted CRAN package URL says where the package came from.
    if (field == "version") {
      x$components$version_is[at] <- "exact"
      if (!at %in% purl_rows) {
        x$components$purl[at] <- override_purl_version(x$components$purl[at], old, new)
      }
      x$components$package_file_name[at] <- override_file_name(
        x$components$package_file_name[at], name, old, new
      )
      if (!identical(old, new)) {
        x$components$hashes[[at]] <- empty_hashes()
      }
    }
    if (follows[[at]] && !identical(ref, x$components$purl[at])) {
      to <- x$components$purl[at]
      x <- override_move_ref(x, ref, to, i)
      ref <- to
      moved <- TRUE
    }
    if (field == "purl") {
      parsed <- purl_parse(new)
      if (parsed$valid %in% TRUE && tolower(parsed$type) %in% "cran") {
        x$components$ecosystem[at] <- if (purl_names_bioconductor(parsed$qualifiers)) "bioconductor" else "cran"
      }
    }
    if (field == "license_spdx") {
      note <- paste0("Asserted by ", row$asserted_by, ": ", row$reason, ".")
      old_comment <- x$components$license_comment[at]
      x$components$license_comment[at] <- if (is.na(old_comment)) note else paste(old_comment, note)
    }
    mine <- x$issues$ref == ref
    x$issues <- x$issues[!(mine & x$issues$code %in% override_answers[[field]]), , drop = FALSE]
    reworded <- override_reworded[[field]]
    for (code in names(reworded)) {
      x$issues <- override_reword(
        x$issues, which(x$issues$ref == ref & x$issues$code == code), paste(name, reworded[[code]])
      )
    }
    x$components$asserted[[at]] <- override_record(x$components$asserted[[at]], data.frame(
      field = field, value = new, asserted_by = row$asserted_by,
      reason = row$reason, stringsAsFactors = FALSE
    ))
  }
  # A dependency that is missing, given a version and a package URL. Named
  # as a dependency of several packages, it had an issue for each, which the
  # new sentence makes one.
  reworded <- integer()
  for (at in intersect(targets[ov$field == "version"], purl_rows)) {
    hit <- which(x$issues$ref == x$components$ref[at] & x$issues$code %in% names(override_reworded_together))
    x$issues <- override_reword(x$issues, hit, paste0(
      x$components$name[at], " is named as a dependency but ",
      unname(override_reworded_together[x$issues$code[hit]]), "; its version and purl are asserted by an override."
    ))
    reworded <- c(reworded, hit)
  }
  again <- duplicated(x$issues[c("ref", "code", "message")]) & seq_len(nrow(x$issues)) %in% reworded
  x$issues <- x$issues[!again, , drop = FALSE]
  # The base packages come with R, so they take its asserted version, with
  # the record of R's last version row, unless a row asserts their own.
  r_rows <- which(ov$field == "version" & x$components$ref[targets] == "R")
  if (length(r_rows) > 0L) {
    r_row <- ov[r_rows[[length(r_rows)]], ]
    base <- setdiff(which(x$components$parent_ref %in% "R"), targets[ov$field == "version"])
    x$components$version[base] <- r_row$value
    x$components$version_is[base] <- "exact"
    for (b in base) {
      x$components$asserted[[b]] <- override_record(x$components$asserted[[b]], data.frame(
        field = "version", value = r_row$value, asserted_by = r_row$asserted_by,
        reason = r_row$reason, stringsAsFactors = FALSE
      ))
    }
  }
  x <- override_rebuild_aggregates(x, before, rels_before)
  x <- override_embedded(x, before)
  x <- override_nix_snapshot(x, before)
  fields <- lapply(seq_len(nrow(x$components)), function(at) ov$field[targets == at])
  x <- override_borrowed(x, unique(targets), fields[unique(targets)])
  if (moved) {
    comps <- x$components[order(x$components$ref, method = "radix"), , drop = FALSE]
    rownames(comps) <- NULL
    x$components <- comps
    rels <- x$relationships
    rels <- rels[order(rels$from, rels$to, rels$field, method = "radix"), , drop = FALSE]
    rownames(rels) <- NULL
    x$relationships <- rels
  }
  rownames(x$issues) <- NULL
  x
}
