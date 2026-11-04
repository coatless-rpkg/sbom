# Code that a package carries inside it. A LinkingTo package is compiled into
# the package that names it, so each such pair becomes an embedded component
# nested under the package. A C or C++ library copied into a package's src/,
# or named in its COPYRIGHTS file or cph entries, becomes a vendored
# component, found by the rules in inst/extdata/vendored.csv (the columns are
# described at the top of that file). JavaScript and CSS libraries under www/,
# htmlwidgets/lib/ and lib/, or declared in htmlwidgets YAML, become npm
# components, found by inst/extdata/javascript.csv.

the <- new.env(parent = emptyenv())

embedded_ref <- function(parent_ref, name) {
  paste0(parent_ref, "#embedded/", name)
}

# Embedded, vendored and bundled JavaScript components are all found inside
# another package.
is_embedded_ref <- function(ref) {
  grepl("#embedded/", ref, fixed = TRUE) | grepl("#vendored/", ref, fixed = TRUE) |
    grepl("#js/", ref, fixed = TRUE)
}

# For each package P with a LinkingTo edge to L, one component "<P
# ref>#embedded/<L>" and a `contains` relationship from P. The LinkingTo edge
# stays. Ecosystem and purl are those of the installed L, if any; the version
# is the one `lookup` finds now, since nothing records the version used at
# build time. Returns list(components, relationships, issues), where the two
# tables hold only the new rows.
linkingto_components <- function(components, relationships, lookup) {
  edges <- relationships[relationships$field == "LinkingTo", , drop = FALSE]
  edges <- edges[!duplicated(edges[c("from", "to")]), , drop = FALSE]
  edges <- edges[edges$from != "R" & !edges$to %in% c("R", components$ref[!is.na(components$parent_ref)]), , drop = FALSE]
  rows <- list()
  for (i in seq_len(nrow(edges))) {
    parent <- components[match(edges$from[[i]], components$ref), , drop = FALSE]
    target <- components[match(edges$to[[i]], components$ref), , drop = FALSE]
    if (nrow(parent) == 0L || nrow(target) == 0L) {
      next
    }
    desc <- lookup$get(target$name)
    installed <- !is.null(desc)
    version <- if (installed) trimws(desc[["Version"]]) else NA_character_
    rows[[length(rows) + 1L]] <- component_row(
      ref = embedded_ref(parent$ref, target$name), name = target$name,
      version = version, version_is = if (installed) "exact" else NA_character_,
      type = "library", ecosystem = if (installed) target$ecosystem,
      scope = parent$scope, parent_ref = parent$ref,
      purl = if (installed) target$purl,
      description = paste0(
        "Compiled into ", parent$name, " from the headers of ", target$name,
        if (installed) paste0(" ", version),
        ", the version installed now; nothing records the version used at build time."
      ),
      evidence = "inferred", source_input = parent$source_input
    )
  }
  if (length(rows) == 0L) {
    return(list(
      components = components[0L, , drop = FALSE],
      relationships = empty_relationships(), issues = empty_issues()
    ))
  }
  new <- do.call(rbind, rows)
  new <- new[!duplicated(new$ref), , drop = FALSE]
  list(
    components = new,
    relationships = data.frame(
      from = new$parent_ref, to = new$ref, field = "contains",
      spec = NA_character_, evidence = "inferred", stringsAsFactors = FALSE
    ),
    issues = empty_issues()
  )
}

# The rules table, read once. Lines that start with "#" are comments.
vendored_rules <- function() {
  if (is.null(the$vendored_rules)) {
    path <- system.file("extdata", "vendored.csv", package = "sbom")
    lines <- readLines(path, encoding = "UTF-8", warn = FALSE)
    lines <- lines[!startsWith(lines, "#")]
    the$vendored_rules <- utils::read.csv(
      text = paste(lines, collapse = "\n"), colClasses = "character",
      na.strings = character(), stringsAsFactors = FALSE
    )
  }
  the$vendored_rules
}

# The dotted version a rule's regex finds in `text`, or NA. Capture groups are
# the parts; a part of digits loses its leading zeros.
vendored_version <- function(text, regex) {
  if (is.na(regex) || !nzchar(regex)) {
    return(NA_character_)
  }
  m <- regmatches(text, regexec(regex, text, perl = TRUE, useBytes = TRUE))[[1L]]
  if (length(m) < 2L || !all(nzchar(m[-1L]))) {
    return(NA_character_)
  }
  parts <- m[-1L]
  digits <- grepl("^[0-9]+$", parts)
  parts[digits] <- as.character(as.integer(parts[digits]))
  paste(parts, collapse = ".")
}

# At most `limit` bytes of a file as text (bytes, never evaluated), or NULL
# when the file is larger than `max_size`.
read_text_bounded <- function(path, limit = 65536L, max_size = 4 * 1024^2) {
  size <- file.size(path)
  if (is.na(size) || size > max_size) {
    return(NULL)
  }
  raw <- tryCatch(readBin(path, "raw", n = limit), error = function(e) raw())
  rawToChar(raw[raw != as.raw(0L)])
}

# Whole-word, case-insensitive: is any of `words` in `text`?
names_word <- function(text, words) {
  words <- gsub("([][{}()+*^$|\\\\?.])", "\\\\\\1", words)
  pattern <- paste0("(?<![A-Za-z0-9_])(", paste(words, collapse = "|"), ")(?![A-Za-z0-9_])")
  grepl(pattern, text, perl = TRUE, ignore.case = TRUE, useBytes = TRUE)
}

# Vendored libraries of the package in `pkg_dir`, a source folder (`installed`
# FALSE: src/ is walked) or an installed one (`installed` TRUE: src/ is
# gone). Either way, COPYRIGHTS and the cph names of Authors@R are searched
# for the names in the rules. `parent` is the package's component row. Returns
# list(components, relationships, issues, limited).
vendored_components <- function(pkg_dir, parent, installed = FALSE, desc = NULL) {
  rules <- vendored_rules()
  found <- list()

  if (!installed && dir.exists(file.path(pkg_dir, "src"))) {
    src <- file.path(pkg_dir, "src")
    dirs <- c(".", list.dirs(src, full.names = FALSE, recursive = TRUE))
    files <- list.files(src, recursive = TRUE, all.files = TRUE, include.dirs = FALSE)
    files <- files[order(files, method = "radix")]
    base <- basename(files)
    dir_names <- basename(dirs[dirs != "."])
    for (i in seq_len(nrow(rules))) {
      rule <- rules[i, ]
      in_dir <- any(grepl(rule$dir_regex, dir_names, perl = TRUE))
      version <- NA_character_
      file <- NA_character_
      for (f in files[grepl(rule$version_file_regex, base, perl = TRUE)]) {
        if (!nzchar(rule$version_regex)) {
          in_dir <- TRUE
          break
        }
        text <- read_text_bounded(file.path(src, f))
        v <- if (!is.null(text)) vendored_version(text, rule$version_regex) else NA_character_
        if (!is.na(v)) {
          version <- v
          file <- paste0("src/", f)
          break
        }
      }
      if (in_dir || !is.na(version)) {
        found[[rule$name]] <- list(version = version, file = file, how = "src")
      }
    }
  }

  # COPYRIGHTS and cph names: the name alone, so no version.
  copyrights <- file.path(pkg_dir, if (installed) "COPYRIGHTS" else file.path("inst", "COPYRIGHTS"))
  text <- if (file.exists(copyrights)) read_text_bounded(copyrights, limit = 262144L) else NULL
  if (is.null(desc)) {
    desc <- tryCatch(read_description(pkg_dir), error = function(e) NULL)
  }
  cph <- character()
  if (!is.null(desc)) {
    people <- parse_authors(desc_field(desc, "Authors@R"))
    if (!is.null(people)) {
      has_cph <- !is.na(people$roles) & grepl("\\bcph\\b", people$roles)
      cph <- people$name[has_cph & !is.na(people$name)]
    }
  }
  for (i in seq_len(nrow(rules))) {
    rule <- rules[i, ]
    if (!is.null(found[[rule$name]])) {
      next
    }
    words <- c(rule$name, strsplit(rule$aliases, ";", fixed = TRUE)[[1L]])
    words <- unique(trimws(words[nzchar(words)]))
    if (!is.null(text) && names_word(text, words)) {
      found[[rule$name]] <- list(version = NA_character_, file = NA_character_, how = "copyrights")
    } else if (length(cph) > 0L && any(names_word(cph, words))) {
      found[[rule$name]] <- list(version = NA_character_, file = NA_character_, how = "cph")
    }
  }

  rows <- list()
  for (name in sort(as.character(names(found)), method = "radix")) {
    rule <- rules[rules$name == name, ]
    hit <- found[[name]]
    known <- !is.na(hit$version)
    has_license <- nzchar(rule$license)
    rows[[length(rows) + 1L]] <- component_row(
      ref = paste0(parent$ref, "#vendored/", name), name = name,
      version = if (known) hit$version, version_is = if (known) "exact",
      type = "library", ecosystem = "vendored", scope = parent$scope,
      parent_ref = parent$ref,
      purl = if (known) sub("{version}", hit$version, rule$purl, fixed = TRUE),
      license_spdx = if (has_license) rule$license,
      license_comment = if (has_license) paste0(
        "The licence is the usual one for ", name, "; sbom did not read the ",
        "vendored files' own notices."
      ),
      homepage = if (nzchar(rule$homepage)) rule$homepage,
      description = switch(hit$how,
        src = paste0(
          "Bundled in ", parent$name, " as source code",
          if (known) paste0(", version ", hit$version, " read from ", hit$file), "."
        ),
        copyrights = paste0("Named in ", parent$name, "'s COPYRIGHTS file."),
        cph = paste0("Named as a copyright holder in ", parent$name, "'s Authors@R.")
      ),
      evidence = "inferred", source_input = parent$source_input
    )
  }

  # `limited` is the label of a package whose compiled code could not be
  # looked into; detect_bundled() reports those together.
  limited <- NA_character_
  if (length(rows) == 0L) {
    if (installed && dir.exists(file.path(pkg_dir, "libs"))) {
      limited <- pkg_label(parent$name, parent$version)
    }
    return(list(
      components = empty_components(), relationships = empty_relationships(),
      issues = empty_issues(), limited = limited
    ))
  }
  new <- do.call(rbind, rows)
  list(
    components = new,
    relationships = data.frame(
      from = new$parent_ref, to = new$ref, field = "contains",
      spec = NA_character_, evidence = "inferred", stringsAsFactors = FALSE
    ),
    issues = empty_issues(), limited = limited
  )
}

# Mockable, so tests can simulate a machine without yaml.
has_yaml <- function() {
  requireNamespace("yaml", quietly = TRUE)
}

# The rules table for JavaScript and CSS libraries, read once. Lines that
# start with "#" are comments.
javascript_rules <- function() {
  if (is.null(the$javascript_rules)) {
    path <- system.file("extdata", "javascript.csv", package = "sbom")
    lines <- readLines(path, encoding = "UTF-8", warn = FALSE)
    lines <- lines[!startsWith(lines, "#")]
    the$javascript_rules <- utils::read.csv(
      text = paste(lines, collapse = "\n"), colClasses = "character",
      na.strings = character(), stringsAsFactors = FALSE
    )
  }
  the$javascript_rules
}

# pkg:npm/<name>@<version>, with the "@" of a scope encoded.
npm_purl <- function(name, version) {
  parts <- strsplit(name, "/", fixed = TRUE)[[1L]]
  parts <- vapply(parts, utils::URLencode, "", reserved = TRUE, USE.NAMES = FALSE)
  paste0("pkg:npm/", paste(parts, collapse = "/"), "@", version)
}

# The dependencies declared in one htmlwidgets YAML file, as a list of
# list(name, version, placeholder), where a placeholder such as "0.0.0" is
# the text of a version that is not one (and `version` is then NA). Versions stay text ("1.10" is not 1.1). Returns NULL
# when the file cannot be read.
read_widget_yaml <- function(path) {
  keep <- function(x) x
  doc <- tryCatch(
    {
      if (isTRUE(file.size(path) > 1024^2)) stop("too large")
      # An empty file is a document with nothing declared.
      list(yaml::read_yaml(
        path, eval.expr = FALSE, readLines.warn = FALSE,
        handlers = list(int = keep, `float#fix` = keep, `float#exp` = keep)
      ))
    },
    error = function(e) NULL
  )
  if (is.null(doc)) {
    return(NULL)
  }
  doc <- doc[[1L]]
  deps <- if (is.list(doc)) doc[["dependencies"]] else NULL
  out <- list()
  for (dep in if (is.list(deps)) deps else list()) {
    name <- if (is.list(dep)) dep[["name"]] else NULL
    if (!is.character(name) || length(name) != 1L || is.na(name) || !nzchar(trimws(name))) {
      next
    }
    version <- dep[["version"]]
    version <- if (is.character(version) && length(version) == 1L && !is.na(version) &&
      nzchar(trimws(version))) trimws(version) else NA_character_
    # 0.0.0 is a placeholder some widgets declare, not a release.
    placeholder <- NA_character_
    if (!is.na(version) && grepl("^0+(\\.0+)*$", version)) {
      placeholder <- version
      version <- NA_character_
    }
    out[[length(out) + 1L]] <- list(
      name = trimws(name), version = version, placeholder = placeholder
    )
  }
  out
}

# JavaScript and CSS libraries bundled in the package in `pkg_dir`, a source
# folder (`installed` FALSE: under inst/) or an installed one. `parent` is the
# package's component row. A library declared in htmlwidgets YAML is declared;
# one found by the header comment of a .js or .css file is inferred; the
# declared one wins when both are found. Returns list(components,
# relationships, issues, libraries), where `libraries` are labels of the
# components, for the one note about their licences.
javascript_components <- function(pkg_dir, parent, installed = FALSE, max_files = 5000L) {
  base <- if (installed) pkg_dir else file.path(pkg_dir, "inst")
  rules <- javascript_rules()
  label <- pkg_label(parent$name, parent$version)
  issues <- empty_issues()
  found <- list()

  # Record a finding. A declared one replaces an inferred one of its name
  # and a different inferred version is reported. Two inferred versions of a
  # name (a package may carry several, as bslib does for Bootstrap) are
  # separate entries, each with its own ref.
  note <- function(name, version, evidence, file, npm, placeholder = NA_character_) {
    key <- tolower(name)
    if (evidence == "declared") {
      found[[key]] <<- list(
        name = name, version = version, evidence = evidence, file = file,
        npm = npm, placeholder = placeholder, header_file = NA_character_
      )
      return(invisible())
    }
    declared <- found[[key]]
    if (!is.null(declared) && declared$evidence == "declared") {
      if (is.na(declared$version)) {
        # The first header version fills in a declared library with none.
        found[[key]]$version <<- version
        found[[key]]$header_file <<- file
        return(invisible())
      }
      if (!is.na(declared$version) && declared$version != version) {
        issues <<- add_issue(
          issues, parent$ref, "version", "javascript-version-differs",
          paste0(
            label, " declares ", name, " ", declared$version, " in ", declared$file,
            " but ", file, " has ", version, "; sbom recorded ", declared$version, "."
          ),
          severity = "warning"
        )
      }
      return(invisible())
    }
    same <- vapply(
      found, function(h) tolower(h$name) == key && identical(h$version, version), NA
    )
    if (any(same)) {
      return(invisible())
    }
    suffix <- if (is.null(found[[key]])) "" else paste0("@", version)
    key <- paste0(key, suffix)
    if (is.null(found[[key]])) {
      found[[key]] <<- list(
        name = name, version = version, evidence = evidence, file = file,
        npm = npm, placeholder = NA_character_, header_file = NA_character_
      )
    }
    invisible()
  }
  # Only a name that a rule knows is an npm package; the name in htmlwidgets
  # YAML is the name of an R html dependency, which need not exist on npm.
  rule_npm <- function(name) {
    npm <- rules$npm[tolower(rules$name) == tolower(name)]
    if (length(npm) == 1L) npm else ""
  }

  # htmlwidgets YAML.
  yaml_dir <- file.path(base, "htmlwidgets")
  yamls <- if (dir.exists(yaml_dir)) {
    list.files(yaml_dir, pattern = "\\.ya?ml$", ignore.case = TRUE)
  } else {
    character()
  }
  yamls <- yamls[order(yamls, method = "radix")]
  for (f in yamls) {
    rel <- paste0(if (installed) "" else "inst/", "htmlwidgets/", f)
    if (!has_yaml()) {
      issues <- add_issue(
        issues, parent$ref, "embedded", "htmlwidgets-not-read",
        paste0(
          label, " declares JavaScript dependencies in ", rel,
          ", which sbom could not read because the yaml package is not installed."
        ),
        severity = "info"
      )
      next
    }
    deps <- read_widget_yaml(file.path(yaml_dir, f))
    if (is.null(deps)) {
      issues <- add_issue(
        issues, parent$ref, "embedded", "htmlwidgets-unreadable",
        paste0("sbom could not read ", rel, " in ", label, ", so the JavaScript it declares is not recorded."),
        severity = "info"
      )
      next
    }
    for (dep in deps) {
      note(dep$name, dep$version, "declared", rel, rule_npm(dep$name), dep$placeholder)
    }
  }

  # Header comments. Candidates are the .js and .css files whose name a rule
  # matches, found within 6 levels of each folder, without following
  # symlinked folders; at most `max_files` are read.
  roots <- file.path(base, c("www", file.path("htmlwidgets", "lib"), "lib"))
  name_regex <- paste0("(", paste(rules$file_regex, collapse = ")|("), ")")
  files <- character()
  truncated <- FALSE
  walk <- function(dir, depth) {
    entries <- list.files(dir, all.files = FALSE, no.. = TRUE)
    entries <- entries[order(entries, method = "radix")]
    paths <- file.path(dir, entries)
    is_dir <- dir.exists(paths)
    for (path in paths[!is_dir]) {
      name <- basename(path)
      if (grepl("\\.(js|css)$", name, ignore.case = TRUE) && grepl(name_regex, name, perl = TRUE)) {
        if (length(files) >= max_files) {
          truncated <<- TRUE
          return(invisible())
        }
        files[[length(files) + 1L]] <<- path
      }
    }
    if (depth < 6L) {
      for (path in paths[is_dir]) {
        if (!nzchar(Sys.readlink(path)) && !truncated) {
          walk(path, depth + 1L)
        }
      }
    }
    invisible()
  }
  for (root in roots[dir.exists(roots)]) {
    if (!nzchar(Sys.readlink(root))) {
      walk(root, 0L)
    }
  }
  if (truncated) {
    issues <- add_issue(
      issues, parent$ref, "embedded", "javascript-scan-truncated",
      paste0(
        "sbom looked at the first ", max_files, " candidate JavaScript and CSS files in ",
        label, " and skipped the rest."
      ),
      severity = "info"
    )
  }
  for (path in files) {
    name <- basename(path)
    hits <- which(vapply(rules$file_regex, grepl, NA, x = name, perl = TRUE, USE.NAMES = FALSE))
    if (length(hits) == 0L) {
      next
    }
    text <- read_text_bounded(path, limit = 2048L, max_size = Inf)
    if (is.null(text)) {
      next
    }
    rel <- substring(path, nchar(pkg_dir) + 2L)
    for (i in hits) {
      version <- vendored_version(text, rules$header_regex[[i]])
      if (!is.na(version)) {
        note(rules$name[[i]], version, "inferred", rel, rules$npm[[i]])
        break
      }
    }
  }

  if (length(found) == 0L) {
    return(list(
      components = empty_components(), relationships = empty_relationships(),
      issues = issues, libraries = character()
    ))
  }
  for (hit in found) {
    if (hit$evidence == "declared" && is.na(hit$version)) {
      issues <- add_issue(
        issues, paste0(parent$ref, "#js/", hit$name), "version", "javascript-version-missing",
        paste0(
          label, " declares ", hit$name, " without a usable version",
          if (!is.na(hit$placeholder)) paste0(" (it gives ", hit$placeholder, ")"), "."
        ),
        severity = "info"
      )
    }
  }
  rows <- lapply(found, function(hit) {
    known <- !is.na(hit$version)
    component_row(
      ref = paste0(parent$ref, "#js/", hit$name, if (known) paste0("@", hit$version)),
      name = hit$name,
      version = if (known) hit$version, version_is = if (known) "exact",
      type = "library", ecosystem = "npm", scope = parent$scope,
      parent_ref = parent$ref,
      purl = if (known && nzchar(hit$npm)) npm_purl(hit$npm, hit$version),
      description = if (hit$evidence == "declared") {
        paste0(
          "Declared in ", hit$file, ".",
          if (!is.na(hit$header_file)) paste0(" The version comes from the header of ", hit$header_file, ".")
        )
      } else {
        paste0(
          "Found as ", hit$file, " in ", parent$name,
          "; the version comes from its header comment."
        )
      },
      evidence = hit$evidence, source_input = parent$source_input
    )
  })
  new <- do.call(rbind, unname(rows))
  new <- new[order(new$ref, method = "radix"), , drop = FALSE]
  rownames(new) <- NULL
  list(
    components = new,
    relationships = data.frame(
      from = new$parent_ref, to = new$ref, field = "contains",
      spec = NA_character_, evidence = new$evidence, stringsAsFactors = FALSE
    ),
    issues = issues, libraries = pkg_label(new$name, new$version)
  )
}

# The folder of the installed copy of `name` in `lib` when its version is
# `version`, else NULL.
installed_dir <- function(name, version, lib) {
  if (is.na(version)) {
    return(NULL)
  }
  cand <- library_candidates(lib)
  for (path in cand$path[cand$package == name]) {
    desc <- read_usable_description(file.path(path, name))
    if (!is.null(desc)) {
      return(if (identical(trimws(desc[["Version"]]), version)) file.path(path, name))
    }
  }
  NULL
}

# vendored_components() and javascript_components() for every package
# component in `comps` that has a folder: the source folder for the root, the
# installed copy for the others.
detect_bundled <- function(comps, root_ref, source_dir, root_desc, lookup, lib) {
  out <- list()
  inspect <- function(dir, row, installed, desc = NULL) {
    out[[length(out) + 1L]] <<- vendored_components(dir, row, installed, desc)
    out[[length(out) + 1L]] <<- javascript_components(dir, row, installed)
  }
  for (i in seq_len(nrow(comps))) {
    row <- comps[i, , drop = FALSE]
    if (!is.na(row$parent_ref) || row$type != "library" || row$ecosystem %in% c("r", "base-r")) {
      next
    }
    if (row$ref == root_ref) {
      if (is.null(source_dir)) {
        next
      }
      installed <- !dir.exists(file.path(source_dir, "src")) &&
        dir.exists(file.path(source_dir, "Meta"))
      inspect(source_dir, row, installed, root_desc)
    } else if (is.function(lookup$dir)) {
      # A library lookup has read this package's DESCRIPTION already.
      dir <- lookup$dir(row$name)
      if (!is.null(dir)) {
        inspect(dir, row, TRUE, lookup$get(row$name))
      }
    } else {
      dir <- installed_dir(row$name, row$version, lib)
      if (!is.null(dir)) {
        inspect(dir, row, TRUE)
      }
    }
  }
  if (length(out) == 0L) {
    return(list(components = empty_components(), relationships = empty_relationships(), issues = empty_issues()))
  }
  issues <- do.call(rbind, c(list(empty_issues()), lapply(out, `[[`, "issues")))
  limited <- unlist(lapply(out, `[[`, "limited"))
  limited <- sort(limited[!is.na(limited)], method = "radix")
  if (length(limited) > 0L) {
    n <- length(limited)
    issues <- add_issue(
      issues, root_ref, "embedded", "compiled-code-limited",
      paste0(
        n, if (n == 1L) " package contains" else " packages contain",
        " compiled code but ", if (n == 1L) "names" else "name",
        " no bundled library in a COPYRIGHTS file or Authors@R, so sbom could not look inside ",
        if (n == 1L) "it" else "them", ": ", paste(limited, collapse = ", "), "."
      ),
      severity = "info"
    )
  }
  libraries <- sort(unique(unlist(lapply(out, `[[`, "libraries"))), method = "radix")
  if (length(libraries) > 0L) {
    issues <- add_issue(
      issues, root_ref, "license", "javascript-license-not-read",
      paste0(
        "sbom does not read the licences of bundled JavaScript, so these have none recorded: ",
        paste(libraries, collapse = ", "), "."
      ),
      severity = "info"
    )
  }
  list(
    components = do.call(rbind, lapply(out, `[[`, "components")),
    relationships = do.call(rbind, lapply(out, `[[`, "relationships")),
    issues = issues
  )
}
