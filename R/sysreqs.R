# Declared system requirements. The SystemRequirements text of a package is
# matched against the rules in pak, which name the system libraries behind
# free text such as "libcurl (>= 7.73): libcurl-devel (rpm)". What pak cannot
# map, such as "C++17" or "GNU make", gets no component and stays as written
# in the package's `system_requirements`. The libraries that packages link
# are found in linked-libraries.R.

# pak's rules only match for a platform, and on macOS, Windows or an unknown
# system an NA platform matches nothing at all. sbom wants the library names,
# which are the same on every platform, so it asks as this reference platform
# and discards the operating system packages that come with it.
sysreqs_reference_platform <- "ubuntu-22.04"

# The ecosystems of components that come from the operating system rather
# than from R: declared or linked libraries and programs, and the packages of
# a system package manager.
system_ecosystems <- c("system", "deb", "rpm", "nix")

# The exported function `name` of pak, or NULL when pak is not installed.
# Tests replace it, so that no test reaches pak.
pak_function <- function(name) {
  if (!requireNamespace("pak", quietly = TRUE)) {
    return(NULL)
  }
  getExportedValue("pak", name)
}

# Calls pak's function `name` with pak's update of its rules turned off. pak
# runs in a subprocess that receives the `pkg.*` options, and with
# `pkg.sysreqs_db_update` FALSE it answers from the rules it has cached or
# ships, so it never reaches the network or rewrites its cache. NULL when pak
# is not installed or the call fails.
#
# The subprocess starts with the first call and is killed when R exits, so it
# never removes its own temporary folder. TMPDIR is the session's temporary
# folder during the call, so that the subprocess makes its folder there and R
# removes it with the session's. TMPDIR is put back after, and a subprocess
# that pak started earlier is left as it is.
pak_call <- function(name, ...) {
  fun <- pak_function(name)
  if (is.null(fun)) {
    return(NULL)
  }
  op <- options(pkg.sysreqs_db_update = FALSE)
  on.exit(options(op), add = TRUE)
  tryCatch(in_session_tmpdir(fun(...)), error = function(e) NULL)
}

# The value of `expr`, evaluated with TMPDIR set to this session's tempdir(),
# so that a subprocess pak starts leaves its temporary folder where R removes
# it at the end of the session.
in_session_tmpdir <- function(expr) {
  old_tmpdir <- Sys.getenv("TMPDIR", unset = NA)
  on.exit(if (is.na(old_tmpdir)) Sys.unsetenv("TMPDIR") else Sys.setenv(TMPDIR = old_tmpdir))
  Sys.setenv(TMPDIR = tempdir())
  expr
}

# For each text in `spec`, a data frame of the sysreq names pak finds in it
# and the operating system packages that provide them on `platform`. The
# packages are empty when `platform` is NA. NULL when pak is not installed or
# fails.
sysreqs_match <- function(spec, platform) {
  if (length(spec) == 0L) {
    return(list())
  }
  known <- length(platform) == 1L && !is.na(platform)
  found <- pak_call(
    "sysreqs_db_match", spec,
    sysreqs_platform = if (known) platform else sysreqs_reference_platform
  )
  if (!is.list(found) || length(found) != length(spec)) {
    return(NULL)
  }
  lapply(found, function(d) {
    n <- nrow(d)
    data.frame(
      sysreq = as.character(d$sysreq),
      packages = I(if (known && n > 0L) lapply(d$packages, as.character) else rep(list(character()), n)),
      stringsAsFactors = FALSE
    )
  })
}

# The platform to ask pak about: the option, else the running Linux
# distribution, else NA.
sysreqs_platform <- function() {
  opt <- getOption("sbom.sysreqs_platform")
  if (is.character(opt) && length(opt) == 1L && !is.na(opt) && nzchar(opt)) {
    return(opt)
  }
  os <- sys_os_release()
  id <- os[["id"]]
  version <- os[["version_id"]]
  if (is.character(id) && length(id) == 1L && nzchar(id)) {
    return(if (is.character(version) && length(version) == 1L && nzchar(version)) paste0(id, "-", version) else id)
  }
  NA_character_
}

# Whether pak has rules for `platform`: TRUE, FALSE, or NA when pak cannot
# say (for example when it is not installed).
sysreqs_platform_supported <- function(platform) {
  ok <- pak_call("sysreqs_is_supported", platform)
  if (isTRUE(ok) || isFALSE(ok)) ok else NA
}

# pak's patterns for each sysreq name, as a named list of regular expressions
# (matched as pak matches them: extended, ignoring case), or NULL when pak
# cannot give them.
sysreqs_rule_patterns <- function() {
  db <- pak_call("sysreqs_db_list", sysreqs_platform = sysreqs_reference_platform)
  if (!is.data.frame(db) || !all(c("name", "patterns") %in% names(db))) {
    return(NULL)
  }
  stats::setNames(lapply(db$patterns, as.character), as.character(db$name))
}

# Sysreqs that are programs used to build a package. They are programs, an
# SPDX 3 document scopes the requirement as "build", and a package that does
# not link one has no static copy of it.
sysreq_build_tools <- c(
  "gnumake", "make", "cmake", "pkg-config", "automake", "autoconf", "libtool",
  "patch", "rust", "cargo", "rustc", "protobuf-compiler"
)

# Whether each `name` is one of the build tools in sysreq_build_tools.
is_build_tool <- function(name) {
  name %in% sysreq_build_tools
}

# Sysreqs that are programs rather than libraries. They become "application"
# components. These are the build tools, the rules in pak's database that
# install a program (tests/testthat/fixtures/pak/tool-rules.txt lists them),
# and older names that are programs but are not pak rules.
sysreq_programs <- sort(unique(c(
  sysreq_build_tools,
  "blender", "bowtie2", "chrome", "dcraw", "dotnet10", "dotnet8", "dotnet9",
  "exiftool", "ggobi", "git", "haveged", "imagej", "java", "latex", "mongodb",
  "mysql", "osmium-tool", "pandoc", "pandoc-citeproc", "pari-gp", "perl",
  "python", "python3", "qgis", "saga", "saint", "swftools", "wget",
  "chromium", "ghostscript", "nodejs", "qpdf", "quarto", "texlive"
)), method = "radix")

# Other ways a text writes a sysreq.
sysreq_aliases <- c(gnumake = "GNU make", nodejs = "node\\.js")

# The parts of `text` between commas and semicolons that are not inside
# parentheses.
requirement_fragments <- function(text) {
  chars <- strsplit(text, "")[[1]]
  parts <- character()
  current <- character()
  depth <- 0L
  for (ch in chars) {
    if (ch == "(") {
      depth <- depth + 1L
    } else if (ch == ")") {
      depth <- max(depth - 1L, 0L)
    }
    if (depth == 0L && ch %in% c(",", ";")) {
      parts <- c(parts, paste(current, collapse = ""))
      current <- character()
    } else {
      current <- c(current, ch)
    }
  }
  parts <- trimws(c(parts, paste(current, collapse = "")))
  parts[nzchar(parts)]
}

# A pattern for `sysreq`, an alias of it, or one of `words` (literal text) as
# a whole word: no letter, digit, "_", ".", "+" or "-" comes before it and no
# letter, digit or "_" after it, so "git" is not found in "libgit2" or
# "GitHub".
sysreq_pattern <- function(sysreq, words = character()) {
  escape <- function(x) gsub("([][{}()+*^$|\\\\?.])", "\\\\\\1", x)
  names <- c(escape(sysreq), unname(sysreq_aliases[sysreq]), escape(words))
  paste0("(?i)(?<![A-Za-z0-9_.+-])(?:", paste(names[!is.na(names)], collapse = "|"), ")(?![A-Za-z0-9_])")
}

# The text in `parts` that the first of pak's `patterns` matches, for each
# part, or NA.
rule_match <- function(parts, patterns) {
  vapply(parts, function(p) {
    for (r in patterns) {
      hit <- tryCatch(
        regmatches(p, regexpr(r, p, ignore.case = TRUE)),
        error = function(e) character(), warning = function(w) character()
      )
      if (length(hit) == 1L && nzchar(hit)) {
        return(hit)
      }
    }
    NA_character_
  }, "", USE.NAMES = FALSE)
}

# The fragment of `text` that names `sysreq`, by its name or else by one of
# pak's `patterns` for it, or NA when none does.
sysreq_fragment <- function(text, sysreq, patterns = character()) {
  parts <- requirement_fragments(text)
  hit <- parts[grepl(sysreq_pattern(sysreq), parts, perl = TRUE)]
  if (length(hit) == 0L) {
    hit <- parts[!is.na(rule_match(parts, patterns))]
  }
  if (length(hit) > 0L) hit[[1]] else NA_character_
}

# The version in "name (>= x)", or "name (>= x, optional)", for `sysreq` or
# one of `words`, or NA.
sysreq_minimum <- function(text, sysreq, words = character()) {
  m <- regmatches(text, regexec(
    paste0(sysreq_pattern(sysreq, words), "[[:alnum:]_.+-]*\\s*\\(\\s*>=\\s*([0-9][0-9.]*)[^)]*\\)"),
    text, perl = TRUE
  ))[[1]]
  if (length(m) == 2L) m[[2]] else NA_character_
}

# The highest of some versions, or NA.
highest_version <- function(versions) {
  versions <- versions[!is.na(versions)]
  if (length(versions) == 0L) {
    return(NA_character_)
  }
  parsed <- lapply(versions, function(v) tryCatch(numeric_version(v), error = function(e) NULL))
  ok <- !vapply(parsed, is.null, NA)
  if (!any(ok)) {
    return(NA_character_)
  }
  versions <- versions[ok]
  versions[order(do.call(c, parsed[ok]))][[length(versions)]]
}

# For each package component in `components` with `system_requirements`, one
# "system" component per sysreq that pak finds, shared by every package that
# needs it (optional when every fragment that states it says "optional" or its
# package is optional), and a "system_requirement" relationship from the package. Returns
# list(components, relationships, issues): the components are all of them,
# sorted by ref, and the other two hold only the new rows.
declared_system_requirements <- function(components) {
  none <- function() {
    list(
      components = components, relationships = empty_relationships(),
      issues = empty_issues()
    )
  }
  has <- !is.na(components$system_requirements) & is.na(components$parent_ref)
  if (!any(has)) {
    return(none())
  }
  pkgs <- components[has, , drop = FALSE]
  texts <- gsub("\\s+", " ", trimws(pkgs$system_requirements))
  root <- components$ref[components$is_root %in% TRUE][1L]
  platform <- sysreqs_platform()
  # pak matches only on a platform it has rules for. On any other, such as
  # Oracle Linux, every result would be empty, so the names come from the
  # reference platform's rules instead, without its operating system packages.
  unknown_platform <- !is.na(platform) && isFALSE(sysreqs_platform_supported(platform))
  matched <- sysreqs_match(unique(texts), if (unknown_platform) NA_character_ else platform)
  if (is.null(matched) || length(matched) != length(unique(texts))) {
    n <- nrow(pkgs)
    out <- none()
    out$issues <- add_issue(
      out$issues, root, "system_requirements", "sysreqs-unmapped",
      paste0(
        "The system requirements of ", n, if (n == 1L) " package are" else " packages are",
        " recorded only as written, because sbom could not map them to system libraries. ",
        "The text is in each package's system-requirements property in CycloneDX, ",
        "its comment in SPDX, the system_requirements column of the CSV and, ",
        "for the root, the SWID tag."
      ),
      severity = "info"
    )
    return(out)
  }
  issues <- empty_issues()
  if (unknown_platform) {
    issues <- add_issue(
      issues, root, "system_requirements", "sysreqs-platform-unknown",
      paste0(
        "sbom matched system requirements with Ubuntu 22.04's rules, because pak has no rules for ",
        platform, "; the OS package names are omitted."
      ),
      severity = "info"
    )
  }
  matched <- stats::setNames(matched, unique(texts))
  rels <- list()
  needs <- list()
  # pak's patterns, read the first time a text does not name a sysreq itself,
  # as "ICU4C" names libicu.
  rule_patterns <- NULL
  for (i in seq_len(nrow(pkgs))) {
    hit <- matched[[texts[[i]]]]
    for (j in seq_len(nrow(hit))) {
      sysreq <- hit$sysreq[[j]]
      ref <- paste0("system/", sysreq)
      frag <- sysreq_fragment(texts[[i]], sysreq)
      word <- character()
      if (is.na(frag)) {
        if (is.null(rule_patterns)) {
          rule_patterns <- c(list(), sysreqs_rule_patterns())
        }
        patterns <- as.character(unlist(rule_patterns[[sysreq]]))
        frag <- sysreq_fragment(texts[[i]], sysreq, patterns)
        # The text the pattern matched, such as "ICU4C", names the minimum.
        if (!is.na(frag)) word <- rule_match(frag, patterns)
      }
      own <- if (is.na(frag)) texts[[i]] else frag
      rels[[length(rels) + 1L]] <- data.frame(
        from = pkgs$ref[[i]], to = ref, field = "system_requirement",
        spec = own, evidence = "declared",
        stringsAsFactors = FALSE
      )
      needs[[ref]] <- c(needs[[ref]], list(list(
        name = sysreq, package = pkgs$name[[i]],
        scope = if (!is.na(frag) && grepl("optional", frag, ignore.case = TRUE)) "optional" else pkgs$scope[[i]],
        source_input = pkgs$source_input[[i]],
        version = sysreq_minimum(own, sysreq, word),
        os = if (unknown_platform) character() else as.character(unlist(hit$packages[[j]]))
      )))
    }
  }
  if (length(rels) == 0L) {
    out <- none()
    out$issues <- issues
    return(out)
  }
  rows <- lapply(sort(names(needs), method = "radix"), function(ref) {
    n <- needs[[ref]]
    by <- sort(unique(vapply(n, `[[`, "", "package")), method = "radix")
    os <- sort(unique(unlist(lapply(n, `[[`, "os"))), method = "radix")
    version <- highest_version(vapply(n, `[[`, "", "version"))
    required <- any(vapply(n, function(e) identical(e$scope, "required"), NA))
    program <- n[[1]]$name %in% sysreq_programs
    component_row(
      ref = ref, name = n[[1]]$name,
      version = if (!is.na(version)) version, version_is = if (!is.na(version)) "minimum",
      type = if (program) "application" else "library", ecosystem = "system",
      scope = if (required) "required" else "optional",
      description = paste0(
        "Needed by ", paste(by, collapse = ", "),
        if (program) "; a program, not a library",
        if (!is.na(platform) && length(os) > 0L) {
          paste0(if (program) ". On " else "; on ", platform, " it is provided by ", paste(os, collapse = ", "))
        },
        "."
      ),
      evidence = "declared", source_input = n[[1]]$source_input,
      deps_known = FALSE
    )
  })
  all <- rbind(components, do.call(rbind, rows))
  all <- all[order(all$ref, method = "radix"), , drop = FALSE]
  rownames(all) <- NULL
  list(
    components = all, relationships = do.call(rbind, rels),
    issues = issues
  )
}

# Observed system libraries. The shared libraries that the compiled code of
# each installed package links are components, with the operating system
# package and version when dpkg or rpm knows the file.
