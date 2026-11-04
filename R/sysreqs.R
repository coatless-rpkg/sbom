# Declared system requirements. The SystemRequirements text of a package is
# matched against the rules in pak, which name the system libraries behind
# free text such as "libcurl (>= 7.73): libcurl-devel (rpm)". What pak cannot
# map, such as "C++17" or "GNU make", gets no component and stays as written
# in the package's `system_requirements`.

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
pak_call <- function(name, ...) {
  fun <- pak_function(name)
  if (is.null(fun)) {
    return(NULL)
  }
  op <- options(pkg.sysreqs_db_update = FALSE)
  on.exit(options(op), add = TRUE)
  tryCatch(fun(...), error = function(e) NULL)
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

# Libraries that come with R or with the compilers rather than with the
# operating system's packages: R itself and the C, C++, Fortran and OpenMP
# runtimes, which a package links wherever its toolchain put them (R for
# macOS ships its own, and a gfortran install puts them in /opt/gfortran).
ignored_libraries <- c(
  "libR", "libSystem", "libc++", "libc++abi", "libc", "libm", "libpthread",
  "libdl", "librt", "libgcc_s", "libstdc++", "linux-vdso", "libgfortran",
  "libquadmath", "libgomp", "libomp"
)

# Whether a library's base name is one of the runtimes that every compiled
# package links: libc, the dynamic loaders (glibc's and musl's) and the like.
ignored_base_name <- function(base) {
  base %in% ignored_libraries | startsWith(base, "ld-linux") |
    startsWith(base, "ld-musl") | startsWith(base, "libc.musl") |
    startsWith(base, "libSystem") | startsWith(base, "libR")
}

# The name of a library without its directory, "lib" kept, and without a
# version or extension: "/usr/lib/libssl.48.dylib" and "libssl.so.3" are both
# "libssl".
library_base_name <- function(path) {
  base <- basename(path)
  base <- sub("\\.(so|dylib)(\\.[0-9.]+)*$", "", base)
  # macOS also names some versions with a letter, as in libicucore.A.dylib.
  sub("(\\.([0-9]+|[A-Z]))+$", "", base)
}

# Whether each library is one every compiled package links, or one of R's
# own: libR, libRblas, libRlapack and the like by name, and anything in R's
# own folder, such as the libgfortran that R for macOS ships.
ignored_library <- function(path) {
  startsWith(path, "/System/Library/Frameworks") |
    ignored_base_name(library_base_name(path)) | inside_any(path, R.home())
}

# Whether a path is absolute: it starts with "/", a drive letter and a
# separator, as in "C:\\" or "C:/", or "\\\\" (a network share).
is_absolute_path <- function(path) {
  !is.na(path) & grepl("^(/|[A-Za-z]:[/\\\\]|\\\\\\\\)", path)
}

# Whether the folder of each path is one of `dirs` or inside one, comparing
# the paths as given and normalised, so that a symlinked folder (R.framework's
# "Resources", macOS's /var) still counts.
inside_any <- function(paths, dirs) {
  forms <- function(x) unique(c(x, normalizePath(x, winslash = "/", mustWork = FALSE)))
  dirs <- as.character(dirs)
  dirs <- dirs[!is.na(dirs) & nzchar(dirs)]
  roots <- if (length(dirs) > 0L) paste0(sub("[/\\\\]+$", "", forms(dirs)), "/") else character()
  vapply(paths, function(p) {
    if (is.na(p) || length(roots) == 0L) {
      return(FALSE)
    }
    folder <- paste0(forms(dirname(p)), "/")
    any(vapply(roots, function(r) any(startsWith(folder, r)), NA))
  }, NA, USE.NAMES = FALSE)
}

# The library names, without "lib", that a sysreq links as when its own name
# does not say: a name ending in "*" is a prefix.
sysreq_link_names <- list(
  openssl = c("ssl", "crypto"), zlib = "z", postgresql = "pq",
  imagemagick = "magick*", icu = "icu*", libicu = "icu*", xz = "lzma",
  zeromq = "zmq", netcdf = "netcdf", netcdf4 = "netcdf", hdf5 = "hdf5",
  pango = "pango", glib = "glib", libjpeg = "jpeg", libtiff = "tiff",
  gdal = "gdal", geos = "geos", proj = "proj", fftw3 = "fftw3", gmp = "gmp",
  mpfr = "mpfr"
)

# The forms of a linked library's base name to compare with a sysreq: in
# lowercase without "lib", then without each trailing version or variant
# suffix in turn, so that "libhdf5_serial" gives "hdf5_serial", "hdf5" and
# "hdf", and "libMagick++-6.Q16" gives "magick++-6.q16", "magick++-6",
# "magick++" and "magick".
link_name_forms <- function(base) {
  x <- sub("^lib", "", tolower(base))
  out <- x
  repeat {
    y <- sub("(\\.q[0-9]+[a-z]*|[-_.]?[0-9][0-9.]*|\\+\\+|_(serial|hl|c|threads|omp|mpi)|-mt)$", "", x)
    if (identical(y, x) || !nzchar(y)) {
      return(out)
    }
    x <- y
    out <- c(out, x)
  }
}

# Whether the library base names `bases` include the one behind `sysreq`:
# its own name without "lib", or another name it links as
# (sysreq_link_names), against each form of each linked name. "openssl" is
# libssl and libcrypto, "postgresql" is libpq, and "libpng" is libpng16.
sysreq_is_linked <- function(sysreq, bases) {
  targets <- unique(c(sub("^lib", "", tolower(sysreq)), sysreq_link_names[[sysreq]]))
  forms <- as.character(unlist(lapply(bases, link_name_forms)))
  prefix <- endsWith(targets, "*")
  any(targets[!prefix] %in% forms) ||
    any(vapply(sub("\\*$", "", targets[prefix]), function(t) any(startsWith(forms, t)), NA))
}

# The absolute path of a library that otool names as `path` for the compiled
# file `so`, or NA. "@loader_path/" is the file's own folder and
# "@executable_path/" is `r_bin`, the folder of R's programs. "@rpath/" is
# looked for in the file's LC_RPATH entries, which are resolved the same way.
# A path found this way counts only when it is absolute and the file exists. A
# path that otool printed in full is taken as it is, since system libraries
# on recent macOS are in a cache and not on disk.
resolve_link <- function(path, so, rpaths, r_bin) {
  under <- function(base, rest) normalizePath(file.path(base, rest), mustWork = FALSE)
  real <- function(p) if (is_absolute_path(p) && file.exists(p)) p else NA_character_
  # Where "@loader_path/..." or "@executable_path/..." points, not checked.
  anchor <- function(p) {
    if (startsWith(p, "@loader_path/")) {
      under(dirname(so), substring(p, 14L))
    } else if (startsWith(p, "@executable_path/")) {
      under(r_bin, substring(p, 18L))
    } else if (is_absolute_path(p)) {
      p
    } else {
      NA_character_
    }
  }
  if (is_absolute_path(path)) {
    return(path)
  }
  if (startsWith(path, "@rpath/")) {
    for (r in rpaths()) {
      base <- anchor(r)
      if (is.na(base)) next
      hit <- real(under(base, substring(path, 8L)))
      if (!is.na(hit)) return(hit)
    }
    return(NA_character_)
  }
  real(anchor(path))
}

# The "Linked as ..." sentence of a library, by file name only so that no
# directory of this machine reaches a document.
linked_as <- function(path, version) {
  paste0("Linked as ", path, if (!is.na(version)) paste0(" (library version ", version, ")"), ".")
}

# The compiled files of an installed package: its shared libraries under
# libs/, in subfolders too (Windows keeps them in libs/x64), but not the
# debugging symbols that macOS keeps in .dSYM bundles.
compiled_files <- function(dir) {
  files <- list.files(
    file.path(dir, "libs"), pattern = "\\.(so|dll|dylib)$", recursive = TRUE,
    full.names = TRUE
  )
  sort(files[!grepl(".dSYM/", files, fixed = TRUE)], method = "radix")
}

# The purl namespaces of the purl spec's deb and rpm types: "the vendor such as
# debian or ubuntu" (deb) and "such as Fedora or OpenSUSE" (rpm), lowercased. An
# os-release ID that is not here, such as rocky, is its own vendor name.
purl_vendors <- c(rhel = "redhat")

# The vendor in a purl for an os-release `id`: Red Hat's is redhat, any
# opensuse-* is opensuse, and any other ID stands for itself.
purl_vendor <- function(id) {
  if (startsWith(id, "opensuse")) {
    return("opensuse")
  }
  if (id %in% names(purl_vendors)) purl_vendors[[id]] else id
}

# The purl of an operating system package `os`, as list(manager, name, version,
# arch), on the system `os_release` describes, or NULL when its ID is unknown.
# The distro qualifier is "<id>-<version_id>", as the rpm example in the spec
# (fedora-25), but the spec's deb examples name the release (jessie, stretch),
# so a deb package uses VERSION_CODENAME when os-release has one.
os_package_purl <- function(os, os_release) {
  id <- os_release$id
  if (is.null(id) || is.na(id) || !nzchar(id)) {
    return(NULL)
  }
  field <- function(x) if (is.null(x) || is.na(x) || !nzchar(x)) NULL else x
  distro <- if (identical(os$manager, "deb") && !is.null(field(os_release$version_codename))) {
    os_release$version_codename
  } else if (!is.null(field(os_release$version_id))) {
    paste0(id, "-", os_release$version_id)
  }
  paste0(
    "pkg:", os$manager, "/", purl_vendor(id), "/", os$name, "@",
    utils::URLencode(os$version, reserved = TRUE), "?arch=", os$arch,
    if (!is.null(distro)) paste0("&distro=", utils::URLencode(distro, reserved = TRUE))
  )
}

# One component per shared library linked by the installed packages in
# `components` (found by name and version in `lib_dirs`), a "dynamic_link"
# relationship from each package, and the issues. A library with an operating
# system package is "deb/<name>" or "rpm/<name>" with that package's version;
# any other is "system/<name>", shared with a declared component of that name,
# which becomes observed. R's own libraries are left out, and a library in
# any folder of `lib_dirs` is a copy that a package ships, not a system
# library. `relationships` holds the declared system requirements, to find
# those with no link. Returns list(components, relationships, issues): all the
# components, sorted by ref, and only the new relationships and issues.
linked_system_libraries <- function(components, lib_dirs, relationships = empty_relationships()) {
  out <- list(
    components = components, relationships = empty_relationships(),
    issues = empty_issues()
  )
  skip_eco <- c("r", "base-r", system_ecosystems, "vendored", "npm", "file", "library")
  pkgs <- components[
    is.na(components$parent_ref) & components$type == "library" &
      !components$is_root & !components$ecosystem %in% skip_eco, ,
    drop = FALSE
  ]
  root <- components$ref[components$is_root %in% TRUE][1L]
  not_checked <- function(issues, because) {
    add_issue(
      issues, root, "system", "links-not-checked",
      paste0("The shared libraries linked by ", because, "."),
      severity = "info"
    )
  }
  os_name <- sys_os_name()
  windows <- identical(os_name, "Windows")
  # On macOS otool works only with the Command Line Tools; asked once.
  tools <- if (identical(os_name, "Darwin")) NA else TRUE
  os_release <- sys_os_release()
  os_cache <- list()
  os_of <- function(path) {
    if (!path %in% names(os_cache)) {
      os_cache[path] <<- list(sys_os_package(path))
    }
    os_cache[[path]]
  }
  found <- list()
  rels <- list()
  issues <- empty_issues()
  tool_missing <- FALSE
  dll_labels <- character()
  reads <- 0L
  failures <- 0L
  for (i in seq_len(nrow(pkgs))) {
    dir <- installed_dir(pkgs$name[[i]], pkgs$version[[i]], lib_dirs)
    if (is.null(dir)) {
      next
    }
    files <- compiled_files(dir)
    if (length(files) == 0L) {
      next
    }
    label <- pkg_label(pkgs$name[[i]], pkgs$version[[i]])
    # sbom does not read what a Windows DLL links, on Windows or elsewhere.
    dll <- windows | endsWith(files, ".dll")
    if (any(dll)) {
      dll_labels <- c(dll_labels, label)
    }
    files <- files[!dll]
    if (length(files) > 0L && is.na(tools)) {
      tools <- isTRUE(sys_xcode_tools())
    }
    if (length(files) > 0L && isFALSE(tools)) {
      tool_missing <- TRUE
      break
    }
    paths <- character()
    versions <- character()
    unfound <- character()
    failed <- FALSE
    for (so in files) {
      got <- sys_linked_libraries(so)
      if (isTRUE(attr(got, "tool_missing"))) {
        tool_missing <- TRUE
        break
      }
      reads <- reads + 1L
      if (isTRUE(attr(got, "failed"))) {
        failures <- failures + 1L
        failed <- TRUE
      }
      unfound <- c(unfound, as.character(attr(got, "not_found")))
      v <- attr(got, "versions")
      v <- if (length(v) == length(got)) as.character(v) else rep(NA_character_, length(got))
      rpaths <- local({
        cache <- NULL
        function() {
          if (is.null(cache)) cache <<- sys_otool_rpaths(so)
          cache
        }
      })
      resolved <- vapply(
        as.character(got), resolve_link, "", so = so, rpaths = rpaths,
        r_bin = sys_r_bin(), USE.NAMES = FALSE
      )
      # A library in a library folder, the package's own or another's, is a
      # copy a package ships. The folder is resolved, not the file, which may
      # not be on disk.
      ok <- !is.na(resolved) & !inside_any(resolved, lib_dirs)
      paths <- c(paths, resolved[ok])
      versions <- c(versions, v[ok])
    }
    if (tool_missing) {
      break
    }
    keep <- !ignored_library(paths) & !duplicated(paths)
    paths <- paths[keep]
    versions <- versions[keep]
    ord <- order(paths, method = "radix")
    paths <- paths[ord]
    versions <- versions[ord]
    pkg_ref <- pkgs$ref[[i]]
    # A library that ldd did not find is not a component, since it is not
    # there; the runtimes every package links are left out as elsewhere.
    unfound <- sort(unique(unfound[!ignored_base_name(library_base_name(unfound))]), method = "radix")
    if (failed || length(unfound) > 0L) {
      issues <- add_issue(
        issues, pkg_ref, "system", "links-not-read",
        paste(c(
          if (failed) paste0("sbom could not read the shared libraries linked by ", label, "."),
          if (length(unfound) > 0L) {
            paste0(
              "ldd did not find ", and_list(unfound), ", which ", label,
              " links, so ", if (length(unfound) == 1L) "it is" else "they are",
              " not listed as ", if (length(unfound) == 1L) "a component." else "components."
            )
          }
        ), collapse = " "),
        severity = "info"
      )
    }
    for (k in seq_along(paths)) {
      os <- os_of(paths[[k]])
      base <- library_base_name(paths[[k]])
      ref <- if (is.null(os)) paste0("system/", base) else paste0(os$manager, "/", os$name)
      if (is.null(found[[ref]])) {
        found[[ref]] <- list(
          os = os, name = if (is.null(os)) base else os$name, path = paths[[k]],
          version = versions[[k]], scope = pkgs$scope[[i]],
          source_input = pkgs$source_input[[i]]
        )
      } else if (identical(pkgs$scope[[i]], "required")) {
        found[[ref]]$scope <- "required"
      }
      rels[[length(rels) + 1L]] <- data.frame(
        from = pkg_ref, to = ref, field = "dynamic_link", spec = NA_character_,
        evidence = "observed", stringsAsFactors = FALSE
      )
    }
    # What a package links is unknown when a read failed, a library was not
    # found or a DLL was not read, so it is not said to carry its own copy of
    # anything.
    if (failed || length(unfound) > 0L || any(dll)) {
      next
    }
    declared <- unique(sub("^system/", "", relationships$to[
      relationships$from == pkg_ref & relationships$field == "system_requirement"
    ]))
    bases <- library_base_name(paths)
    for (sysreq in sort(setdiff(declared, sysreq_programs), method = "radix")) {
      if (!sysreq_is_linked(sysreq, bases)) {
        issues <- add_issue(
          issues, pkg_ref, "system_requirements", "may-statically-link",
          paste0(
            label, " declares ", sysreq, " but does not link to it dynamically, ",
            "so it may include its own copy, whose version is unknown."
          ),
          severity = "info"
        )
      }
    }
  }
  if (tool_missing) {
    out$issues <- not_checked(
      issues[!issues$code %in% "links-not-read", , drop = FALSE],
      if (identical(os_name, "Darwin") && isFALSE(tools)) {
        paste0(
          "compiled packages were not checked, because otool cannot run without ",
          "the Xcode Command Line Tools"
        )
      } else {
        "compiled packages were not checked, because neither otool nor ldd is available"
      }
    )
    return(out)
  }
  if (reads > 0L && failures == reads) {
    issues <- not_checked(
      issues[!issues$code %in% "links-not-read", , drop = FALSE],
      "compiled packages were not checked, because sbom could not read them for any package"
    )
  }
  if (length(dll_labels) > 0L) {
    issues <- not_checked(issues, paste0(
      if (windows) "compiled packages" else paste0("the Windows DLLs of ", and_list(dll_labels)),
      " were not checked, because sbom does not read the libraries that Windows DLLs link"
    ))
  }
  out$issues <- issues
  if (length(found) == 0L) {
    return(out)
  }
  all <- components
  for (ref in sort(names(found), method = "radix")) {
    f <- found[[ref]]
    sentence <- linked_as(basename(f$path), f$version)
    i <- match(ref, all$ref)
    if (!is.na(i)) {
      # A declared minimum stays a minimum: the link was observed, the
      # version was not.
      declared_version <- all$version_is[[i]] %in% "minimum"
      if (declared_version) {
        sentence <- paste(sentence, "The link was observed; the version is the declared minimum, not an observed one.")
      } else {
        all$evidence[[i]] <- "observed"
      }
      all$description[[i]] <- if (is.na(all$description[[i]])) sentence else paste(all$description[[i]], sentence)
      if (identical(f$scope, "required")) {
        all$scope[[i]] <- "required"
      }
      next
    }
    os <- f$os
    all <- rbind(all, component_row(
      ref = ref, name = f$name, version = if (!is.null(os)) os$version,
      version_is = if (!is.null(os)) "exact", type = "library",
      ecosystem = if (is.null(os)) "system" else os$manager,
      scope = f$scope, description = sentence, evidence = "observed",
      purl = if (!is.null(os)) os_package_purl(os, os_release),
      source_input = f$source_input, deps_known = FALSE
    ))
  }
  all <- all[order(all$ref, method = "radix"), , drop = FALSE]
  rownames(all) <- NULL
  # A linked library with no operating system package has no version.
  unknown <- all$ref %in% names(found) & all$ecosystem == "system" & !all$version_is %in% "exact"
  if (any(unknown)) {
    n <- sum(unknown)
    out$issues <- add_issue(
      out$issues, root, "version", "system-version-unknown",
      paste0(
        if (n == 1L) "The version of the linked system library " else "The versions of the linked system libraries ",
        and_list(all$name[unknown]), if (n == 1L) " is" else " are",
        " unknown, because sbom found no package manager that owns ",
        if (n == 1L) "it." else "them."
      ),
      severity = "info"
    )
  }
  out$components <- all
  out$relationships <- do.call(rbind, rels)
  out
}
