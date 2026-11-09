# The shared libraries that compiled packages link, read with otool or ldd,
# and the operating system packages that own them.

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
# the paths as given and normalized, so that a symlinked folder (R.framework's
# "Resources", macOS's /var) still counts.
inside_any <- function(paths, dirs) {
  # Each path as given and resolved, with forward slashes; on Windows, where
  # a folder can also appear by its short name and paths ignore case, in
  # lower case too.
  forms <- function(x) {
    x <- gsub("\\", "/", c(x, normalizePath(x, winslash = "/", mustWork = FALSE)), fixed = TRUE)
    if (.Platform$OS.type == "windows") x <- tolower(x)
    unique(x)
  }
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
  with_sys_cache(linked_libraries_cached(components, lib_dirs, relationships))
}

# The body of linked_system_libraries(), run inside the system cache that
# with_sys_cache() opens; it takes the same arguments and returns the same list.
linked_libraries_cached <- function(components, lib_dirs, relationships) {
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
  os_of <- function(path) sys_cached(paste0("os-package:", path), sys_os_package(path))
  found <- list()
  rels <- list()
  issues <- empty_issues()
  tool_missing <- FALSE
  dll_labels <- character()
  reads <- 0L
  failures <- 0L
  unfound_all <- character()
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
    links <- read_package_links(files, lib_dirs)
    if (links$tool_missing) {
      tool_missing <- TRUE
      break
    }
    reads <- reads + links$reads
    failures <- failures + links$failures
    failed <- links$failures > 0L
    paths <- links$paths
    versions <- links$versions
    unfound <- links$unfound
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
    unfound_all <- c(unfound_all, unfound)
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
    issues <- static_link_issues(issues, pkg_ref, label, relationships, paths)
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
    # The notes for each package collapse into one, which still names the
    # libraries that ldd did not find.
    unfound_all <- sort(unique(unfound_all), method = "radix")
    one <- length(unfound_all) == 1L
    issues <- not_checked(
      issues[!issues$code %in% "links-not-read", , drop = FALSE],
      paste0(
        "compiled packages were not checked, because sbom could not read them for any package",
        if (length(unfound_all) > 0L) {
          paste0(
            ", and ldd did not find ", and_list(unfound_all), ", so ",
            if (one) "it is not listed as a component" else "they are not listed as components"
          )
        }
      )
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
  all <- add_linked_components(components, found, os_release)
  # A linked library with no operating system package has no version.
  unknown <- all$ref %in% names(found) & all$ecosystem == "system" & !all$version_is %in% "exact"
  if (any(unknown)) {
    out$issues <- add_issue(
      out$issues, root, "version", "system-version-unknown",
      system_version_unknown_sentence(all$name[unknown]),
      severity = "info"
    )
  }
  out$components <- all
  out$relationships <- do.call(rbind, rels)
  out
}

# What the compiled `files` of one package link, as list(paths, versions,
# unfound, reads, failures, tool_missing): the resolved paths of the
# libraries outside `lib_dirs` and their versions, the libraries that ldd
# did not find, how many files were read and how many of those reads
# failed, and whether neither otool nor ldd could run, which stops the read.
read_package_links <- function(files, lib_dirs) {
  out <- list(
    paths = character(), versions = character(), unfound = character(),
    reads = 0L, failures = 0L, tool_missing = FALSE
  )
  for (so in files) {
    # A file is read once a build, by its real path, however many packages
    # hold it; where its links point is resolved from each package's copy.
    real <- normalizePath(so, mustWork = FALSE)
    got <- sys_cached(paste0("links:", real), sys_linked_libraries(so))
    if (isTRUE(attr(got, "tool_missing"))) {
      out$tool_missing <- TRUE
      return(out)
    }
    out$reads <- out$reads + 1L
    if (isTRUE(attr(got, "failed"))) {
      out$failures <- out$failures + 1L
    }
    out$unfound <- c(out$unfound, as.character(attr(got, "not_found")))
    v <- attr(got, "versions")
    v <- if (length(v) == length(got)) as.character(v) else rep(NA_character_, length(got))
    rpaths <- function() sys_cached(paste0("rpaths:", real), sys_otool_rpaths(so))
    resolved <- vapply(
      as.character(got), resolve_link, "", so = so, rpaths = rpaths,
      r_bin = sys_r_bin(), USE.NAMES = FALSE
    )
    # A library in a library folder, the package's own or another's, is a
    # copy a package ships. The folder is resolved, not the file, which may
    # not be on disk.
    ok <- !is.na(resolved) & !inside_any(resolved, lib_dirs)
    out$paths <- c(out$paths, resolved[ok])
    out$versions <- c(out$versions, v[ok])
  }
  out
}

# `issues` with one for each system requirement that the package `pkg_ref`
# (`label`) declares in `relationships` but whose library is not among the
# `paths` it links, so that it may carry its own copy.
static_link_issues <- function(issues, pkg_ref, label, relationships, paths) {
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
  issues
}

# `components` with the linked libraries in `found` (by ref, as
# linked_libraries_cached() gathers them) added, sorted by ref. A library
# that is already a component, declared, becomes observed unless its version
# is a declared minimum, and its description says how it was linked.
add_linked_components <- function(components, found, os_release) {
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
  all
}

# The sentence of the system-version-unknown issue, naming the linked system
# libraries without a version, in the order given. apply_overrides() builds
# it again after an override asserts some of their versions.
system_version_unknown_sentence <- function(names) {
  n <- length(names)
  paste0(
    if (n == 1L) "The version of the linked system library " else "The versions of the linked system libraries ",
    and_list(names), if (n == 1L) " is" else " are",
    " unknown, because sbom found no package manager that owns ",
    if (n == 1L) "it." else "them."
  )
}
