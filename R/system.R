# Wrappers for what sbom asks of the operating system. Each is small so that
# tests can replace it, and each returns an empty result when its tool is
# missing or fails. Tests never run a real command.

# What one build learns from the operating system and its library folders,
# kept while that build runs so that nothing is asked twice: where each tool
# is, what each compiled file links, which package owns each library, and
# the packages each library folder holds. A build runs in with_sys_cache(),
# and the cache is dropped when it ends, never kept for the next build: a
# tool can be installed, or a library updated, in between.
sys_cache <- new.env(parent = emptyenv())

# `code`, evaluated with a cache open: a new one, dropped when `code` ends,
# however it ends, or the one already open. The drop is this function's
# own, so no on.exit() in the code can undo it.
with_sys_cache <- function(code) {
  if (!is.null(sys_cache$current)) {
    return(code)
  }
  sys_cache$current <- new.env(parent = emptyenv())
  on.exit(sys_cache_drop(), add = TRUE)
  code
}

# Closes the system cache, so later lookups are evaluated each time.
sys_cache_drop <- function() {
  sys_cache$current <- NULL
}

# `value`, the answer to `key`, from the open cache when it holds it, else
# evaluated and kept there. With no cache open, `value` is evaluated each time.
sys_cached <- function(key, value) {
  cache <- sys_cache$current
  if (is.null(cache)) {
    return(value)
  }
  if (!exists(key, envir = cache, inherits = FALSE)) {
    assign(key, value, envir = cache)
  }
  get(key, envir = cache, inherits = FALSE)
}

# Where a tool is, as Sys.which() says, asked once a build: each call of
# Sys.which() starts a shell.
sys_which <- function(command) {
  sys_cached(paste0("which:", command), Sys.which(command))
}

# The lines a command prints, or NULL when the tool is not on the path, the
# command fails or it takes longer than `timeout` seconds.
sys_run <- function(command, args, timeout = 5) {
  if (!nzchar(sys_cached(paste0("which:", command), Sys.which(command)))) {
    return(NULL)
  }
  out <- tryCatch(
    suppressWarnings(system2(
      command, args, stdout = TRUE, stderr = FALSE, timeout = timeout
    )),
    error = function(e) NULL
  )
  if (is.null(out) || !is.null(attr(out, "status"))) {
    return(NULL)
  }
  as.character(out)
}

# The name of the operating system, as Sys.info() gives it: "Darwin",
# "Linux", "Windows" and so on.
sys_os_name <- function() {
  Sys.info()[["sysname"]]
}

# Whether the Xcode Command Line Tools are installed, which on macOS is what
# makes otool work: /usr/bin/otool is only a shim without them, which fails
# or asks to install them.
sys_xcode_tools <- function() {
  !is.null(sys_run("xcode-select", "-p"))
}

# The shared libraries a compiled file links, as a character vector of paths.
# Two attributes say more: `versions`, one entry per path, holds the "current
# version" otool prints for a dylib (NA when there is none, as on Linux), and
# `not_found` holds the names of the libraries ldd reports as "not found", and
# `tool_missing` is TRUE when otool (macOS) or ldd (elsewhere) is not on the
# path, and `failed` is TRUE when the tool ran but failed or timed out, or
# when the file was not given to it. In either case the answer is unknown
# rather than empty.
sys_linked_libraries <- function(so_file) {
  mac <- identical(sys_os_name(), "Darwin")
  tool <- if (mac) "otool" else "ldd"
  # Older versions of ldd run a file that names its own program interpreter,
  # so ldd is given only ELF files without one.
  if (!mac && nzchar(sys_which(tool)) && !identical(elf_has_interp(so_file), FALSE)) {
    return(structure(character(), versions = character(), tool_missing = FALSE, failed = TRUE))
  }
  lines <- sys_run(tool, if (mac) c("-L", shQuote(so_file)) else shQuote(so_file))
  if (is.null(lines)) {
    missing <- !nzchar(sys_which(tool))
    return(structure(
      character(), versions = character(), tool_missing = missing, failed = !missing
    ))
  }
  parsed <- if (mac) parse_otool(lines, so_file) else parse_ldd(lines)
  structure(
    parsed$paths, versions = parsed$versions, not_found = parsed$not_found,
    tool_missing = FALSE, failed = FALSE
  )
}

# Whether the ELF file at `path` names a program interpreter (it has a
# PT_INTERP segment): TRUE or FALSE, or NA when it is not an ELF file or
# cannot be read. Only the ELF header and the program headers are read, for
# 32- and 64-bit files of either byte order.
elf_has_interp <- function(path) {
  con <- tryCatch(file(path, "rb"), error = function(e) NULL, warning = function(w) NULL)
  if (is.null(con)) {
    return(NA)
  }
  on.exit(close(con), add = TRUE)
  head <- readBin(con, "raw", n = 64L)
  if (length(head) < 52L || !identical(head[1:4], as.raw(c(0x7f, 0x45, 0x4c, 0x46)))) {
    return(NA)
  }
  class <- as.integer(head[[5]])
  order <- as.integer(head[[6]])
  if (!class %in% 1:2 || !order %in% 1:2 || (class == 2L && length(head) < 64L)) {
    return(NA)
  }
  # An unsigned integer from its bytes, in the file's byte order.
  num <- function(bytes) {
    v <- as.numeric(as.integer(bytes))
    if (order == 2L) v <- rev(v)
    sum(v * 256^(seq_along(v) - 1L))
  }
  if (class == 2L) {
    phoff <- num(head[33:40])
    phentsize <- num(head[55:56])
    phnum <- num(head[57:58])
  } else {
    phoff <- num(head[29:32])
    phentsize <- num(head[43:44])
    phnum <- num(head[45:46])
  }
  if (phnum == 0) {
    return(FALSE)
  }
  # A count of 0xffff means the real count is kept elsewhere, which sbom does
  # not read; a table that does not fit in the file is not a real one.
  size <- file.size(path)
  if (phnum >= 65535 || phentsize < 4 || phentsize > 256 || is.na(size) ||
      phoff + phnum * phentsize > size) {
    return(NA)
  }
  seek(con, phoff)
  table <- readBin(con, "raw", n = phnum * phentsize)
  if (length(table) < phnum * phentsize) {
    return(NA)
  }
  types <- vapply(seq_len(phnum) - 1L, function(i) num(table[i * phentsize + 1:4]), 0)
  any(types == 3)
}

# The paths and current versions in the output of `otool -L file`. The first
# line is the file itself, and a library often lists its own install name
# among the libraries, which is not a link to anything else.
parse_otool <- function(lines, so_file) {
  lines <- lines[grepl("^\\s+\\S", lines)]
  path <- sub("^\\s+(\\S.*?)\\s+\\(.*$", "\\1", lines, perl = TRUE)
  path <- sub("^\\s+", "", path)
  version <- ifelse(
    grepl("current version ", lines, fixed = TRUE),
    sub(".*current version ([^,)]+).*", "\\1", lines),
    NA_character_
  )
  keep <- basename(path) != basename(so_file)
  list(paths = path[keep], versions = version[keep])
}

# The paths in the output of `ldd file`: "name => /path (0x...)" and a bare
# "/path (0x...)" such as the dynamic loader, and the names of the libraries
# that are "not found", which have no path. The kernel's vdso has none either.
parse_ldd <- function(lines) {
  lines <- trimws(lines)
  has_arrow <- grepl("=>", lines, fixed = TRUE)
  absent <- has_arrow & grepl("=>\\s*not found\\s*$", lines)
  path <- ifelse(
    has_arrow, sub("^.*=>\\s*(\\S+).*$", "\\1", lines),
    ifelse(startsWith(lines, "/"), sub("^(\\S+).*$", "\\1", lines), NA_character_)
  )
  path <- path[!is.na(path) & startsWith(path, "/")]
  list(
    paths = path, versions = rep(NA_character_, length(path)),
    not_found = sort(unique(trimws(sub("=>.*$", "", lines[absent]))), method = "radix")
  )
}

# The operating system package that owns `path`, as
# list(manager, name, version, arch), or NULL when there is none or neither
# dpkg nor rpm is available.
sys_os_package <- function(path) {
  if (nzchar(sys_which("dpkg"))) {
    owner <- sys_run("dpkg", c("-S", shQuote(path)))
    if (is.null(owner) && file.exists(path)) {
      owner <- sys_run("dpkg", c("-S", shQuote(normalizePath(path))))
    }
    name <- parse_dpkg_owner(owner)
    if (is.na(name)) {
      return(NULL)
    }
    info <- sys_run("dpkg-query", c("-W", shQuote("-f=${Version} ${Architecture}"), shQuote(name)))
    got <- parse_os_package(info, "deb", name)
    return(got)
  }
  if (nzchar(sys_which("rpm"))) {
    info <- sys_run("rpm", c("-qf", "--qf", shQuote("%{NAME} %{VERSION}-%{RELEASE} %{ARCH}"), shQuote(path)))
    return(parse_os_package(info, "rpm", NULL))
  }
  NULL
}

# The package name in the first line of `dpkg -S` output, such as
# "libcurl4:amd64: /usr/lib/x86_64-linux-gnu/libcurl.so.4", or NA.
parse_dpkg_owner <- function(lines) {
  if (length(lines) == 0L || !grepl(": ", lines[[1]], fixed = TRUE)) {
    return(NA_character_)
  }
  name <- sub(":.*$", "", lines[[1]])
  if (nzchar(name)) name else NA_character_
}

# list(manager, name, version, arch) from "[name ]version arch" output, or
# NULL. `name` is given for dpkg-query, whose output starts at the version.
parse_os_package <- function(lines, manager, name) {
  if (length(lines) == 0L) {
    return(NULL)
  }
  parts <- strsplit(trimws(lines[[1]]), " ", fixed = TRUE)[[1]]
  if (is.null(name)) {
    if (length(parts) != 3L) {
      return(NULL)
    }
    name <- parts[[1]]
    parts <- parts[-1L]
  }
  if (length(parts) != 2L || !all(nzchar(parts))) {
    return(NULL)
  }
  list(manager = manager, name = name, version = parts[[1]], arch = parts[[2]])
}

# The fields of /etc/os-release as a named list with lowercase names and
# values, such as `id` and `version_id`, or NULL when the file cannot be read.
# It is a file, not a command.
sys_os_release <- function(file = "/etc/os-release") {
  lines <- tryCatch(
    suppressWarnings(readLines(file, warn = FALSE)),
    error = function(e) NULL
  )
  if (is.null(lines)) {
    return(NULL)
  }
  parse_os_release(lines)
}

# The KEY=value lines of `lines` as a list with lower-case names and values and
# quotes removed; NULL when no line has that form.
parse_os_release <- function(lines) {
  lines <- trimws(lines)
  lines <- lines[grepl("^[A-Za-z_][A-Za-z0-9_]*=", lines)]
  if (length(lines) == 0L) {
    return(NULL)
  }
  key <- tolower(sub("=.*$", "", lines))
  value <- tolower(gsub("^[\"']|[\"']$", "", sub("^[^=]*=", "", lines)))
  as.list(stats::setNames(value, key))
}

# The LC_RPATH entries of a macOS compiled file, from `otool -l`, as a
# character vector; empty when otool is missing or fails.
sys_otool_rpaths <- function(so_file) {
  lines <- sys_run("otool", c("-l", shQuote(so_file)))
  parse_otool_rpaths(lines)
}

# The paths of the LC_RPATH load commands in `otool -l` output:
#   cmd LC_RPATH / cmdsize 32 / path @loader_path/../deps (offset 12)
parse_otool_rpaths <- function(lines) {
  at <- which(trimws(lines) == "cmd LC_RPATH")
  paths <- vapply(at, function(i) {
    nxt <- trimws(lines[seq(i + 1L, min(i + 3L, length(lines)))])
    hit <- nxt[startsWith(nxt, "path ")][1L]
    sub("^path (.*?) \\(offset [0-9]+\\)$", "\\1", hit, perl = TRUE)
  }, "")
  paths[!is.na(paths) & nzchar(paths)]
}

# The folder of R's programs, which dyld takes as "@executable_path" for code
# that R loads.
sys_r_bin <- function() {
  R.home("bin")
}

# The script that the child R process runs to evaluate an app's UI. It uses
# base R only, because the library it sees need not hold any of sbom's own
# packages. It reads the app folder, the layout and the output path from its
# command line, and writes a DCF file: one record per html dependency (name,
# version, package, src), or a single `reason` field when it cannot say.
ui_child_script <- function() {
  c(
    'args <- commandArgs(trailingOnly = TRUE)',
    'dir <- args[[1L]]; layout <- args[[2L]]; out <- args[[3L]]',
    'fail <- function(reason) {',
    '  write.dcf(data.frame(reason = reason, stringsAsFactors = FALSE), out, width = 10000L)',
    '  quit(save = "no", status = 0L)',
    '}',
    'if (!requireNamespace("htmltools", quietly = TRUE)) fail("htmltools is not installed")',
    'deps <- tryCatch({',
    '  setwd(dir)',
    '  env <- new.env(parent = globalenv())',
    '  file <- if (identical(layout, "ui-server")) "ui.R" else "app.R"',
    '  value <- source(file, local = env)$value',
    '  if (exists("ui", envir = env, inherits = FALSE)) {',
    '    ui <- get("ui", envir = env, inherits = FALSE)',
    '  } else if (identical(layout, "ui-server")) {',
    '    ui <- value',
    '  } else {',
    '    stop(structure(class = c("sbomNoUi", "error", "condition"), list(message = "", call = NULL)))',
    '  }',
    '  if (is.function(ui)) ui <- ui(list())',
    '  htmltools::findDependencies(ui)',
    '}, error = function(e) {',
    '  # Only fixed reasons leave the child: the message of an error raised by',
    '  # the app can name any path.',
    '  pkg <- tryCatch(e$package, error = function(e2) NULL)',
    '  if (inherits(e, "sbomNoUi")) {',
    '    fail("the app defines no ui object")',
    '  } else if (inherits(e, "packageNotFoundError") && is.character(pkg) && length(pkg) == 1L &&',
    '    !is.na(pkg) && grepl("^[A-Za-z][A-Za-z0-9.]*$", pkg)) {',
    '    fail(paste0("the UI needs the package ", pkg, ", which is not installed"))',
    '  }',
    '  fail("the UI code failed")',
    '})',
    'field <- function(d, name) {',
    '  v <- d[[name]]',
    '  if (is.null(v) || length(v) == 0L) NA_character_ else as.character(v)[[1L]]',
    '}',
    'rows <- lapply(deps, function(d) data.frame(',
    '  name = field(d, "name"), version = field(d, "version"), package = field(d, "package"),',
    '  src = if (is.null(d$src$file)) "href" else "file", stringsAsFactors = FALSE',
    '))',
    'res <- if (length(rows) > 0L) do.call(rbind, rows) else data.frame()',
    'write.dcf(res, out)'
  )
}

# The html dependencies of the UI of the Shiny app in `dir` (layout "app.R" or
# "ui-server"), found by running its UI code in a separate R process that
# sees the libraries `lib`. A data frame of name, version, package (NA when
# not known) and src ("file" or "href"). When it cannot say, it returns an
# empty list with a `reason` attribute, a short phrase that says why not (R
# cannot put an attribute on NULL). The process starts R with --vanilla and
# inherits this process's environment variables, except that R_LIBS is set
# to `lib`; R adds the user and site libraries after it. For an app.R app the
# whole file runs; global.R and the app's R/ folder are not sourced. It is
# stopped after `timeout` seconds.
sys_ui_dependencies <- function(dir, layout, lib = .libPaths(), timeout = 60) {
  fail <- function(reason) structure(list(), reason = reason)
  rscript <- file.path(R.home("bin"), "Rscript")
  if (!file.exists(rscript) && !nzchar(Sys.which(rscript))) {
    return(fail("Rscript was not found"))
  }
  script <- tempfile("sbom-ui-", fileext = ".R")
  out <- tempfile("sbom-ui-", fileext = ".dcf")
  on.exit(unlink(c(script, out)), add = TRUE)
  write_text(paste0(paste(ui_child_script(), collapse = "\n"), "\n"), script)
  libs <- paste(normalizePath(lib, mustWork = FALSE), collapse = .Platform$path.sep)
  # R_LIBS is set in this process around the call, and put back after, so the
  # child changes nothing else and the same works in every shell.
  old <- Sys.getenv("R_LIBS", unset = NA)
  on.exit(
    if (is.na(old)) Sys.unsetenv("R_LIBS") else Sys.setenv(R_LIBS = old),
    add = TRUE
  )
  Sys.setenv(R_LIBS = libs)
  status <- tryCatch(
    {
      res <- suppressWarnings(system2(
        rscript, shQuote(c("--vanilla", script, normalizePath(dir), layout, out)),
        stdout = TRUE, stderr = FALSE, timeout = timeout
      ))
      st <- attr(res, "status")
      if (is.null(st)) 0L else st
    },
    error = function(e) NA_integer_
  )
  if (identical(as.integer(status), 124L)) {
    return(fail(paste0("the UI did not finish within ", timeout, " seconds")))
  }
  if (!file.exists(out) || is.na(status) || status != 0L) {
    return(fail("the UI evaluation gave no readable result"))
  }
  read_ui_dcf(out)
}

# The result file of the child process as a data frame, or NULL with a reason.
read_ui_dcf <- function(path) {
  fail <- function(reason) structure(list(), reason = reason)
  cols <- c("name", "version", "package", "src")
  if (file.size(path) == 0L) {
    return(stats::setNames(
      data.frame(character(), character(), character(), character(), stringsAsFactors = FALSE), cols
    ))
  }
  dcf <- tryCatch(read.dcf(path), error = function(e) NULL)
  if (is.null(dcf)) {
    return(fail("the UI evaluation gave no readable result"))
  }
  if ("reason" %in% colnames(dcf)) {
    reason <- unname(dcf[1L, "reason"])
    fixed <- c("htmltools is not installed", "the app defines no ui object", "the UI code failed")
    pkg <- grepl("^the UI needs the package [A-Za-z][A-Za-z0-9.]*, which is not installed$", reason)
    if (!reason %in% fixed && !pkg) {
      reason <- "the UI evaluation gave no readable result"
    }
    return(fail(reason))
  }
  if (!all(c("name", "src") %in% colnames(dcf))) {
    return(fail("the UI evaluation gave no readable result"))
  }
  out <- lapply(cols, function(col) {
    if (col %in% colnames(dcf)) enc2utf8_bytes(unname(dcf[, col])) else rep(NA_character_, nrow(dcf))
  })
  data.frame(stats::setNames(out, cols), stringsAsFactors = FALSE)
}

# Whether Nix is installed: both nix-instantiate and nix-store are on the
# path. It runs no command.
sys_nix_available <- function() {
  all(nzchar(Sys.which(c("nix-instantiate", "nix-store"))))
}

# The derivation `nix-instantiate file` makes, as its store path: the last
# line it prints. NULL when Nix is missing, or the evaluation fails or takes
# longer than 600 seconds (the first one may download nixpkgs).
sys_nix_instantiate <- function(file) {
  lines <- sys_run("nix-instantiate", shQuote(file), timeout = 600)
  lines <- lines[nzchar(lines)]
  if (length(lines) == 0L) {
    return(NULL)
  }
  lines[[length(lines)]]
}

# The lines of `nix-store --query <args>`, such as --references, --outputs,
# --requisites or --graph and the store paths they apply to. NULL when Nix is
# missing or the query fails or takes longer than 600 seconds.
sys_nix_query <- function(args) {
  sys_run("nix-store", c("--query", shQuote(args)), timeout = 600)
}

# Whether each store path exists: whether an output has been built.
nix_store_exists <- function(paths) {
  file.exists(paths)
}

# The DESCRIPTION of R package `pkg` in the store output `out`, as
# read_description() gives it, or NULL when it cannot be read.
nix_store_description <- function(out, pkg) {
  file <- file.path(out, "library", pkg, "DESCRIPTION")
  if (!file.exists(file)) {
    return(NULL)
  }
  tryCatch(read_description(file), error = function(e) NULL)
}

# A CRAN PACKAGES file as a data frame with the columns Package, Version,
# Depends, Imports and LinkingTo (NA where the file lacks a field), from a
# local path or a URL. This is the only place sbom uses the network, and only
# when the user passes a snapshot. On failure it returns an empty list with
# the attribute `reason`, a fixed phrase that never holds a path.
read_packages_file <- function(location, timeout = 60) {
  fields <- c("Package", "Version", "Depends", "Imports", "LinkingTo")
  fail <- function(reason) structure(list(), reason = reason)
  remote <- grepl("^(https?|ftp|file)://", location)
  dcf <- tryCatch(
    {
      if (remote) {
        old <- options(timeout = timeout)
        on.exit(options(old), add = TRUE)
        con <- url(location)
        on.exit(try(close(con), silent = TRUE), add = TRUE)
        read.dcf(con, fields = fields)
      } else {
        read.dcf(location, fields = fields)
      }
    },
    warning = function(w) {
      m <- regmatches(conditionMessage(w), regexpr("HTTP status was '[0-9]{3}", conditionMessage(w)))
      structure(list(), status = sub("^HTTP status was '", "", m))
    },
    error = function(e) structure(list(), status = character())
  )
  if (!is.matrix(dcf)) {
    if (!remote) {
      return(fail("the snapshot file could not be read"))
    }
    code <- attr(dcf, "status")
    return(fail(paste0(
      "the snapshot could not be downloaded",
      if (length(code) == 1L) paste0(", HTTP status ", code)
    )))
  }
  if (nrow(dcf) == 0L || all(is.na(dcf[, "Package"]))) {
    return(fail("the snapshot lists no packages"))
  }
  out <- lapply(fields, function(f) enc2utf8_bytes(unname(dcf[, f])))
  data.frame(stats::setNames(out, fields), stringsAsFactors = FALSE)
}

# OSV's advisory data, downloaded from `url` to `dest`, a temporary file that
# the caller chose and removes. TRUE when the download finished, otherwise
# FALSE with the attribute `reason`, a fixed phrase that never holds a path
# or anything the server sent: "HTTP status <code>" or "the connection
# failed". With osv_lookup(), the only place sbom reaches OSV, and only when
# the user passes advisories = TRUE.
osv_download <- function(url, dest, timeout = 300) {
  fail <- function(reason) structure(FALSE, reason = reason)
  old <- options(timeout = timeout)
  on.exit(options(old), add = TRUE)
  status <- tryCatch(
    utils::download.file(url, dest, mode = "wb", quiet = TRUE),
    warning = function(w) {
      m <- regmatches(conditionMessage(w), regexpr("HTTP status was '[0-9]{3}", conditionMessage(w)))
      structure(NA_integer_, code = sub("^HTTP status was '", "", m))
    },
    error = function(e) structure(NA_integer_, code = character())
  )
  if (identical(as.integer(status), 0L) && file.exists(dest)) {
    return(TRUE)
  }
  code <- attr(status, "code")
  fail(if (length(code) == 1L) paste("HTTP status", code) else "the connection failed")
}

# The OSV record of the advisory `id`, as parsed JSON, read from
# https://api.osv.dev/v1/vulns/<id>; NULL when the server's answer cannot be
# read or is not a JSON object parsed as read_document() parses JSON, as for
# an HTTP error status; and FALSE, with the attribute `reason` "the
# connection failed", when no answer came: the lookup timed out or failed at
# the connection, so that the caller can stop looking up. Only an id that
# osv_id_ok() accepts is sent, and nothing else is: no package name leaves
# the machine.
osv_lookup <- function(id, timeout = 30) {
  if (!is_string(id) || !osv_id_ok(id)) {
    return(NULL)
  }
  old <- options(timeout = timeout)
  on.exit(options(old), add = TRUE)
  # R's url() names an HTTP status that the server answered with; any other
  # failure is one of the connection.
  failed <- function(cnd) {
    if (grepl("HTTP status was", conditionMessage(cnd), fixed = TRUE)) NULL else FALSE
  }
  bytes <- tryCatch(
    {
      con <- url(paste0("https://api.osv.dev/v1/vulns/", id), open = "rb")
      on.exit(try(close(con), silent = TRUE), add = TRUE)
      read_capped(con, osv_max_mb() * 2^20)
    },
    error = failed,
    warning = failed
  )
  if (isFALSE(bytes)) {
    return(structure(FALSE, reason = "the connection failed"))
  }
  if (is.null(bytes)) {
    return(NULL)
  }
  doc <- osv_parse_record(bytes)
  if (is.list(doc) && !is.null(names(doc))) doc else NULL
}

# The bytes of an open connection, or NULL when there are more than `cap`.
read_capped <- function(con, cap) {
  chunks <- list()
  total <- 0
  repeat {
    chunk <- readBin(con, "raw", n = 65536L)
    if (length(chunk) == 0L) {
      break
    }
    total <- total + length(chunk)
    if (total > cap) {
      return(NULL)
    }
    chunks[[length(chunks) + 1L]] <- chunk
  }
  if (length(chunks) == 0L) raw() else unlist(chunks)
}
