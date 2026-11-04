# Wrappers for what sbom asks of the operating system. Each is small so that
# tests can replace it, and each returns an empty result when its tool is
# missing or fails. Tests never run a real command.

# The lines a command prints, or NULL when the tool is not on the path, the
# command fails or it takes longer than `timeout` seconds.
sys_run <- function(command, args, timeout = 5) {
  if (!nzchar(Sys.which(command))) {
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
# `tool_missing` is TRUE when otool (macOS) or ldd (elsewhere) is not on the
# path, and `failed` is TRUE when the tool ran but failed or timed out, or
# when the file was not given to it. In either case the answer is unknown
# rather than empty.
sys_linked_libraries <- function(so_file) {
  mac <- identical(sys_os_name(), "Darwin")
  tool <- if (mac) "otool" else "ldd"
  # Older versions of ldd run a file that names its own program interpreter,
  # so ldd is given only ELF files without one.
  if (!mac && nzchar(Sys.which(tool)) && !identical(elf_has_interp(so_file), FALSE)) {
    return(structure(character(), versions = character(), tool_missing = FALSE, failed = TRUE))
  }
  lines <- sys_run(tool, if (mac) c("-L", shQuote(so_file)) else shQuote(so_file))
  if (is.null(lines)) {
    missing <- !nzchar(Sys.which(tool))
    return(structure(
      character(), versions = character(), tool_missing = missing, failed = !missing
    ))
  }
  parsed <- if (mac) parse_otool(lines, so_file) else parse_ldd(lines)
  structure(parsed$paths, versions = parsed$versions, tool_missing = FALSE, failed = FALSE)
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
# "/path (0x...)" such as the dynamic loader. A library that is not found has
# no path, and the kernel's vdso has none either.
parse_ldd <- function(lines) {
  lines <- trimws(lines)
  has_arrow <- grepl("=>", lines, fixed = TRUE)
  path <- ifelse(
    has_arrow, sub("^.*=>\\s*(\\S+).*$", "\\1", lines),
    ifelse(startsWith(lines, "/"), sub("^(\\S+).*$", "\\1", lines), NA_character_)
  )
  path <- path[!is.na(path) & startsWith(path, "/")]
  list(paths = path, versions = rep(NA_character_, length(path)))
}

# The operating system package that owns `path`, as
# list(manager, name, version, arch), or NULL when there is none or neither
# dpkg nor rpm is available.
sys_os_package <- function(path) {
  if (nzchar(Sys.which("dpkg"))) {
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
  if (nzchar(Sys.which("rpm"))) {
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
