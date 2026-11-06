# The slowest everyday calls: the writers of a large SBOM, the shared
# libraries of an R library, and sbom()'s cross-checks. They were made faster
# without changing a byte of what they write.

# A package `name` in `lib` with the compiled file libs/<name>.so.
local_compiled <- function(lib, name) {
  dir.create(file.path(lib, name, "libs"))
  write_text("", file.path(lib, name, "libs", paste0(name, ".so")))
}

test_that("each writer writes 20,000 components in seconds", {
  skip_on_cran()
  x <- read_sbom(generate_cdx(20000))
  formats <- c("spdx-tv", "spdx-yaml", "cyclonedx-xml")
  txt <- list()
  times <- numeric()
  for (f in formats) {
    times[[f]] <- system.time(txt[[f]] <- written(x, f, format_registry()[[f]]$default_version))[["elapsed"]]
  }
  count <- function(text, pattern) lengths(regmatches(text, gregexpr(pattern, text, fixed = TRUE)))
  expect_identical(count(txt[["spdx-tv"]], "\nPackageName: "), 20001L)
  expect_identical(count(txt[["spdx-yaml"]], "\n  - name: "), 20001L)
  expect_identical(count(txt[["cyclonedx-xml"]], " bom-ref=\"pkg:cran/comp"), 20000L)
  skip_unless_timing()
  expect_lt(times[["spdx-tv"]], 30)
  expect_lt(times[["spdx-yaml"]], 30)
  expect_lt(times[["cyclonedx-xml"]], 30)
})

test_that("tag-value lines written at once are those written one at a time, whatever their encodings", {
  utf8 <- "Caf\u00e9\n  au lait</text>"
  latin1 <- iconv("Na\u00efve\r\nline", "UTF-8", "latin1")
  # Bytes that are not ASCII, in no declared encoding: in a C locale, R
  # cannot match them beside a string that declares one.
  unmarked <- "Gr\u00fcn\n  tea</te</text>xt>"
  Encoding(unmarked) <- "unknown"
  local_c_ctype()
  tags <- c("A", "B", "C", "D", "E")
  values <- c(utf8, latin1, unmarked, unmarked, utf8)
  wrap <- c(FALSE, FALSE, FALSE, TRUE, TRUE)
  # Each line as the writer once wrote it, one regular expression a line.
  one_by_one <- vapply(seq_along(tags), function(i) {
    value <- values[[i]]
    if (wrap[[i]]) {
      while (grepl("</text>", value, fixed = TRUE)) value <- gsub("</text>", "", value, fixed = TRUE)
      value <- paste0("<text>", value, "</text>")
    } else {
      value <- gsub("[[:space:]]*[\r\n]+[[:space:]]*", " ", value)
    }
    paste0(tags[[i]], ": ", value)
  }, "")
  at_once <- tv_lines(tags, values, wrap)
  expect_identical(charToRaw(paste(at_once, collapse = "\n")), charToRaw(paste(one_by_one, collapse = "\n")))
})

test_that("otool or ldd reads each compiled file once in a build, however many packages hold it", {
  skip_on_os("windows")
  lib <- local_fake_lib(list(a = c(Version = "1.0"), b = c(Version = "1.0"), c = c(Version = "1.0")))
  local_compiled(lib, "a")
  local_compiled(lib, "b")
  # c holds a's compiled file, through a link to a's libs folder.
  dir.create(file.path(lib, "c"), showWarnings = FALSE)
  if (!isTRUE(file.symlink(file.path(lib, "a", "libs"), file.path(lib, "c", "libs")))) {
    skip("This file system makes no symbolic links.")
  }
  seen <- new.env()
  seen$files <- character()
  local_mocked_bindings(
    sys_linked_libraries = function(so) {
      seen$files <- c(seen$files, normalizePath(so))
      structure("/usr/lib/libcurl.so.4", versions = NA_character_)
    },
    sysreqs_match = function(spec, platform) NULL
  )
  x <- sbom_installed(lib = lib)
  expect_length(seen$files, 2L)
  expect_identical(anyDuplicated(seen$files), 0L)
  # Each package still links what its file links.
  rel <- sbom_dependencies(x)
  expect_setequal(rel$from[rel$field == "dynamic_link"], c("local/a", "local/b", "local/c"))
  # The next build reads them again: nothing is kept from one build to the next.
  sbom_installed(lib = lib)
  expect_length(seen$files, 4L)
})

test_that("each tool is looked up once in a build, and again in the next", {
  lib <- local_fake_lib(list(a = c(Version = "1.0"), b = c(Version = "1.0")))
  local_compiled(lib, "a")
  local_compiled(lib, "b")
  calls <- new.env()
  calls$which <- character()
  calls$run <- character()
  links <- c(a = "/usr/lib/libcurl.4.dylib", b = "/usr/lib/libssl.48.dylib")
  local_mocked_bindings(
    Sys.which = function(names) {
      calls$which <- c(calls$which, names)
      stats::setNames(ifelse(names == "otool", "/usr/bin/otool", ""), names)
    },
    system2 = function(command, args = character(), ...) {
      calls$run <- c(calls$run, command)
      # The file name, whatever quotes shQuote() put round it.
      file <- sub("[.]so$", "", basename(gsub("[\"']", "", args[[length(args)]])))
      line <- paste0("\t", links[[file]], " (compatibility version 1.0.0, current version 9.0.0)")
      c(paste0(file, ".so:"), line)
    },
    .package = "base"
  )
  local_mocked_bindings(
    sys_linked_libraries = sys_linked_libraries_real,
    sys_os_package = sys_os_package_real,
    sys_os_name = function() "Darwin",
    sysreqs_match = function(spec, platform) NULL
  )
  x <- sbom_installed(lib = lib)
  expect_true(all(c("system/libcurl", "system/libssl") %in% sbom_components(x)$ref))
  # otool runs once for each file, and is looked up once; so are dpkg and
  # rpm, however many libraries are asked about.
  expect_identical(sum(calls$run == "otool"), 2L)
  expect_identical(sum(calls$which == "otool"), 1L)
  expect_identical(sum(calls$which == "dpkg"), 1L)
  expect_identical(sum(calls$which == "rpm"), 1L)
  sbom_installed(lib = lib)
  expect_identical(sum(calls$run == "otool"), 4L)
  expect_identical(sum(calls$which == "otool"), 2L)
})

test_that("a build's cache is dropped however the build ends", {
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled(lib, "a")
  local_mocked_bindings(
    sys_linked_libraries = function(so) stop("otool broke"),
    sysreqs_match = function(spec, platform) NULL
  )
  expect_error(sbom_installed(lib = lib), "otool broke")
  expect_null(sys_cache$current)
  # The drop is with_sys_cache()'s own: an on.exit() in the code it runs
  # cannot replace it.
  build <- function() with_sys_cache({
    on.exit()
    sys_cached("answer", 42)
  })
  expect_identical(build(), 42)
  expect_null(sys_cache$current)
})

test_that("a cross-check sees the packages the full reader lists for the same root", {
  lib1 <- local_fake_lib(list(
    a = c(Version = "1.0", Repository = "CRAN", Imports = "deep"), deep = c(Version = "2.0"),
    linker = c(Version = "0.1", Repository = "CRAN"), broken = c(Package = "broken")
  ))
  lib2 <- local_fake_lib(list(only2 = c(Version = "3.0", RemoteType = "github", RemoteUsername = "u",
                                        RemoteRepo = "only2", RemoteSha = strrep("a", 40))))
  lib <- c(lib1, lib2)
  dir <- file.path(withr::local_tempdir(), "mypkg")
  dir.create(file.path(dir, "R"), recursive = TRUE)
  write_text(paste0(
    "Package: mypkg\nVersion: 1.0\nDepends: R (>= 4.1), methods, a\n",
    "Imports: a, only2, missingpkg, broken, mypkg\nLinkingTo: linker\nSuggests: sugg\n"
  ), file.path(dir, "DESCRIPTION"))
  write_text("library(a)\nlibrary(zzz)\nlibrary(mypkg)\nutils::head(1)\n", file.path(dir, "R", "x.R"))
  # What drift_issues() compares of a "direct" source.
  compared <- function(x) {
    v <- drift_view(x, "direct", suggests = FALSE)$components
    v <- v[!v$is_root %in% TRUE & !v$ecosystem %in% c("r", "base-r"), c("ref", "name", "ecosystem")]
    v <- v[order(v$ref, method = "radix"), , drop = FALSE]
    rownames(v) <- NULL
    v
  }
  full <- sbom_package(dir, lib = lib, embedded = FALSE, system = FALSE)
  light <- description_records(dir, lib = lib)
  expect_identical(compared(light), compared(full))
  expect_identical(light$metadata$inputs, full$metadata$inputs)
  expect_setequal(compared(light)$name, c("a", "only2", "missingpkg", "broken", "linker"))
  full <- code_scan(dir, lib = lib, embedded = FALSE, system = FALSE)
  light <- code_records(dir, lib = lib)
  expect_identical(compared(light), compared(full))
  expect_identical(light$metadata$inputs, full$metadata$inputs)
  expect_true(all(c("a", "zzz") %in% compared(light)$name))
  expect_false("mypkg" %in% compared(light)$name)
})

test_that("a cross-check reads only the packages it compares, and builds no SBOM of its own", {
  dir <- withr::local_tempdir()
  file.copy(test_path("fixtures/renv/modern/renv.lock"), dir)
  write_text(
    "Package: mypkg\nVersion: 1.0\nImports: cli, yyy\nSuggests: sss\n",
    file.path(dir, "DESCRIPTION")
  )
  write_text("library(zzz)\nlibrary(cli)\n", file.path(dir, "analysis.R"))
  lib <- local_fake_lib(list(
    cli = c(Version = "3.6.6", Repository = "CRAN"), yyy = c(Version = "1.0", Imports = "deep"),
    deep = c(Version = "2.0"), zzz = c(Version = "1.0", LinkingTo = "deep"), sss = c(Version = "1.0")
  ))
  calls <- new.env()
  counted <- function(name, f) {
    force(f)
    calls[[name]] <- 0L
    function(...) {
      calls[[name]] <- calls[[name]] + 1L
      f(...)
    }
  }
  real_resolve <- resolve_dependencies
  calls$followed <- logical()
  local_mocked_bindings(
    build_sbom = counted("build", build_sbom),
    resolve_dependencies = function(..., recurse = TRUE) {
      calls$followed <- c(calls$followed, recurse)
      real_resolve(..., recurse = recurse)
    },
    linkingto_components = counted("linkingto", linkingto_components),
    detect_bundled = counted("bundled", detect_bundled),
    declared_system_requirements = counted("declared", declared_system_requirements),
    linked_system_libraries = counted("linked", linked_system_libraries)
  )
  x <- sbom(dir, lib = lib)
  # Only renv.lock, the source of the SBOM, is built, with what it carries
  # and what it links; DESCRIPTION and the code are only compared, from the
  # packages they name themselves, none followed.
  expect_identical(calls$build, 1L)
  expect_identical(calls$followed, c(FALSE, FALSE))
  expect_identical(
    c(calls$linkingto, calls$bundled, calls$declared, calls$linked),
    c(1L, 1L, 1L, 1L)
  )
  iss <- sbom_issues(x)
  drift <- iss$message[iss$code %in% c("drift-extra", "drift-missing", "drift-version")]
  # renv's scan of the code reads DESCRIPTION too.
  expect_identical(sort(drift, method = "radix"), c(
    "yyy is in DESCRIPTION but not in renv.lock.",
    "yyy is in the code but not in renv.lock.",
    "zzz is in the code but not in renv.lock."
  ))
  expect_identical(
    x$metadata$inputs$kind,
    c("renv.lock", "DESCRIPTION", "library", "code")
  )
})

test_that("the writers' output is byte-identical to what they wrote before they were made faster", {
  # The digests were taken from the writers before this change. Like every
  # snapshot, they are not compared on CRAN, whose jsonlite may differ, so
  # the SBOMs are not built there either. SPDX XML and SWID tags, which
  # this change did not touch and which libxml2 still writes, are left out:
  # another libxml2 may write them otherwise.
  skip_on_cran()
  # Nothing that depends on when the test runs, or on sbom's own version.
  steady <- function(x) {
    x$metadata$tool_version <- "0.1.0"
    x$metadata$notes <- sub(
      "on [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z", "on 2026-01-01T00:00:00Z", x$metadata$notes
    )
    x
  }
  sboms <- list(
    fixture = fixture_sbom(),
    minimal = minimal_sbom(),
    library = sbom_installed(lib = fixture_lib(), author = "Tester", timestamp = 0),
    advisory = two_advisory_sbom()
  )
  pinned <- Filter(function(fv) !fv$format %in% c("spdx-xml", "swid"), every_format_version())
  digests <- unlist(lapply(names(sboms), function(name) {
    x <- steady(sboms[[name]])
    vapply(pinned, function(fv) {
      paste(name, fv$format, fv$version, cli::hash_raw_sha256(charToRaw(written(x, fv$format, fv$version))))
    }, "")
  }))
  expect_length(digests, 4L * length(pinned))
  expect_snapshot(writeLines(digests))
})
