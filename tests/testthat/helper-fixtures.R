# Writes `lines` (UTF-8 in this file) to dir/DESCRIPTION as bytes in `encoding`.
write_description_bytes <- function(dir, lines, encoding = "UTF-8") {
  con <- file(file.path(dir, "DESCRIPTION"), "wb")
  on.exit(close(con))
  writeLines(iconv(lines, from = "UTF-8", to = encoding), con, useBytes = TRUE)
  invisible(dir)
}

# A package whose DESCRIPTION is latin1 bytes, alone in a library (its parent
# directory). `declare = FALSE` leaves out the Encoding field.
local_latin1_pkg <- function(declare = TRUE, env = parent.frame()) {
  lib <- withr::local_tempdir(.local_envir = env)
  dir <- file.path(lib, "latin1pkg")
  dir.create(dir)
  lines <- c(
    "Package: latin1pkg",
    "Version: 1.0",
    if (declare) "Encoding: latin1",
    "Maintainer: Gábor Csárdi <g@example.org>"
  )
  write_description_bytes(dir, lines, "latin1")
  dir
}

# Runs the rest of the calling test with LC_CTYPE = "C", where R treats the
# native encoding as ASCII. Skips when the platform refuses that locale.
local_c_ctype <- function(env = parent.frame()) {
  suppressWarnings(withr::local_locale(c(LC_CTYPE = "C"), .local_envir = env))
  if (!identical(Sys.getlocale("LC_CTYPE"), "C")) {
    testthat::skip("This platform refuses LC_CTYPE = C.")
  }
}

minimal_sbom <- function() {
  comps <- empty_components()
  row <- function(ref, name, version, type, ecosystem, is_root, purl) {
    data.frame(
      ref = ref, name = name, version = version, version_is = "exact",
      type = type, ecosystem = ecosystem, is_root = is_root,
      scope = "required", parent_ref = NA_character_, purl = purl,
      stringsAsFactors = FALSE
    )
  }
  rows <- rbind(
    row("pkg:cran/a@1.0", "a", "1.0", "library", "cran", TRUE, "pkg:cran/a@1.0"),
    row("pkg:cran/b@2.0", "b", "2.0", "library", "cran", FALSE, "pkg:cran/b@2.0"),
    row("R", "R", NA_character_, "platform", "r", FALSE, NA_character_)
  )
  for (col in setdiff(component_columns(), names(rows))) {
    rows[[col]] <- if (col %in% c("hashes", "deps", "asserted")) {
      replicate(nrow(rows), data.frame(), simplify = FALSE)
    } else if (col == "deps_known") {
      TRUE
    } else {
      NA_character_
    }
  }
  rows <- rows[, component_columns()]
  rels <- data.frame(
    from = "pkg:cran/a@1.0", to = "pkg:cran/b@2.0", field = "Imports",
    spec = NA_character_, evidence = "declared", stringsAsFactors = FALSE
  )
  new_sbom(
    list(
      root = "pkg:cran/a@1.0",
      timestamp = as.POSIXct("2026-11-04", tz = "UTC"),
      author = NA_character_,
      organization = NA_character_,
      tool_version = as.character(utils::packageVersion("sbom")),
      notes = character(),
      inputs = data.frame(kind = character(), path = character()),
      regid = NA_character_
    ),
    rows, rels, empty_issues()
  )
}

local_fake_lib <- function(pkgs, env = parent.frame()) {
  lib <- withr::local_tempdir(.local_envir = env)
  for (name in names(pkgs)) {
    fields <- pkgs[[name]]
    dir.create(file.path(lib, name))
    fields <- c(Package = name, fields[names(fields) != "Package"])
    writeLines(
      paste0(names(fields), ": ", unname(fields)),
      file.path(lib, name, "DESCRIPTION")
    )
  }
  lib
}

fixture_lib <- function(env = parent.frame()) {
  local_fake_lib(
    list(
      cranpkg = c(
        Version = "1.2.0", Repository = "CRAN", License = "GPL-2 | GPL-3",
        Maintainer = "Grace Hopper <grace@example.org>", Imports = "methods",
        `Date/Publication` = "2026-01-02 10:00:00 UTC",
        URL = "https://github.com/example/cranpkg"
      ),
      localpkg = c(
        Version = "0.0.1", License = "file LICENSE",
        Maintainer = "Alan Turing <alan@example.org>"
      ),
      suggestpkg = c(
        Version = "2.0.0", Repository = "CRAN", License = "MIT + file LICENSE",
        Maintainer = "X Y <x@example.org>", Imports = "deeppkg"
      ),
      oldpkg = c(
        Version = "1.0.0", Repository = "CRAN", License = "MIT + file LICENSE",
        Maintainer = "Old <o@example.org>"
      )
    ),
    env = env
  )
}

fixture_sbom <- function(env = parent.frame()) {
  sbom_package(
    test_path("fixtures/pkgs/srcpkg"),
    lib = fixture_lib(env = env), author = "Test Author",
    organization = "Test Org", timestamp = as.POSIXct("2026-11-04", tz = "UTC")
  )
}

# A copy of the fixture folder `fixture` in a new temporary folder, under the
# name `name`, so that it is not inside this package's git repository.
local_fixture_copy <- function(fixture, name = basename(fixture), env = parent.frame()) {
  dir <- file.path(withr::local_tempdir(.local_envir = env), name)
  dir.create(dir)
  src <- test_path(fixture)
  file.copy(list.files(src, full.names = TRUE, all.files = TRUE, no.. = TRUE), dir, recursive = TRUE)
  dir
}

# Writes `x` in every format, and checks each against its schema where the
# package that checks it is installed: jsonvalidate for every format checked
# against a JSON schema, and yaml too for SPDX YAML. Without them the schema
# layer rightly says "skipped", so the format is only written; the caller
# goes on, as it would not after skip_if_not_installed().
expect_valid_in_every_format <- function(x, label = "") {
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  expected <- c(`cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
                `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "partial")
  if (!requireNamespace("jsonvalidate", quietly = TRUE)) {
    expected <- expected[c("cyclonedx-xml", "swid")]
  }
  if (!requireNamespace("yaml", quietly = TRUE)) {
    expected <- expected[names(expected) != "spdx-yaml"]
  }
  for (f in names(ext)) {
    tf <- withr::local_tempfile(fileext = ext[[f]])
    write_sbom(x, tf, format = f)
    if (f %in% names(expected)) {
      expect_identical(schema_validate(tf, f)$status, expected[[f]], label = paste(label, f))
    } else {
      expect_true(file.exists(tf), label = paste(label, f))
    }
  }
}

# Folder of a fake library, with one DESCRIPTION per element of `pkgs` (a
# named list of named field vectors), written with write_text().
write_fake_lib <- function(lib, pkgs) {
  for (name in names(pkgs)) {
    fields <- c(Package = name, pkgs[[name]])
    dir.create(file.path(lib, name), recursive = TRUE, showWarnings = FALSE)
    write_text(paste0(paste0(names(fields), ": ", unname(fields)), "\n", collapse = ""),
               file.path(lib, name, "DESCRIPTION"))
  }
  lib
}

# Every format sbom writes as an SBOM, at every version, as list(format,
# version, extension).
every_format_version <- function() {
  reg <- format_registry()
  keys <- setdiff(names(reg), "csv")
  unlist(lapply(keys, function(f) {
    lapply(reg[[f]]$versions, function(v) list(format = f, version = v, extension = reg[[f]]$extension))
  }), recursive = FALSE)
}

# The text of `x` written in format `f` at version `v`.
written <- function(x, f, v) {
  format_registry()[[f]]$writer(x, v)
}

# cli output at a fixed width, without colors or Unicode, for snapshots.
local_plain_cli <- function(env = parent.frame()) {
  withr::local_options(cli.width = 80, cli.num_colors = 1, cli.unicode = FALSE, .local_envir = env)
}
