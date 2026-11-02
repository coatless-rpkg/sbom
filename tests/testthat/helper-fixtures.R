local_latin1_pkg <- function(env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  lines <- c(
    "Package: latin1pkg",
    "Version: 1.0",
    "Encoding: latin1",
    "Maintainer: Gábor Csárdi <g@example.org>"
  )
  con <- file(file.path(dir, "DESCRIPTION"), "wb")
  on.exit(close(con))
  writeLines(iconv(lines, from = "UTF-8", to = "latin1"), con, useBytes = TRUE)
  dir
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
      inputs = data.frame(kind = character(), path = character())
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
