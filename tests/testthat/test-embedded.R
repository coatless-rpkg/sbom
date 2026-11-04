cdx_or <- function(a, b) if (is.null(a)) b else a

test_that("a LinkingTo package becomes an embedded component of its parent", {
  x <- fixture_sbom()
  comps <- sbom_components(x)
  e <- comps[comps$ref == "local/srcpkg#embedded/cranpkg", ]
  expect_equal(nrow(e), 1L)
  expect_equal(e$parent_ref, "local/srcpkg")
  expect_equal(e$version, "1.2.0")
  expect_equal(e$evidence, "inferred")
  expect_equal(e$type, "library")
  expect_equal(e$purl, "pkg:cran/cranpkg@1.2.0")
  expect_equal(e$description, paste0(
    "Compiled into srcpkg from the headers of cranpkg 1.2.0, the version installed in the library ",
    "sbom read; nothing records the version used at build time."
  ))
  expect_equal(e$license_spdx, "GPL-2.0-only OR GPL-3.0-only")
  expect_equal(e$license_as_written, comps$license_as_written[comps$ref == "pkg:cran/cranpkg@1.2.0"])
  expect_true("pkg:cran/cranpkg@1.2.0" %in% comps$ref)
  rel <- sbom_dependencies(x)
  expect_true(any(rel$from == "local/srcpkg" & rel$to == e$ref & rel$field == "contains"))
  expect_true(any(rel$from == "local/srcpkg" & rel$to == "pkg:cran/cranpkg@1.2.0" & rel$field == "LinkingTo"))
})

test_that("a LinkingTo package that is not installed has no version or purl", {
  desc <- withr::local_tempdir()
  write_text("Package: p\nVersion: 1\nLinkingTo: ghostpkg\n", file.path(desc, "DESCRIPTION"))
  x <- sbom_package(desc, lib = fixture_lib())
  comps <- sbom_components(x)
  e <- comps[grepl("#embedded/ghostpkg", comps$ref, fixed = TRUE), ]
  expect_equal(nrow(e), 1L)
  expect_true(is.na(e$version))
  expect_true(is.na(e$purl))
  expect_true(is.na(e$ecosystem))
  expect_equal(e$description, paste0(
    "Compiled into p from the headers of ghostpkg, which is not installed in the library sbom read; ",
    "nothing records the version used at build time."
  ))
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "embedded-not-installed"], paste0(
    "ghostpkg is compiled into p 1 through LinkingTo, but is not installed in the library sbom read, ",
    "so its version is unknown."
  ))
  expect_equal(iss$severity[iss$code == "embedded-not-installed"], "info")
  expect_valid_in_every_format(x)
})

test_that("LinkingTo packages that are not installed are named in one issue", {
  desc <- withr::local_tempdir()
  write_text("Package: p\nVersion: 1\nLinkingTo: ghostpkg, phantompkg\n", file.path(desc, "DESCRIPTION"))
  iss <- sbom_issues(sbom_package(desc, lib = fixture_lib()))
  expect_equal(iss$message[iss$code == "embedded-not-installed"], paste0(
    "ghostpkg and phantompkg are compiled into p 1 through LinkingTo, but are not installed in the ",
    "library sbom read, so their versions are unknown."
  ))
})

test_that("a LinkingTo copy in an renv SBOM names the lockfile as its version's source", {
  dir <- withr::local_tempdir()
  lock <- list(R = list(Version = "4.6.2"), Packages = list(
    a = list(Package = "a", Version = "1.0", Source = "Repository", Repository = "CRAN", LinkingTo = list("b")),
    b = list(Package = "b", Version = "2.0", Source = "Repository", Repository = "CRAN", License = "MIT")
  ))
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE, pretty = TRUE), file.path(dir, "renv.lock"))
  x <- sbom_renv(file.path(dir, "renv.lock"), library = local_fake_lib(list()), system = FALSE)
  comps <- sbom_components(x)
  e <- comps[grepl("#embedded/b", comps$ref, fixed = TRUE), ]
  expect_equal(e$description, paste0(
    "Compiled into a from the headers of b 2.0, the version recorded in renv.lock; ",
    "nothing records the version used at build time."
  ))
  expect_equal(e$license_spdx, "MIT")
})

test_that("embedded components nest in CycloneDX and validate everywhere", {
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  x <- fixture_sbom()
  d <- cdx_document(x)
  root_children <- vapply(cdx_or(d$metadata$component$components, list()), `[[`, "", "bom-ref")
  expect_true("local/srcpkg#embedded/cranpkg" %in% root_children)
  dep_refs <- vapply(d$dependencies, `[[`, "", "ref")
  expect_false("local/srcpkg#embedded/cranpkg" %in% dep_refs)
  top <- vapply(d$components, `[[`, "", "bom-ref")
  expect_false("local/srcpkg#embedded/cranpkg" %in% top)
  expected <- c(`cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
                `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "pass")
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  for (f in names(expected)) {
    tf <- withr::local_tempfile(fileext = ext[[f]]); write_sbom(x, tf, format = f)
    expect_identical(schema_validate(tf, f)$status, expected[[f]], label = f)
  }
})

test_that("the other writers record the embedded component", {
  x <- fixture_sbom()
  doc <- spdx_document(x)
  ids <- vapply(doc$packages, `[[`, "", "SPDXID")
  expect_true("SPDXRef-embedded-cranpkg" %in% ids)
  rel <- doc$relationships
  expect_true(any(vapply(rel, function(r) {
    r$relationshipType == "CONTAINS" && r$spdxElementId == "SPDXRef-local-srcpkg" &&
      r$relatedSpdxElement == "SPDXRef-embedded-cranpkg"
  }, NA)))
  csv <- utils::read.csv(text = sub("^﻿", "", csv_inventory(x)), check.names = FALSE)
  expect_equal(names(csv)[ncol(csv)], "parent")
  expect_equal(csv$parent[csv$ref == "local/srcpkg#embedded/cranpkg"], "local/srcpkg")
  swid <- swid_tag(x)
  expect_false(grepl("#embedded/", swid, fixed = TRUE))
})

test_that("a package both embedded and a dependency keeps two components", {
  x <- fixture_sbom()
  comps <- sbom_components(x)
  expect_equal(sum(comps$name == "cranpkg"), 2L)
  expect_false(anyDuplicated(comps$ref) > 0L)
})

test_that("embedded components do not break overrides, diffs or drift", {
  x <- fixture_sbom()
  y <- apply_overrides(x, data.frame(
    component = "cranpkg", field = "license_spdx", value = "MIT",
    asserted_by = "me", reason = "checked"
  ))
  comps <- sbom_components(y)
  expect_equal(comps$license_spdx[comps$ref == "pkg:cran/cranpkg@1.2.0"], "MIT")
  expect_false(identical(comps$license_spdx[grepl("#embedded/", comps$ref)], "MIT"))
  expect_equal(nrow(as.data.frame(sbom_diff(x, x))), 0L)
  expect_false(any(grepl("#embedded/", drift_view(x, "all")$components$ref)))
})

test_that("embedded = FALSE leaves them out", {
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), embedded = FALSE)
  expect_false(any(grepl("#embedded/", sbom_components(x)$ref)))
})

test_that("every builder takes embedded and system", {
  for (f in list(sbom_package, sbom_installed, sbom_renv, sbom_rsconnect)) {
    expect_true(all(c("embedded", "system") %in% names(formals(f))))
  }
})

test_that("sbom() forwards embedded and system", {
  dir <- local_fixture_copy("fixtures/pkgs/srcpkg")
  x <- sbom(dir, lib = fixture_lib(), embedded = FALSE, system = FALSE)
  expect_false(any(grepl("#embedded/", sbom_components(x)$ref)))
  y <- sbom(dir, lib = fixture_lib())
  expect_true(any(grepl("#embedded/", sbom_components(y)$ref)))
})

test_that("sbom_diff() matches embedded components by ref", {
  old <- fixture_sbom()
  new <- old
  new$components$version[new$components$ref == "local/srcpkg#embedded/cranpkg"] <- "9.9.9"
  ch <- as.data.frame(sbom_diff(old, new))
  expect_equal(nrow(ch), 1L)
  expect_equal(ch$change, "version")
  expect_equal(ch$new, "9.9.9")
})

test_that("vendored libraries are found in src/, COPYRIGHTS and cph entries", {
  x <- sbom_package(test_path("fixtures/pkgs/vendorpkg"), lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  s <- comps[comps$name == "sqlite", ]
  expect_equal(s$version, "3.45.1")
  expect_equal(s$purl, "pkg:generic/sqlite@3.45.1")
  expect_equal(s$ecosystem, "vendored")
  expect_equal(s$ref, "local/vendorpkg#vendored/sqlite")
  expect_equal(s$parent_ref, "local/vendorpkg")
  expect_equal(s$evidence, "inferred")
  expect_equal(s$description, "Bundled in vendorpkg as source code, version 3.45.1 read from src/sqlite3/sqlite3.h.")
  expect_true(all(c("libuv", "zstd") %in% comps$name[comps$ecosystem == "vendored"]))
  expect_true(all(is.na(comps$version[comps$name %in% c("libuv", "zstd")])))
  expect_true(all(is.na(comps$purl[comps$name %in% c("libuv", "zstd")])))
  expect_equal(comps$description[comps$name == "libuv"], "Named in vendorpkg's COPYRIGHTS file.")
  expect_match(comps$license_comment[comps$name == "libuv"], "usual one for libuv", fixed = TRUE)
  expect_equal(comps$license_spdx[comps$name == "libuv"], "MIT")
  rel <- sbom_dependencies(x)
  expect_true(any(rel$from == "local/vendorpkg" & rel$to == s$ref & rel$field == "contains"))
  expect_valid_in_every_format(x)
})

test_that("embedded = FALSE skips vendored detection", {
  x <- sbom_package(test_path("fixtures/pkgs/vendorpkg"), lib = local_fake_lib(list()), embedded = FALSE)
  expect_false(any(sbom_components(x)$ecosystem == "vendored"))
})

test_that("an installed package is searched through its COPYRIGHTS file and cph names", {
  lib <- local_fake_lib(list(cpkg = c(
    Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE",
    Maintainer = "A B <a@example.org>",
    `Authors@R` = 'c(person("A", "B", role = c("aut", "cre")), person("The LZ4 authors", role = "cph"))'
  )))
  dir.create(file.path(lib, "cpkg", "libs"))
  write_text("Bundles SQLite and a utf8procish thing.\n", file.path(lib, "cpkg", "COPYRIGHTS"))
  x <- sbom_installed("cpkg", lib = lib)
  comps <- sbom_components(x)
  v <- comps[comps$ecosystem == "vendored", ]
  expect_equal(sort(v$name), c("lz4", "sqlite"))
  expect_true(all(is.na(v$version)))
  expect_equal(v$description[v$name == "lz4"], "Named as a copyright holder in cpkg's Authors@R.")
  expect_equal(v$ref[v$name == "sqlite"], "pkg:cran/cpkg@1.0#vendored/sqlite")
  expect_false("compiled-code-limited" %in% sbom_issues(x)$code)
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "vendored-version-unknown"],
    "sbom found no version for the bundled lz4 in cpkg 1.0 and sqlite in cpkg 1.0.")
  expect_equal(iss$severity[iss$code == "vendored-version-unknown"], "info")
})

test_that("one bundled library without a version is named alone, and a known version gives no issue", {
  lib <- local_fake_lib(list(cpkg = c(Version = "1.0")))
  write_text("Bundles libuv.\n", file.path(lib, "cpkg", "COPYRIGHTS"))
  iss <- sbom_issues(sbom_installed("cpkg", lib = lib))
  expect_equal(iss$message[iss$code == "vendored-version-unknown"],
    "sbom found no version for the bundled libuv in cpkg 1.0.")
  x <- sbom_package(test_path("fixtures/pkgs/vendorpkg"), lib = local_fake_lib(list()))
  msg <- sbom_issues(x)$message[sbom_issues(x)$code == "vendored-version-unknown"]
  expect_false(grepl("sqlite", msg, fixed = TRUE))
})

test_that("zstd and mbedtls keep both sides of their dual licences", {
  r <- vendored_rules()
  expect_equal(r$license[r$name == "zstd"], "BSD-3-Clause OR GPL-2.0-only")
  expect_equal(r$license[r$name == "mbedtls"], "Apache-2.0 OR GPL-2.0-or-later")
  lib <- local_fake_lib(list(cpkg = c(Version = "1.0", License = "MIT")))
  write_text("Bundles zstd and Mbed TLS.\n", file.path(lib, "cpkg", "COPYRIGHTS"))
  x <- sbom_installed("cpkg", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$license_spdx[comps$name == "zstd"], "BSD-3-Clause OR GPL-2.0-only")
  expect_equal(comps$license_spdx[comps$name == "mbedtls"], "Apache-2.0 OR GPL-2.0-or-later")
  pkgs <- spdx_document(x)$packages
  declared <- vapply(pkgs, function(p) paste(p$name, p$licenseDeclared), "")
  expect_true("zstd BSD-3-Clause OR GPL-2.0-only" %in% declared)
  expect_valid_in_every_format(x)
})

test_that("an installed package with compiled code and no clues raises one issue", {
  lib <- local_fake_lib(list(cpkg = c(Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE",
                                      Maintainer = "A B <a@example.org>")))
  dir.create(file.path(lib, "cpkg", "libs"))
  x <- sbom_installed("cpkg", lib = lib)
  iss <- sbom_issues(x)[sbom_issues(x)$code == "compiled-code-limited", ]
  expect_equal(nrow(iss), 1L)
  expect_equal(iss$severity, "info")
  expect_equal(iss$field, "embedded")
  expect_equal(iss$ref, sbom_components(x)$ref[sbom_components(x)$is_root])
  expect_equal(
    iss$message,
    paste0("1 package contains compiled code, but sbom recognised no bundled library in its COPYRIGHTS ",
           "file or cph entries, so it could not look inside it: cpkg 1.0.")
  )
  expect_false(any(sbom_components(x)$ecosystem == "vendored"))
})

test_that("an installed package without compiled code raises no issue", {
  lib <- local_fake_lib(list(rpkg = c(Version = "1.0", License = "MIT")))
  x <- sbom_installed("rpkg", lib = lib)
  expect_false("compiled-code-limited" %in% sbom_issues(x)$code)
})

test_that("a word inside a longer word does not name a library", {
  expect_false(names_word("the sqlite3x engine and zstdlib", c("sqlite", "zstd")))
  expect_true(names_word("Copyright (c) SQLite3 authors", c("sqlite", "sqlite3")))
  expect_true(names_word("{fmt} by Victor", "fmt"))
})

test_that("every vendored rule's version regex matches its documented macro", {
  r <- vendored_rules()
  expect_true(all(c("sqlite", "libuv", "zstd", "lz4", "mbedtls", "libgit2") %in% r$name))
  expect_match('#define SQLITE_VERSION        "3.45.1"', r$version_regex[r$name == "sqlite"], perl = TRUE)
  samples <- list(
    sqlite = c('#define SQLITE_VERSION        "3.45.1"', "3.45.1"),
    libuv = c("#define UV_VERSION_MAJOR 1\n#define UV_VERSION_MINOR 46\n#define UV_VERSION_PATCH 0\n", "1.46.0"),
    zstd = c("#define ZSTD_VERSION_MAJOR    1\n#define ZSTD_VERSION_MINOR    5\n#define ZSTD_VERSION_RELEASE  5\n", "1.5.5"),
    lz4 = c("#define LZ4_VERSION_MAJOR    1    /* for breaking interface changes  */\n#define LZ4_VERSION_MINOR    9    /* for new (non-breaking) interface capabilities */\n#define LZ4_VERSION_RELEASE  4    /* for tweaks, bug-fixes, or development */\n", "1.9.4"),
    mbedtls = c('#define MBEDTLS_VERSION_STRING         "2.28.0"', "2.28.0"),
    libgit2 = c('#define LIBGIT2_VERSION "1.7.1"', "1.7.1"),
    miniz = c('#define MZ_VERSION "11.0.2"', "11.0.2"),
    pcre2 = c("#define PCRE2_MAJOR          10\n#define PCRE2_MINOR          42\n", "10.42"),
    libdeflate = c('#define LIBDEFLATE_VERSION_STRING  "1.19"', "1.19"),
    utf8proc = c("#define UTF8PROC_VERSION_MAJOR 2\n#define UTF8PROC_VERSION_MINOR 9\n#define UTF8PROC_VERSION_PATCH 0\n", "2.9.0"),
    fmt = c("#define FMT_VERSION 100201", "10.2.1")
  )
  for (name in names(samples)) {
    expect_equal(
      vendored_version(samples[[name]][[1L]], r$version_regex[r$name == name]),
      samples[[name]][[2L]], label = name
    )
  }
  expect_equal(vendored_version("#define FMT_VERSION 80100", r$version_regex[r$name == "fmt"]), "8.1.0")
  # tinyformat has no version macro.
  expect_equal(r$version_regex[r$name == "tinyformat"], "")
  expect_setequal(names(samples), setdiff(r$name, "tinyformat"))
})

test_that("a version file's text is read only up to a bound, and a huge file is skipped", {
  dir <- withr::local_tempdir()
  write_text(paste0(strrep("x", 70000), '#define SQLITE_VERSION "3.1.1"'), file.path(dir, "late.h"))
  expect_false(grepl("SQLITE_VERSION", read_text_bounded(file.path(dir, "late.h"))))
  expect_null(read_text_bounded(file.path(dir, "late.h"), max_size = 100))
})

test_that("a tinyformat directory is found without a version", {
  pkg <- withr::local_tempdir()
  write_text("Package: tf\nVersion: 1\n", file.path(pkg, "DESCRIPTION"))
  dir.create(file.path(pkg, "src", "tinyformat"), recursive = TRUE)
  write_text("// tinyformat\n", file.path(pkg, "src", "tinyformat", "tinyformat.h"))
  x <- sbom_package(pkg, lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  expect_equal(comps$description[comps$name == "tinyformat"], "Bundled in tf as source code.")
  expect_true(is.na(comps$version[comps$name == "tinyformat"]))
})

test_that("a component whose parent is not in the document is written at the top level", {
  x <- fixture_sbom()
  x$components$parent_ref[x$components$ref == "local/srcpkg#embedded/cranpkg"] <- "ghost/parent"
  d <- cdx_document(x)
  top <- vapply(cdx_or(d$components, list()), `[[`, "", "bom-ref")
  expect_true("local/srcpkg#embedded/cranpkg" %in% top)
})

test_that("several packages with compiled code share one issue, labels in radix order", {
  f <- c(Version = "1.0", Repository = "CRAN", License = "MIT", Maintainer = "A B <a@example.org>")
  lib <- local_fake_lib(list(zeta = f, Alpha = f, mid = f))
  for (p in c("zeta", "Alpha", "mid")) dir.create(file.path(lib, p, "libs"))
  x <- sbom_installed(c("zeta", "Alpha", "mid"), lib = lib)
  iss <- sbom_issues(x)[sbom_issues(x)$code == "compiled-code-limited", ]
  expect_equal(nrow(iss), 1L)
  expect_equal(
    iss$message,
    paste0("3 packages contain compiled code, but sbom recognised no bundled library in their COPYRIGHTS ",
           "file or cph entries, so it could not look inside them: Alpha 1.0, mid 1.0, zeta 1.0.")
  )
})

test_that("bundled JavaScript is found in htmlwidgets YAML and by header", {
  skip_if_not_installed("yaml")
  x <- sbom_package(test_path("fixtures/pkgs/widgetpkg"), lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  js <- comps[comps$ecosystem == "npm", ]
  expect_setequal(js$name, c("d3", "jquery"))
  expect_equal(js$evidence[js$name == "d3"], "declared")
  expect_equal(js$evidence[js$name == "jquery"], "inferred")
  expect_equal(js$purl[js$name == "jquery"], "pkg:npm/jquery@3.7.1")
  expect_equal(js$purl[js$name == "d3"], "pkg:npm/d3@7.8.5")
  expect_equal(js$ref[js$name == "jquery"], "local/widgetpkg#js/jquery@3.7.1")
  expect_equal(js$ref[js$name == "d3"], "local/widgetpkg#js/d3@7.8.5")
  expect_equal(js$parent_ref, rep("local/widgetpkg", 2L))
  expect_equal(js$description[js$name == "d3"], "Declared in inst/htmlwidgets/widgetpkg.yaml.")
  expect_equal(
    js$description[js$name == "jquery"],
    "Found as inst/www/jquery.min.js in widgetpkg; the version comes from its header comment."
  )
  expect_false(any(grepl("app|notes", js$name)))
  expect_true(all(is.na(js$license_spdx)))
  issues <- sbom_issues(x)
  note <- issues[issues$code == "javascript-license-not-read", ]
  expect_equal(nrow(note), 1L)
  expect_equal(note$severity, "info")
  expect_equal(
    note$message,
    "sbom does not read the licences of bundled JavaScript, so these have none recorded: d3 7.8.5, jquery 3.7.1."
  )
  expect_false(any(issues$code == "license-missing" & grepl("#js/", issues$ref, fixed = TRUE)))
  rel <- sbom_dependencies(x)
  expect_true(any(rel$from == "local/widgetpkg" & rel$to == js$ref[1L] & rel$field == "contains"))
  expect_valid_in_every_format(x)
})

test_that("without yaml, the declared dependencies are noted, not invented", {
  local_mocked_bindings(has_yaml = function() FALSE)
  x <- sbom_package(test_path("fixtures/pkgs/widgetpkg"), lib = local_fake_lib(list()))
  expect_true("htmlwidgets-not-read" %in% sbom_issues(x)$code)
  expect_match(
    sbom_issues(x)$message[sbom_issues(x)$code == "htmlwidgets-not-read"],
    "widgetpkg 1.0 declares JavaScript dependencies in inst/htmlwidgets/widgetpkg.yaml, which sbom could not read because the yaml package is not installed.",
    fixed = TRUE
  )
  comps <- sbom_components(x)
  # The header of d3.min.js still finds d3, as inferred.
  expect_equal(comps$evidence[comps$name == "d3"], "inferred")
})

test_that("embedded = FALSE skips bundled JavaScript", {
  x <- sbom_package(test_path("fixtures/pkgs/widgetpkg"), lib = local_fake_lib(list()), embedded = FALSE)
  expect_false(any(sbom_components(x)$ecosystem == "npm"))
})

test_that("every JavaScript rule matches a one-line sample of its real header", {
  rules <- javascript_rules()
  samples <- list(
    jquery = c("jquery.min.js", "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */", "3.7.1"),
    bootstrap = c("bootstrap.bundle.min.js", "/*! * Bootstrap v5.3.1 (https://getbootstrap.com/) * Copyright 2011-2023 The Bootstrap Authors */", "5.3.1"),
    d3 = c("d3.min.js", "// https://d3js.org v7.8.5 Copyright 2010-2023 Mike Bostock", "7.8.5"),
    datatables = c("jquery.dataTables.min.js", "/*! DataTables 1.13.6 * ©2008-2023 SpryMedia Ltd - datatables.net/license */", "1.13.6"),
    leaflet = c("leaflet.js", "/* @preserve * Leaflet 1.9.4, a JS library for interactive maps. https://leafletjs.com */", "1.9.4"),
    plotly.js = c("plotly-latest.min.js", "/** * plotly.js v2.25.2 * Copyright 2012-2023, Plotly, Inc. */", "2.25.2"),
    highlight.js = c("highlight.min.js", "/*! highlight.js v11.8.0 (git: 65687a907b) | (c) 2006-2023 undefined and other contributors | License: BSD-3-Clause */", "11.8.0"),
    `font-awesome` = c("all.min.css", "/*! * Font Awesome Free 6.4.2 by @fontawesome - https://fontawesome.com */", "6.4.2")
  )
  expect_setequal(rules$name, names(samples))
  for (name in names(samples)) {
    s <- samples[[name]]
    rule <- rules[rules$name == name, ]
    expect_true(grepl(rule$file_regex, s[[1L]], perl = TRUE), info = name)
    expect_equal(vendored_version(s[[2L]], rule$header_regex), s[[3L]], info = name)
  }
  # A file of another name is not matched, even with a matching header.
  expect_false(any(grepl(rules$file_regex[rules$name == "jquery"], c("jquery-ui.min.js", "app.js"), perl = TRUE)))
})

test_that("YAML versions stay text, and a broken YAML file is noted", {
  skip_if_not_installed("yaml")
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "inst", "htmlwidgets"), recursive = TRUE)
  write_text("Package: ypkg\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  write_text(
    paste0(
      "dependencies:\n  - name: lib-a\n    version: 1.10\n  - name: lib-b\n",
      "  - name: lib-zero\n    version: 0.0.0\n  - name: d3\n    version: '0'\n",
      "  - name: '@scope/lib-c'\n    version: 2\n    script: !expr system('x')\n"
    ),
    file.path(dir, "inst", "htmlwidgets", "a.yaml")
  )
  write_text("", file.path(dir, "inst", "htmlwidgets", "empty.yaml"))
  write_text("dependencies: [unclosed\n  - : :", file.path(dir, "inst", "htmlwidgets", "b.yaml"))
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$name == "lib-a"], "1.10")
  expect_true(is.na(comps$version[comps$name == "lib-b"]))
  expect_true(is.na(comps$purl[comps$name == "lib-b"]))
  expect_equal(comps$ref[comps$name == "lib-a"], "local/ypkg#js/lib-a@1.10")
  expect_equal(comps$ref[comps$name == "lib-zero"], "local/ypkg#js/lib-zero")
  expect_true(is.na(comps$version[comps$name == "lib-zero"]))
  expect_true(is.na(comps$purl[comps$name == "lib-zero"]))
  expect_true(is.na(comps$version_is[comps$name == "lib-zero"]))
  expect_equal(comps$evidence[comps$name == "lib-zero"], "declared")
  expect_true(is.na(comps$version[comps$name == "d3"]))
  expect_true(is.na(comps$purl[comps$name == "d3"]))
  expect_equal(comps$ref[comps$name == "lib-b"], "local/ypkg#js/lib-b")
  # A declared name that no rule knows is an R html dependency, not
  # necessarily an npm package, so it gets no purl.
  expect_true(is.na(comps$purl[comps$name == "@scope/lib-c"]))
  expect_true(is.na(comps$purl[comps$name == "lib-a"]))
  issues <- sbom_issues(x)
  expect_match(issues$message[issues$code == "htmlwidgets-unreadable"], "inst/htmlwidgets/b.yaml", fixed = TRUE)
  expect_equal(sum(issues$code == "htmlwidgets-unreadable"), 1L)
  expect_equal(issues$severity[issues$code == "htmlwidgets-unreadable"], "info")
  vm <- issues[issues$code == "javascript-version-missing", ]
  expect_false("version-missing" %in% issues$code[issues$ref == "local/ypkg"])
  expect_equal(vm$ref[grepl("lib-b ", vm$message)], "local/ypkg#js/lib-b")
  expect_equal(vm$severity[grepl("lib-b ", vm$message)], "info")
  expect_equal(
    vm$message[grepl("lib-b ", vm$message)],
    "ypkg 1.0 declares lib-b without a usable version."
  )
  expect_equal(sum(grepl("lib-zero ", vm$message)), 1L)
  expect_equal(
    vm$message[grepl("lib-zero ", vm$message)],
    "ypkg 1.0 declares lib-zero without a usable version (it gives 0.0.0)."
  )
  expect_equal(vm$ref[grepl("lib-zero ", vm$message)], "local/ypkg#js/lib-zero")
})

test_that("a declared and a header version that disagree are reported", {
  skip_if_not_installed("yaml")
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "inst", "htmlwidgets"), recursive = TRUE)
  dir.create(file.path(dir, "inst", "www"))
  write_text("Package: dpkg2\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  write_text("dependencies:\n  - name: jquery\n    version: 3.6.0\n", file.path(dir, "inst", "htmlwidgets", "a.yaml"))
  write_text("/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n", file.path(dir, "inst", "www", "jquery.min.js"))
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  js <- comps[comps$name == "jquery", ]
  expect_equal(nrow(js), 2L)
  expect_equal(js$evidence[js$version == "3.6.0"], "declared")
  expect_equal(js$ref[js$version == "3.6.0"], "local/dpkg2#js/jquery@3.6.0")
  expect_equal(js$evidence[js$version == "3.7.1"], "inferred")
  expect_equal(js$ref[js$version == "3.7.1"], "local/dpkg2#js/jquery@3.7.1")
  expect_equal(js$description[js$version == "3.6.0"], "Declared in inst/htmlwidgets/a.yaml.")
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "javascript-version-differs"], paste0(
    "dpkg2 1.0 ships two versions of jquery: 3.6.0, declared in inst/htmlwidgets/a.yaml, ",
    "and 3.7.1, found in inst/www/jquery.min.js; both are recorded."
  ))
  expect_valid_in_every_format(x)
  # A declared library without a version takes the first header's, which is
  # then not said to be declared.
  write_text("dependencies:\n  - name: jquery\n", file.path(dir, "inst", "htmlwidgets", "a.yaml"))
  write_text("/*! jQuery v3.5.1 | x */\n", file.path(dir, "inst", "www", "jquery-3.5.1.min.js"))
  iss <- sbom_issues(sbom_package(dir, lib = local_fake_lib(list())))
  expect_equal(iss$message[iss$code == "javascript-version-differs"], paste0(
    "dpkg2 1.0 ships two versions of jquery: 3.5.1, found in inst/www/jquery-3.5.1.min.js, ",
    "and 3.7.1, found in inst/www/jquery.min.js; both are recorded."
  ))
})

test_that("several versions of one library in a package are separate components", {
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "inst", "lib", "v1"), recursive = TRUE)
  dir.create(file.path(dir, "inst", "lib", "v2"))
  write_text("Package: mpkg\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  write_text("/*! jQuery v1.12.4 | x */\n", file.path(dir, "inst", "lib", "v1", "jquery.min.js"))
  write_text("/*! jQuery v3.6.0 | x */\n", file.path(dir, "inst", "lib", "v2", "jquery.min.js"))
  write_text("/*! jQuery v3.6.0 | x */\n", file.path(dir, "inst", "lib", "v2", "jquery.js"))
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  js <- comps[comps$ecosystem == "npm", ]
  expect_equal(nrow(js), 2L)
  expect_setequal(js$version, c("1.12.4", "3.6.0"))
  expect_equal(anyDuplicated(js$ref), 0L)
  expect_setequal(js$ref, c("local/mpkg#js/jquery@1.12.4", "local/mpkg#js/jquery@3.6.0"))
  expect_false("javascript-version-differs" %in% sbom_issues(x)$code)
  expect_valid_in_every_format(x)
})

test_that("only the first 2 KB of a file is searched for a header", {
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "inst", "www"), recursive = TRUE)
  write_text("Package: hpkg\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  write_text(
    paste0(strrep("x", 3000L), "\n/*! jQuery v3.7.1 */\n"),
    file.path(dir, "inst", "www", "jquery.js")
  )
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  expect_false(any(sbom_components(x)$ecosystem == "npm"))
})

test_that("an installed package's www/ folder is searched", {
  lib <- local_fake_lib(list(wpkg = c(Version = "1.0", Repository = "CRAN", License = "MIT")))
  dir.create(file.path(lib, "wpkg", "www"))
  write_text("/*! jQuery v3.5.1 | x */\n", file.path(lib, "wpkg", "www", "jquery.min.js"))
  x <- sbom_installed("wpkg", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$ref[comps$name == "jquery"], "pkg:cran/wpkg@1.0#js/jquery@3.5.1")
  expect_equal(comps$description[comps$name == "jquery"], "Found as www/jquery.min.js in wpkg; the version comes from its header comment.")
})

js_parent <- function() {
  component_row(
    ref = "local/p", name = "p", version = "1.0", type = "library",
    ecosystem = "local", scope = "required"
  )
}

test_that("the header scan stops at a bounded depth and does not follow symlinks", {
  dir <- withr::local_tempdir()
  deep <- file.path(dir, "inst", "www", "a", "b", "c", "d", "e", "f")
  dir.create(deep, recursive = TRUE)
  write_text("/*! jQuery v3.7.1 | x */\n", file.path(deep, "jquery.min.js"))
  too_deep <- file.path(deep, "g")
  dir.create(too_deep)
  write_text("/*! jQuery v1.12.4 | x */\n", file.path(too_deep, "jquery.min.js"))
  outside <- withr::local_tempdir()
  write_text("/*! Leaflet 1.9.4, a JS library */\n", file.path(outside, "leaflet.js"))
  skip_on_os("windows")
  file.symlink(outside, file.path(dir, "inst", "www", "linked"))
  res <- javascript_components(dir, js_parent())
  expect_equal(res$components$version, "3.7.1")
  expect_false("leaflet" %in% res$components$name)
})

test_that("candidates are chosen by file name before the cap, and a hit cap is noted", {
  dir <- withr::local_tempdir()
  www <- file.path(dir, "inst", "www")
  dir.create(www, recursive = TRUE)
  for (i in 1:5) write_text("var x = 1;\n", file.path(www, sprintf("a%d.js", i)))
  write_text("/*! jQuery v3.7.1 | x */\n", file.path(www, "jquery.min.js"))
  # Five other .js files come first, but only candidates count towards the cap.
  res <- javascript_components(dir, js_parent(), max_files = 1L)
  expect_equal(res$components$name, "jquery")
  expect_false("javascript-scan-truncated" %in% res$issues$code)
  write_text("/*! jQuery v3.6.0 | x */\n", file.path(www, "jquery-3.6.0.js"))
  res <- javascript_components(dir, js_parent(), max_files = 1L)
  trunc <- res$issues[res$issues$code == "javascript-scan-truncated", ]
  expect_equal(nrow(trunc), 1L)
  expect_equal(trunc$ref, "local/p")
  expect_equal(trunc$field, "embedded")
  expect_equal(trunc$severity, "info")
  expect_equal(
    trunc$message,
    "sbom looked at the first 1 candidate JavaScript and CSS files in p 1.0 and skipped the rest."
  )
})

test_that("a root licence override leaves the JavaScript licence note in place", {
  x <- sbom_package(
    test_path("fixtures/pkgs/widgetpkg"), lib = local_fake_lib(list()),
    overrides = data.frame(
      component = "widgetpkg", field = "license_spdx", value = "MIT",
      asserted_by = "Me", reason = "Test"
    )
  )
  issues <- sbom_issues(x)
  expect_true("javascript-license-not-read" %in% issues$code)
  expect_false(any(issues$code == "license-missing" & issues$ref == "local/widgetpkg"))
})

test_that("a declared library without a usable version takes the header's version", {
  skip_if_not_installed("yaml")
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "inst", "htmlwidgets"), recursive = TRUE)
  dir.create(file.path(dir, "inst", "www"))
  write_text("Package: zpkg\nVersion: 1.0\n", file.path(dir, "DESCRIPTION"))
  write_text("dependencies:\n  - name: jquery\n    version: 0.0.0\n", file.path(dir, "inst", "htmlwidgets", "a.yaml"))
  write_text("/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n", file.path(dir, "inst", "www", "jquery.min.js"))
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  comps <- sbom_components(x)
  j <- comps[comps$name == "jquery", ]
  expect_equal(nrow(j), 1L)
  expect_equal(j$version, "3.7.1")
  expect_equal(j$purl, "pkg:npm/jquery@3.7.1")
  expect_equal(j$ref, "local/zpkg#js/jquery@3.7.1")
  expect_equal(j$evidence, "declared")
  expect_equal(
    j$description,
    "Declared in inst/htmlwidgets/a.yaml. The version comes from the header of inst/www/jquery.min.js."
  )
  expect_false("javascript-version-missing" %in% sbom_issues(x)$code)
  expect_false("javascript-version-differs" %in% sbom_issues(x)$code)
})
