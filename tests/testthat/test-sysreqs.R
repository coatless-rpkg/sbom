test_that("SystemRequirements text becomes system components through pak's rules", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    lapply(spec, function(s) {
      if (grepl("libcurl", s)) {
        data.frame(sysreq = "libcurl", packages = I(list("libcurl4-openssl-dev")))
      } else {
        data.frame(sysreq = character(), packages = I(list()))
      }
    })
  })
  lib <- local_fake_lib(list(curlish = c(
    Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE",
    Maintainer = "A B <a@example.org>",
    SystemRequirements = "libcurl (>= 7.73): libcurl-devel (rpm) or libcurl4-openssl-dev (deb); C++17"
  )))
  x <- sbom_installed("curlish", lib = lib)
  comps <- sbom_components(x)
  s <- comps[comps$ref == "system/libcurl", ]
  expect_equal(s$version, "7.73")
  expect_equal(s$version_is, "minimum")
  expect_equal(s$evidence, "declared")
  expect_equal(s$ecosystem, "system")
  expect_match(s$description, "Needed by curlish.")
  expect_true(any(sbom_dependencies(x)$field == "system_requirement"))
  expect_match(comps$system_requirements[comps$name == "curlish"], "C++17", fixed = TRUE)
  expect_false(any(grepl("C\\+\\+", comps$name)))
  expect_false("sysreqs-unmapped" %in% sbom_issues(x)$code)
})

test_that("a sysreq shared by two packages is one component with the highest minimum", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    lapply(spec, function(s) {
      data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev")))
    })
  })
  lib <- local_fake_lib(list(
    a = c(Version = "1.0", SystemRequirements = "libxml2 (>= 2.6.0)"),
    b = c(Version = "1.0", SystemRequirements = "libxml2 (>= 2.9.1)")
  ))
  x <- sbom_installed(c("a", "b"), lib = lib)
  comps <- sbom_components(x)
  s <- comps[comps$ref == "system/libxml2", ]
  expect_equal(nrow(s), 1L)
  expect_equal(s$version, "2.9.1")
  expect_match(s$description, "Needed by a, b.")
  rel <- sbom_dependencies(x)
  expect_equal(sum(rel$field == "system_requirement"), 2L)
})

test_that("a minimum may be followed by a qualifier", {
  expect_equal(sysreq_minimum("libxml2 (optional), glpk (>= 4.57, optional)", "glpk"), "4.57")
  expect_true(is.na(sysreq_minimum("libxml2 (optional)", "libxml2")))
  expect_true(is.na(sysreq_minimum("OpenSSL >= 1.0.2", "openssl")))
})

test_that("a platform adds the operating system packages to the description", {
  withr::local_options(sbom.sysreqs_platform = "ubuntu-22.04")
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    expect_equal(platform, "ubuntu-22.04")
    lapply(spec, function(s) data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev"))))
  })
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libxml2")))
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_match(
    comps$description[comps$ref == "system/libxml2"],
    "on ubuntu-22.04 it is provided by libxml2-dev", fixed = TRUE
  )
})

test_that("without pak the text is kept and one issue says so", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) NULL)
  lib <- local_fake_lib(list(
    curlish = c(Version = "1.0", SystemRequirements = "libcurl"),
    other = c(Version = "1.0", SystemRequirements = "GNU make")
  ))
  x <- sbom_installed(c("curlish", "other"), lib = lib)
  issues <- sbom_issues(x)
  expect_equal(sum(issues$code == "sysreqs-unmapped"), 1L)
  expect_match(issues$message[issues$code == "sysreqs-unmapped"], "of 2 packages")
  expect_match(issues$message[issues$code == "sysreqs-unmapped"], "system-requirements property in CycloneDX", fixed = TRUE)
  comps <- sbom_components(x)
  expect_false(any(comps$ecosystem == "system"))
  expect_equal(comps$system_requirements[comps$name == "curlish"], "libcurl")
})

test_that("system = FALSE skips the mapping and the column", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) stop("not called"))
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libxml2")))
  x <- sbom_installed("a", lib = lib, system = FALSE)
  expect_true(all(is.na(sbom_components(x)$system_requirements)))
  expect_false("sysreqs-unmapped" %in% sbom_issues(x)$code)
})

test_that("every writer accepts system components and relationships", {
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    lapply(spec, function(s) data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev"))))
  })
  lib <- local_fake_lib(list(a = c(Version = "1.0", License = "MIT", SystemRequirements = "libxml2 (>= 2.6)")))
  x <- sbom_installed("a", lib = lib)
  for (fmt in sbom_formats()$format) {
    tf <- withr::local_tempfile()
    write_sbom(x, tf, format = fmt)
    if (fmt != "csv") {
      res <- schema_validate(tf, fmt)
      expect_false(res$status == "fail", info = fmt)
    }
  }
  spdx <- jsonlite::fromJSON(spdx_json(x, "2.3"), simplifyVector = FALSE)
  ids <- vapply(spdx$packages, `[[`, "", "SPDXID")
  expect_true("SPDXRef-system-libxml2" %in% ids)
  comments <- unlist(lapply(spdx$relationships, `[[`, "comment"))
  expect_true("SystemRequirements: libxml2 (>= 2.6)" %in% comments)
})

test_that("pak's rules map real text, when pak and its rules are available", {
  skip_if_not_installed("pak")
  skip_on_cran()
  skip_if_offline()
  withr::local_options(pkg.sysreqs_db_update = FALSE)
  local_mocked_bindings(sysreqs_match = sysreqs_match_real, pak_function = pak_function_real)
  got <- sysreqs_match(c("libxml2", "GNU make", "C++17"), NA_character_)
  skip_if(is.null(got))
  expect_true("libxml2" %in% got[[1]]$sysreq)
  expect_equal(nrow(got[[3]]), 0L)
  expect_equal(lengths(got[[1]]$packages), rep(0L, nrow(got[[1]])))
})

test_that("the platform comes from the lowercase fields of sys_os_release()", {
  local_mocked_bindings(
    sys_os_release = function() list(id = "ubuntu", version_id = "22.04"),
    sysreqs_match = function(spec, platform) {
      expect_equal(platform, "ubuntu-22.04")
      lapply(spec, function(s) data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev"))))
    }
  )
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libxml2")))
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_match(comps$description[comps$ref == "system/libxml2"], "ubuntu-22.04")
})

test_that("an optional requirement is optional unless another package requires it", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    lapply(spec, function(s) data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev"))))
  })
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libxml2 (optional)")))
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_equal(comps$scope[comps$ref == "system/libxml2"], "optional")

  lib <- local_fake_lib(list(
    a = c(Version = "1.0", SystemRequirements = "libxml2 (optional)"),
    b = c(Version = "1.0", SystemRequirements = "libxml2 (>= 2.9)")
  ))
  comps <- sbom_components(sbom_installed(c("a", "b"), lib = lib))
  expect_equal(comps$scope[comps$ref == "system/libxml2"], "required")
})

mock_names <- function(table) {
  # `table` maps a word in the text to the sysreq it stands for.
  function(spec, platform) {
    lapply(spec, function(s) {
      hit <- names(table)[vapply(names(table), grepl, NA, x = s, ignore.case = TRUE)]
      data.frame(sysreq = unname(table[hit]), packages = I(rep(list("pkg-dev"), length(hit))))
    })
  }
}

test_that("each requirement takes its scope and spec from its own fragment", {
  local_mocked_bindings(sysreqs_match = mock_names(c(libcurl = "libcurl", libxml2 = "libxml2")))
  lib <- local_fake_lib(list(a = c(Version = "1.0",
    SystemRequirements = "libcurl (>= 7.73), libxml2 (optional)")))
  x <- sbom_installed("a", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$scope[comps$ref == "system/libcurl"], "required")
  expect_equal(comps$scope[comps$ref == "system/libxml2"], "optional")
  expect_equal(comps$version[comps$ref == "system/libcurl"], "7.73")
  rel <- sbom_dependencies(x)
  rel <- rel[rel$field == "system_requirement", ]
  expect_equal(rel$spec[rel$to == "system/libcurl"], "libcurl (>= 7.73)")
  expect_equal(rel$spec[rel$to == "system/libxml2"], "libxml2 (optional)")
})

test_that("a name inside another name is not that requirement's text", {
  expect_true(is.na(sysreq_minimum("libgit2 (>= 1.0)", "git")))
  expect_true(is.na(sysreq_minimum("libcurl4-openssl-dev (>= 7.73)", "openssl")))
  expect_equal(sysreq_minimum("libgit2 (>= 1.0)", "libgit2"), "1.0")
  expect_equal(sysreq_fragment("libgit2 (>= 1.0), git (optional)", "git"), "git (optional)")
  expect_true(is.na(sysreq_fragment("libgit2 (>= 1.0)", "git")))
})

test_that("programs become application components", {
  local_mocked_bindings(sysreqs_match = mock_names(c("GNU make" = "gnumake", pandoc = "pandoc", libxml2 = "libxml2")))
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "GNU make, Pandoc, libxml2; C++17")))
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_equal(comps$type[comps$ref == "system/gnumake"], "application")
  expect_equal(comps$type[comps$ref == "system/pandoc"], "application")
  expect_equal(comps$type[comps$ref == "system/libxml2"], "library")
  expect_match(comps$description[comps$ref == "system/pandoc"], "Needed by a; a program, not a library.", fixed = TRUE)
  expect_false(any(grepl("C\\+\\+", comps$name)))
})

test_that("a name matches whole words only", {
  text <- "Requires a GitHub token; git (>= 2.0)"
  expect_equal(sysreq_fragment(text, "git"), "git (>= 2.0)")
  expect_equal(sysreq_minimum(sysreq_fragment(text, "git"), "git"), "2.0")
  expect_true(is.na(sysreq_fragment("Requires a GitHub token", "git")))
  expect_true(is.na(sysreq_fragment("gitlab access", "git")))
  expect_equal(sysreq_fragment("libcurl (>= 7.73)", "libcurl"), "libcurl (>= 7.73)")
  expect_equal(sysreq_fragment("openssl, libcurl", "openssl"), "openssl")
})

test_that("pak is called with its rules update off, and the option is restored", {
  seen <- new.env()
  local_mocked_bindings(
    sysreqs_match = sysreqs_match_real,
    pak_function = function(name) {
      function(...) {
        seen$name <- name
        seen$during <- getOption("pkg.sysreqs_db_update")
        list(data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev"))))
      }
    }
  )
  withr::local_options(pkg.sysreqs_db_update = NULL)
  got <- sysreqs_match("libxml2", NA_character_)
  expect_equal(seen$name, "sysreqs_db_match")
  expect_identical(seen$during, FALSE)
  expect_null(getOption("pkg.sysreqs_db_update"))
  expect_equal(got[[1]]$sysreq, "libxml2")

  # A value the user set comes back after the call.
  withr::local_options(pkg.sysreqs_db_update = TRUE)
  seen$during <- NULL
  sysreqs_match("libxml2", NA_character_)
  expect_identical(seen$during, FALSE)
  expect_identical(getOption("pkg.sysreqs_db_update"), TRUE)
})

test_that("pak runs with TMPDIR set to the session's temporary folder, and TMPDIR is put back", {
  # pak's subprocess is killed when R exits, so it never removes its own
  # temporary folder. Inside the session's, R removes it.
  seen <- new.env()
  local_mocked_bindings(
    pak_function = function(name) {
      function(...) {
        seen$tmpdir <- Sys.getenv("TMPDIR", unset = NA)
        TRUE
      }
    }
  )
  before <- withr::local_tempdir()
  withr::local_envvar(TMPDIR = before)
  expect_true(sysreqs_platform_supported("ubuntu-22.04"))
  expect_equal(normalizePath(seen$tmpdir), normalizePath(tempdir()))
  expect_equal(Sys.getenv("TMPDIR"), before)

  withr::local_envvar(TMPDIR = NA)
  seen$tmpdir <- NULL
  expect_true(sysreqs_platform_supported("ubuntu-22.04"))
  expect_equal(normalizePath(seen$tmpdir), normalizePath(tempdir()))
  expect_true(is.na(Sys.getenv("TMPDIR", unset = NA)))
})

test_that("the SystemRequirements text is written in every format, without pak", {
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  lib <- local_fake_lib(list(curlish = c(
    Version = "1.0", License = "MIT", SystemRequirements = "libcurl; C++17"
  )))
  x <- sbom_installed("curlish", lib = lib)
  expect_false(any(sbom_components(x)$ecosystem == "system"))
  for (fmt in sbom_formats()$format) {
    tf <- withr::local_tempfile()
    write_sbom(x, tf, format = fmt)
    text <- rawToChar(readBin(tf, "raw", 1e7))
    if (fmt != "swid") {
      expect_match(text, "C++17", fixed = TRUE, info = fmt)
    }
    if (fmt != "csv") {
      expect_false(schema_validate(tf, fmt)$status == "fail", info = fmt)
    }
  }
  pkg <- function(doc) Filter(function(p) identical(p$name, "curlish"), doc$packages)[[1]]
  expect_true(endsWith(pkg(spdx_document(x, "2.3"))$comment, "SystemRequirements: libcurl; C++17"))
  s3 <- Filter(function(e) identical(e$name, "curlish"), spdx3_document(x)[["@graph"]])[[1]]
  expect_true(endsWith(s3$comment, "SystemRequirements: libcurl; C++17"))
  cdx <- Filter(function(c) identical(c$name, "curlish"), cdx_document(x, "1.6")$components)[[1]]
  props <- vapply(cdx$properties, function(p) paste0(p$name, "=", p$value), "")
  expect_true("sbom:system-requirements=libcurl; C++17" %in% props)
  csv <- utils::read.csv(text = csv_inventory(x), colClasses = "character")
  expect_equal(csv$system_requirements[csv$name == "curlish"], "libcurl; C++17")
})

test_that("a SWID tag gives the root's SystemRequirements text", {
  dir <- withr::local_tempdir()
  write_text("Package: rootpkg\nVersion: 1.0\nLicense: MIT\nSystemRequirements: GNU make, C++17\n",
             file.path(dir, "DESCRIPTION"))
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  tag <- xml2::read_xml(swid_tag(x))
  meta <- xml2::xml_find_first(tag, "//*[local-name()='Meta']")
  expect_equal(xml2::xml_attr(meta, "sbom:systemRequirements", ns = c(sbom = swid_sbom_ns)), "GNU make, C++17")
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_sbom(x, tf, format = "swid")
  expect_equal(schema_validate(tf, "swid")$status, "partial")
})

test_that("the programs are pak's tool rules and the older program names", {
  tools <- readLines(test_path("fixtures", "pak", "tool-rules.txt"))
  older <- c("make", "autoconf", "cargo", "rustc", "chromium", "texlive", "nodejs", "quarto", "ghostscript", "qpdf")
  expect_setequal(sysreq_programs, c(tools, older))
  expect_true(all(sysreq_build_tools %in% sysreq_programs))
  expect_true(is_build_tool("rust"))
  expect_false(is_build_tool("pandoc"))
  # The rules pak ships still have those names. This reads files; it does not run pak.
  rules <- system.file("library", "pkgdepends", "sysreqs", "rules", package = "pak")
  skip_if(!nzchar(rules), "pak's bundled rules are not available.")
  expect_true(all(tools %in% sub("\\.json$", "", list.files(rules))))
})

test_that("a build tool is an application, never statically linked, and build-scoped in SPDX 3", {
  local_mocked_bindings(
    sysreqs_match = mock_names(c("GNU make" = "gnumake", rust = "rust", pandoc = "pandoc")),
    sys_linked_libraries = function(so) "/usr/lib/libfoo.so.1"
  )
  lib <- local_fake_lib(list(a = c(Version = "1.0", License = "MIT",
                                   SystemRequirements = "GNU make, Cargo (Rust's package manager), rustc, pandoc")))
  dir.create(file.path(lib, "a", "libs"))
  write_text("", file.path(lib, "a", "libs", "a.so"))
  x <- sbom_installed("a", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$type[comps$ref == "system/rust"], "application")
  expect_false("may-statically-link" %in% sbom_issues(x)$code)
  s3 <- spdx3_document(x)[["@graph"]]
  id_of <- function(name) {
    Filter(function(e) identical(e$type, "software_Package") && identical(e$name, name), s3)[[1]]$spdxId
  }
  scope_to <- function(name) {
    hit <- Filter(function(e) identical(e$type, "LifecycleScopedRelationship") && identical(e$to[[1]], id_of(name)), s3)
    hit[[1]]$scope
  }
  expect_equal(scope_to("gnumake"), "build")
  expect_equal(scope_to("rust"), "build")
  expect_equal(scope_to("pandoc"), "runtime")
})

test_that("on a platform pak has no rules for, names come from Ubuntu's rules without OS packages", {
  local_mocked_bindings(
    sys_os_release = function() list(id = "ol", version_id = "9"),
    sysreqs_platform_supported = function(platform) !identical(platform, "ol-9"),
    sysreqs_match = function(spec, platform) {
      lapply(spec, function(s) {
        if (identical(platform, "ol-9")) {
          data.frame(sysreq = character(), packages = I(list()))
        } else {
          data.frame(sysreq = "libxml2", packages = I(list("libxml2-dev")))
        }
      })
    }
  )
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libxml2")))
  x <- sbom_installed("a", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$description[comps$ref == "system/libxml2"], "Needed by a.")
  iss <- sbom_issues(x)
  expect_equal(iss$message[iss$code == "sysreqs-platform-unknown"], paste0(
    "sbom matched system requirements with Ubuntu 22.04's rules, because pak has no rules ",
    "for ol-9; the OS package names are omitted."
  ))
  expect_equal(iss$severity[iss$code == "sysreqs-platform-unknown"], "info")
})

test_that("a requirement's fragment is found by pak's patterns when the text names it otherwise", {
  local_mocked_bindings(
    sysreqs_match = mock_names(c(icu4c = "libicu")),
    sysreqs_rule_patterns = function() list(libicu = "\\bicu4c\\b", libxml2 = "\\blibxml2\\b")
  )
  lib <- local_fake_lib(list(stringi = c(Version = "1.8", SystemRequirements = "ICU4C (>= 61, optional)")))
  x <- sbom_installed("stringi", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$scope[comps$ref == "system/libicu"], "optional")
  expect_equal(comps$version[comps$ref == "system/libicu"], "61")
  rel <- sbom_dependencies(x)
  expect_equal(rel$spec[rel$to == "system/libicu"], "ICU4C (>= 61, optional)")
  expect_equal(sysreq_fragment("C++17, ICU4C (>= 61, optional)", "libicu", "\\bicu4c\\b"), "ICU4C (>= 61, optional)")
  expect_equal(sysreq_minimum("ICU4C (>= 61, optional)", "libicu", "ICU4C"), "61")
})
