test_that("sbom_package() builds the fixture tree", {
  x <- fixture_sbom()
  comps <- sbom_components(x)
  expect_setequal(comps$ref, c("local/srcpkg", "pkg:cran/cranpkg@1.2.0", "local/localpkg",
                               "pkg:cran/suggestpkg@2.0.0", "R", "R/utils", "R/methods",
                               "local/srcpkg#embedded/cranpkg"))
  expect_equal(comps$scope[comps$ref == "pkg:cran/suggestpkg@2.0.0"], "optional")
  expect_equal(comps$version_is[comps$ref == "R"], "minimum")
  rel <- sbom_dependencies(x)
  expect_equal(rel$spec[rel$to == "pkg:cran/cranpkg@1.2.0" & rel$field == "Imports"], "cranpkg (>= 1.0.0)")
  expect_true(any(rel$field == "LinkingTo"))
  expect_true(all(c("R/utils", "R/methods") %in% rel$to[rel$field == "contains"]))
  expect_false(any(grepl("deeppkg", c(comps$ref, sbom_issues(x)$message))))
  expect_true(
    "Packages listed only under Suggests are included, but their own dependencies were not read." %in%
      x$metadata$notes
  )
})

test_that("dropping Suggests drops suggested packages", {
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), dependencies = c("Depends", "Imports", "LinkingTo"),
                    lib = fixture_lib())
  expect_false("pkg:cran/suggestpkg@2.0.0" %in% sbom_components(x)$ref)
  expect_false(any(grepl("Suggests", x$metadata$notes)))
})

test_that("missing and unsatisfied dependencies become issues", {
  lib <- local_fake_lib(list(rlang = c(Version = "1.2.0", Repository = "CRAN", License = "MIT + file LICENSE",
                                       Maintainer = "L H <l@example.org>")))
  tmp <- withr::local_tempdir()
  writeLines(c("Package: top", "Version: 1.0", "License: MIT + file LICENSE", "Maintainer: T <t@example.org>",
               "Imports: rlang (>= 1.3.0), gone"), file.path(tmp, "DESCRIPTION"))
  x <- sbom_package(tmp, lib = lib)
  iss <- sbom_issues(x)
  expect_true("unknown/gone" %in% sbom_components(x)$ref)
  expect_equal(iss$message[iss$code == "constraint-unsatisfied"],
               "rlang 1.2.0 is installed, but top requires rlang (>= 1.3.0).")
  expect_true("dependency-not-installed" %in% iss$code)
})

test_that("an installed package with no License or Maintainer does not fail", {
  lib <- local_fake_lib(list(bare = c(Version = "1.0", Repository = "CRAN")))
  x <- sbom_installed("bare", lib = lib)
  expect_true(all(c("license-missing", "maintainer-missing") %in% sbom_issues(x)$code))
})

test_that("sbom_installed() makes a library root that contains its packages", {
  x <- sbom_installed(lib = fixture_lib())
  rel <- sbom_dependencies(x)
  expect_setequal(rel$to[rel$from == "r-library" & rel$field == "contains"],
                  c("pkg:cran/cranpkg@1.2.0", "local/localpkg", "pkg:cran/suggestpkg@2.0.0", "pkg:cran/oldpkg@1.0.0"))
})

test_that("r_version is exact when given, and a tarball root is hashed", {
  tmp <- withr::local_tempdir()
  tarball <- file.path(tmp, "srcpkg_0.1.0.tar.gz")
  withr::with_dir(test_path("fixtures/pkgs"), utils::tar(tarball, "srcpkg", compression = "gzip"))
  x <- sbom_package(tarball, lib = fixture_lib(), r_version = "4.6.2")
  comps <- sbom_components(x)
  expect_equal(comps$version[comps$ref == "R"], "4.6.2")
  expect_equal(comps$version_is[comps$ref == "R"], "exact")
  expect_equal(comps$hashes[comps$is_root][[1]]$content, cli::hash_file_sha256(tarball))
})

test_that("the same tree built from two libraries is identical, with no paths in it", {
  a <- fixture_sbom()
  b <- fixture_sbom()
  expect_equal(sbom_components(a), sbom_components(b))
  expect_equal(sbom_dependencies(a), sbom_dependencies(b))
  expect_equal(sbom_issues(a), sbom_issues(b))
  expect_equal(a$metadata$notes, b$metadata$notes)
  expect_equal(a$metadata$inputs$kind, c("DESCRIPTION", "library"))
  expect_identical(sbom_components(a)$ref, sort(sbom_components(a)$ref, method = "radix"))
})

test_that("metadata records the author, notes, and the missing-author issue", {
  withr::local_envvar(SOURCE_DATE_EPOCH = NA)
  x <- fixture_sbom()
  expect_equal(x$metadata$author, "Test Author")
  expect_equal(x$metadata$notes[[1]], "R is listed at the lowest version stated, R (>= 4.1.0).")
  expect_length(x$metadata$notes, 5)
  expect_equal(x$metadata$notes[[5]], "No advisory data was on hand for this file, so it lists no advisories.")
  expect_false("no-sbom-author" %in% sbom_issues(x)$code)
  y <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib())
  iss <- sbom_issues(y)
  expect_true(is.na(y$metadata$author) && is.na(y$metadata$organization))
  expect_equal(iss$severity[iss$code == "no-sbom-author"], "info")
  expect_equal(iss$ref[iss$code == "no-sbom-author"], y$metadata$root)
})

test_that("R is exact for the library search path and unversioned when nothing is stated", {
  tmp <- withr::local_tempdir()
  writeLines(c("Package: plain", "Version: 1.0"), file.path(tmp, "DESCRIPTION"))
  x <- sbom_package(tmp, lib = fixture_lib())
  expect_true(is.na(sbom_components(x)$version[sbom_components(x)$ref == "R"]))
  expect_true("R is listed without a version, since no minimum is stated." %in% x$metadata$notes)
  y <- sbom_package(tmp)
  comps <- sbom_components(y)
  expect_equal(comps$version[comps$ref == "R"], as.character(getRversion()))
  expect_false(any(grepl("^R is listed", y$metadata$notes)))
})

test_that("a missing suggested package is an optional unknown component", {
  tmp <- withr::local_tempdir()
  writeLines(c("Package: top", "Version: 1.0", "Suggests: nothere"), file.path(tmp, "DESCRIPTION"))
  x <- sbom_package(tmp, lib = fixture_lib())
  comps <- sbom_components(x)
  expect_equal(comps$scope[comps$ref == "unknown/nothere"], "optional")
})

test_that("sbom_installed() handles explicit, missing-dependency and base packages", {
  lib <- fixture_lib()
  x <- sbom_installed("suggestpkg", lib = lib, name = "mylib")
  comps <- sbom_components(x)
  expect_equal(comps$name[comps$is_root], "mylib")
  expect_true("unknown/deeppkg" %in% comps$ref)
  expect_false("pkg:cran/cranpkg@1.2.0" %in% comps$ref)
  iss <- sbom_issues(x)
  expect_true("deeppkg is named as a dependency of suggestpkg but is not installed in the library sbom read, so its version and source are unknown." %in% iss$message)
  base_lib <- local_fake_lib(list(utils = c(Version = "4.6.2", Priority = "base"),
                                  other = c(Version = "1.0", Repository = "CRAN")))
  y <- sbom_installed(lib = base_lib)
  rel <- sbom_dependencies(y)
  expect_true("R/utils" %in% rel$to[rel$from == "R" & rel$field == "contains"])
  expect_false("R/utils" %in% rel$to[rel$from == "r-library"])
})

test_that("explicit pkgs list only the base packages they reach", {
  lib <- local_fake_lib(list(
    utils = c(Version = "4.6.2", Priority = "base"),
    stats = c(Version = "4.6.2", Priority = "base"),
    cranpkg = c(Version = "1.0", Repository = "CRAN", Imports = "utils")
  ))
  x <- sbom_installed("cranpkg", lib = lib)
  refs <- sbom_components(x)$ref
  expect_true("R/utils" %in% refs)
  expect_false("R/stats" %in% refs)
  expect_false("R/stats" %in% sbom_dependencies(x)$to)
  # Base packages the user lists by name are kept.
  expect_true("R/stats" %in% sbom_components(sbom_installed(c("cranpkg", "stats"), lib = lib))$ref)
  # pkgs = NULL lists every base package found in lib.
  all <- sbom_components(sbom_installed(lib = lib))$ref
  expect_true(all(c("R/utils", "R/stats") %in% all))
})

test_that("an undeclared latin1 DESCRIPTION builds, with a UTF-8 maintainer", {
  pkg <- local_latin1_pkg(declare = FALSE)
  x <- sbom_package(pkg, lib = local_fake_lib(list()))
  y <- sbom_installed(lib = dirname(pkg))
  for (s in list(x, y)) {
    comps <- sbom_components(s)
    maintainer <- comps$maintainer[comps$name == "latin1pkg"]
    expect_equal(maintainer, "Gábor Csárdi")
    expect_true(validUTF8(maintainer))
    expect_true(validUTF8(cdx_json(s)))
  }
})

test_that("explicit pkgs that are not installed are an error", {
  lib <- fixture_lib()
  err <- expect_error(sbom_installed(c("suggestpkg", "zzz", "yyy"), lib = lib))
  expect_match(conditionMessage(err), "zzz")
  expect_match(conditionMessage(err), "yyy")
  expect_match(conditionMessage(err), "not installed in")
  expect_false(grepl("suggestpkg", conditionMessage(err)))
  # Base packages need not be in lib.
  expect_true("R/stats" %in% sbom_components(sbom_installed(c("suggestpkg", "stats"), lib = lib))$ref)
})

test_that("a library path that does not exist is an error", {
  nope <- file.path(withr::local_tempdir(), "nope")
  expect_error(sbom_installed(lib = nope), "nope")
  expect_error(sbom_installed(lib = c(fixture_lib(), nope)), "does not exist")
  expect_error(sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = nope), "does not exist")
})

test_that("a library with no packages is recorded as an issue", {
  x <- sbom_installed(lib = withr::local_tempdir())
  iss <- sbom_issues(x)
  row <- iss[iss$code == "library-empty", , drop = FALSE]
  expect_equal(nrow(row), 1L)
  expect_equal(row$severity, "warning")
  expect_equal(row$ref, "r-library")
  expect_equal(row$field, "library")
  expect_equal(row$message, "The library sbom read holds no installed packages.")
  expect_false("library-empty" %in% sbom_issues(sbom_installed(lib = fixture_lib()))$code)
})

test_that("SOURCE_DATE_EPOCH is used without a timestamp argument, and a note says so", {
  skip_on_cran()
  note <- "The timestamp comes from the SOURCE_DATE_EPOCH environment variable."
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), system = FALSE)
  expect_equal(format_timestamp(x$metadata$timestamp), "2023-11-14T22:13:20Z")
  expect_true(note %in% x$metadata$notes)
  expect_true(note %in% sbom_installed(lib = fixture_lib(), system = FALSE)$metadata$notes)
  withr::local_envvar(SOURCE_DATE_EPOCH = NA)
  y <- fixture_sbom()
  expect_equal(format_timestamp(y$metadata$timestamp), "2026-11-04T00:00:00Z")
  expect_false(note %in% y$metadata$notes)
})

test_that("an explicit timestamp wins over SOURCE_DATE_EPOCH, with no note about the variable", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  x <- fixture_sbom()
  expect_equal(format_timestamp(x$metadata$timestamp), "2026-11-04T00:00:00Z")
  expect_false(any(grepl("SOURCE_DATE_EPOCH|placeholder", x$metadata$notes)))
})

test_that("Nix's 1980 placeholder is used, with a note saying what it is", {
  skip_on_cran()
  note <- paste0(
    "The timestamp is 1980-01-01T00:00:00Z, the placeholder that Nix sets in ",
    "SOURCE_DATE_EPOCH, not the time this SBOM was made."
  )
  withr::local_envvar(SOURCE_DATE_EPOCH = "315532800")
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), system = FALSE)
  expect_equal(x$metadata$timestamp, as.POSIXct(315532800, origin = "1970-01-01", tz = "UTC"))
  expect_true(note %in% x$metadata$notes)
  expect_false(note %in% fixture_sbom()$metadata$notes)
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  expect_false(note %in% sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), system = FALSE)$metadata$notes)
})

test_that("a source tarball root records that its bundled code was not listed", {
  skip_on_cran()
  tmp <- withr::local_tempdir()
  tarball <- file.path(tmp, "srcpkg_0.1.0.tar.gz")
  withr::with_dir(test_path("fixtures/pkgs"), utils::tar(tarball, "srcpkg", compression = "gzip"))
  x <- sbom_package(tarball, lib = fixture_lib(), system = FALSE)
  iss <- sbom_issues(x)
  row <- iss[iss$code == "tarball-not-unpacked", ]
  expect_equal(nrow(row), 1L)
  expect_equal(row$severity, "info")
  expect_equal(row$ref, x$metadata$root)
  expect_equal(row$message, paste0(
    "The source tarball srcpkg_0.1.0.tar.gz was not unpacked, so the code bundled in it is not listed."
  ))
  expect_false("tarball-not-unpacked" %in% sbom_issues(sbom_package(tarball, lib = fixture_lib(), system = FALSE, embedded = FALSE))$code)
  folder <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), system = FALSE)
  expect_false("tarball-not-unpacked" %in% sbom_issues(folder)$code)
})

test_that("a root without Version gets no invented version or file name", {
  tmp <- withr::local_tempdir()
  writeLines("Package: myanalysis", file.path(tmp, "DESCRIPTION"))
  x <- sbom_package(tmp, lib = fixture_lib())
  iss <- sbom_issues(x)
  expect_false(any(grepl("\\bNA\\b", iss$message)))
  expect_true("myanalysis declares no version." %in% iss$message)
  root <- Find(function(p) p$SPDXID == "SPDXRef-local-myanalysis", spdx_document(x)$packages)
  expect_null(root$packageFileName)
  expect_false(grepl("_NA", spdx_json(x), fixed = TRUE))
})

test_that("a tarball root records the tarball's own file name", {
  tmp <- withr::local_tempdir()
  tarball <- file.path(tmp, "build-output.tar.gz")
  withr::with_dir(test_path("fixtures/pkgs"), utils::tar(tarball, "srcpkg", compression = "gzip"))
  x <- sbom_package(tarball, lib = fixture_lib())
  comps <- sbom_components(x)
  expect_equal(comps$package_file_name[comps$is_root], "build-output.tar.gz")
  y <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib())
  expect_true(is.na(sbom_components(y)$package_file_name[sbom_components(y)$is_root]))
})

test_that("author takes several people and drops NA and empty ones", {
  skip_on_cran()
  build <- function(author, organization = NULL) {
    sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(),
                 author = author, organization = organization)
  }
  x <- build(c("Ada Lovelace", NA, "", "Grace Hopper"))
  expect_equal(x$metadata$author, c("Ada Lovelace", "Grace Hopper"))
  expect_false("no-sbom-author" %in% sbom_issues(x)$code)
  expect_equal(cdx_document(x)$metadata$authors,
               list(list(name = "Ada Lovelace"), list(name = "Grace Hopper")))
  creators <- unlist(spdx_document(x)$creationInfo$creators)
  expect_equal(creators[startsWith(creators, "Person: ")],
               c("Person: Ada Lovelace", "Person: Grace Hopper"))
  doc <- xml2::read_xml(cdx_xml(x))
  xml2::xml_ns_strip(doc)
  expect_equal(xml2::xml_text(xml2::xml_find_all(doc, "/bom/metadata/authors/author/name")),
               c("Ada Lovelace", "Grace Hopper"))

  y <- build(c(NA, ""))
  expect_true(is.na(y$metadata$author))
  expect_true("no-sbom-author" %in% sbom_issues(y)$code)
  expect_false("no-sbom-author" %in% sbom_issues(build(c(NA, ""), "Org"))$code)
})

test_that("a numeric timestamp is seconds since 1970-01-01 UTC", {
  withr::local_envvar(SOURCE_DATE_EPOCH = NA)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), timestamp = 1700000000)
  expect_equal(format_timestamp(x$metadata$timestamp), "2023-11-14T22:13:20Z")
})

test_that("a maintainer taken from Authors@R survives a C locale", {
  local_c_ctype()
  dir <- withr::local_tempdir()
  writeLines(enc2utf8(c("Package: authpkg", "Version: 1.0", "License: MIT + file LICENSE",
    'Authors@R: person("Gábor", "Csárdi", email = "g@example.org", role = c("aut", "cre"))')),
    file.path(dir, "DESCRIPTION"), useBytes = TRUE)
  x <- sbom_package(dir, lib = local_fake_lib(list()))
  expect_equal(sbom_components(x)$maintainer[sbom_components(x)$is_root], "Gábor Csárdi")
})

test_that("base packages carry R's version when R's version is exact", {
  skip_on_cran()
  x <- sbom_installed(lib = fixture_lib(), r_version = "4.4.0", timestamp = 0, system = FALSE)
  comps <- x$components
  r <- comps[comps$ref == "R", , drop = FALSE]
  expect_identical(r$version_is, "exact")
  base <- comps[comps$parent_ref %in% "R", , drop = FALSE]
  expect_identical(base$ref, "R/methods")
  expect_identical(base$version, "4.4.0")
  expect_identical(base$version_is, "exact")
  expect_identical(base$evidence, r$evidence)
  expect_identical(base$evidence, "observed")
  # From a lockfile, R's version is declared, and so are the base packages'.
  dir <- withr::local_tempdir()
  lock <- list(R = list(Version = "4.5.0"), Packages = list(cli = list(
    Package = "cli", Version = "3.6.6", Source = "Repository", Repository = "CRAN",
    License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>", Requirements = list("utils")
  )))
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  y <- sbom_renv(file.path(dir, "renv.lock"), timestamp = 0, system = FALSE, embedded = FALSE)
  base <- y$components[y$components$parent_ref %in% "R", , drop = FALSE]
  expect_identical(base$ref, "R/utils")
  expect_identical(base$version, "4.5.0")
  expect_identical(base$version_is, "exact")
  expect_identical(base$evidence, "declared")
  expect_identical(base$evidence, y$components$evidence[y$components$ref == "R"])
  expect_valid_in_every_format(x, "base versions")
})

test_that("base packages stay versionless when R's version is a minimum", {
  tmp <- withr::local_tempdir()
  write_text("Package: bare\nVersion: 1.0\nDepends: R (>= 4.1.0)\nImports: utils, stats\n",
             file.path(tmp, "DESCRIPTION"))
  lib <- withr::local_tempdir()
  x <- sbom_package(tmp, lib = lib, timestamp = 0, system = FALSE)
  comps <- x$components
  expect_identical(comps$version_is[comps$ref == "R"], "minimum")
  base <- comps[comps$parent_ref %in% "R", , drop = FALSE]
  expect_identical(base$ref, c("R/stats", "R/utils"))
  expect_true(all(is.na(base$version)))
  expect_true(all(is.na(base$version_is)))
  expect_identical(base$evidence, c("inferred", "inferred"))
})
