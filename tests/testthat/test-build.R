test_that("sbom_package() builds the fixture tree", {
  x <- fixture_sbom()
  comps <- sbom_components(x)
  expect_setequal(comps$ref, c("local/srcpkg", "pkg:cran/cranpkg@1.2.0", "local/localpkg",
                               "pkg:cran/suggestpkg@2.0.0", "R", "R/utils", "R/methods"))
  expect_equal(comps$scope[comps$ref == "pkg:cran/suggestpkg@2.0.0"], "optional")
  expect_equal(comps$version_is[comps$ref == "R"], "minimum")
  rel <- sbom_dependencies(x)
  expect_equal(rel$spec[rel$to == "pkg:cran/cranpkg@1.2.0" & rel$field == "Imports"], "cranpkg (>= 1.0.0)")
  expect_true(any(rel$field == "LinkingTo"))
  expect_true(all(c("R/utils", "R/methods") %in% rel$to[rel$field == "contains"]))
  expect_false(any(grepl("deeppkg", c(comps$ref, sbom_issues(x)$message))))
})

test_that("dropping Suggests drops suggested packages", {
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), dependencies = c("Depends", "Imports", "LinkingTo"),
                    lib = fixture_lib())
  expect_false("pkg:cran/suggestpkg@2.0.0" %in% sbom_components(x)$ref)
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
  expect_equal(a$metadata$inputs$kind, c("package", "library"))
  expect_identical(sbom_components(a)$ref, sort(sbom_components(a)$ref, method = "radix"))
})

test_that("metadata records the author, notes, and the missing-author issue", {
  x <- fixture_sbom()
  expect_equal(x$metadata$author, "Test Author")
  expect_equal(x$metadata$notes[[1]], "R is listed at the lowest version stated, R (>= 4.1.0).")
  expect_length(x$metadata$notes, 3)
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

test_that("sbom_installed() handles explicit, unknown and base packages", {
  lib <- fixture_lib()
  x <- sbom_installed(c("suggestpkg", "zzz"), lib = lib, name = "mylib")
  comps <- sbom_components(x)
  expect_equal(comps$name[comps$is_root], "mylib")
  expect_true(all(c("unknown/zzz", "unknown/deeppkg") %in% comps$ref))
  expect_false("pkg:cran/cranpkg@1.2.0" %in% comps$ref)
  iss <- sbom_issues(x)
  expect_true("zzz is named as a dependency of mylib but is not installed in the library sbom read, so its version and source are unknown." %in% iss$message)
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
