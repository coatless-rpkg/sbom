test_that("sbom_diff() reports additions, removals and changes", {
  a <- fixture_sbom()
  b <- a
  b$components$version[b$components$ref == "pkg:cran/cranpkg@1.2.0"] <- "1.3.0"
  b$components$license_spdx[b$components$name == "localpkg"] <- "MIT"
  b$components <- b$components[b$components$name != "suggestpkg", ]
  d <- sbom_diff(a, b)
  expect_s3_class(d, "sbom_diff")
  ch <- as.data.frame(d)
  expect_equal(ch$change[ch$name == "cranpkg"], "version")
  expect_equal(ch$new[ch$name == "cranpkg"], "1.3.0")
  expect_equal(ch$change[ch$name == "localpkg"], "license")
  expect_equal(ch$change[ch$name == "suggestpkg"], "removed")
  expect_snapshot(print(d))
  expect_equal(nrow(as.data.frame(sbom_diff(a, a))), 0L)
  expect_snapshot(print(sbom_diff(a, a)))
})

test_that("sbom_diff() reports source changes and additions", {
  a <- fixture_sbom()
  b <- a
  i <- which(b$components$name == "cranpkg")
  b$components$purl[i] <- paste0(b$components$purl[i], "?repository_url=https://x.example")
  b$components$ecosystem[b$components$name == "localpkg"] <- "github"
  d <- as.data.frame(sbom_diff(b, a))
  expect_true(all(c("source") %in% d$change))
  expect_equal(d$old[d$name == "localpkg"], "github")
  expect_equal(as.data.frame(sbom_diff(a, b))$change[1], "source")
})

test_that("drift_issues() writes the pinned sentences", {
  a <- fixture_sbom()
  b <- a
  b$components$version[b$components$name == "cranpkg"] <- "1.3.0"
  iss <- drift_issues(empty_issues(), a, b, "renv.lock", "the project library")
  expect_equal(iss$message, "cranpkg is 1.2.0 in renv.lock but 1.3.0 in the project library.")
  expect_equal(iss$code, "drift-version")
  expect_equal(iss$severity, "warning")
})

test_that("drift_issues() reports missing and extra components, never R", {
  a <- fixture_sbom()
  b <- a
  b$components <- b$components[b$components$name != "suggestpkg", ]
  b$components$version[b$components$name == "R"] <- "0.0.1"
  iss <- drift_issues(empty_issues(), a, b, "the code", "renv.lock")
  expect_equal(iss$code, "drift-missing")
  expect_equal(iss$message, "suggestpkg 2.0.0 is in the code but not in renv.lock.")
  expect_equal(iss$ref, a$components$ref[a$components$name == "suggestpkg"])
  iss <- drift_issues(empty_issues(), b, a, "renv.lock", "the code")
  expect_equal(iss$code, "drift-extra")
  expect_equal(iss$ref, "unknown/suggestpkg")
  expect_equal(iss$message, "suggestpkg 2.0.0 is in the code but not in renv.lock.")
  a$components$version[a$components$name == "suggestpkg"] <- NA
  iss <- drift_issues(empty_issues(), b, a, "renv.lock", "the code")
  expect_equal(iss$message, "suggestpkg is in the code but not in renv.lock.")
})
test_that("sbom_diff() pairs the two roots whatever their refs", {
  lib <- fixture_lib()
  build <- function(version) {
    dir <- file.path(withr::local_tempdir(), "srcpkg")
    dir.create(dir)
    write_text(
      paste0("Package: srcpkg\nVersion: ", version, "\nRepository: CRAN\n"),
      file.path(dir, "DESCRIPTION")
    )
    sbom_package(dir, lib = lib, timestamp = as.POSIXct("2026-11-04", tz = "UTC"))
  }
  old <- build("1.0.0")
  new <- build("2.0.0")
  expect_false(identical(old$metadata$root, new$metadata$root))
  ch <- as.data.frame(sbom_diff(old, new))
  expect_equal(ch$change, "version")
  expect_equal(ch$name, "srcpkg")
  expect_equal(ch$new, "2.0.0")
})

test_that("sbom_diff() pairs R packages by name and system components by ref", {
  # deb/openssl sorts before local/openssl, the R package of the same name.
  local_mocked_bindings(
    sys_linked_libraries = function(so) "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    sys_os_package = function(path) list(manager = "deb", name = "openssl", version = "3.0.11-1", arch = "amd64")
  )
  build <- function(version) {
    lib <- local_fake_lib(list(openssl = c(Version = version, License = "MIT")), env = parent.frame())
    dir.create(file.path(lib, "openssl", "libs"))
    write_text("", file.path(lib, "openssl", "libs", "openssl.so"))
    sbom_installed("openssl", lib = lib)
  }
  old <- build("2.0")
  new <- build("2.1")
  ch <- as.data.frame(sbom_diff(old, new))
  expect_equal(ch$change, "version")
  expect_equal(ch$ecosystem, "local")
  expect_equal(ch$old, "2.0")
  expect_equal(ch$new, "2.1")
})
