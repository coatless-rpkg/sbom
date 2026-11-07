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

test_that("sbom_diff() finds no license or source change between an SBOM and itself read back from any format", {
  x <- fixture_sbom()
  dir <- withr::local_tempdir()
  formats <- sbom_formats()
  formats <- formats[formats$format != "csv", ]
  for (i in seq_len(nrow(formats))) {
    path <- file.path(dir, paste0("x", formats$extension[i]))
    write_sbom(x, path, format = formats$format[i])
    back <- suppressWarnings(read_sbom(path))
    ch <- as.data.frame(sbom_diff(x, back))
    expect_equal(ch$change[ch$change %in% c("license", "source")], character(), label = formats$format[i])
  }
})

test_that("sbom_diff() compares a license only in the forms both SBOMs state", {
  a <- fixture_sbom()
  at <- a$components$name == "suggestpkg"
  # The license as written on one side only, and a license one side does not
  # state at all, as a format without the field leaves them, are no change.
  b <- a
  b$components$license_as_written[at] <- NA
  b$components[b$components$name == "R", c("license_spdx", "license_as_written")] <- NA
  expect_equal(nrow(as.data.frame(sbom_diff(a, b))), 0L)
  expect_equal(nrow(as.data.frame(sbom_diff(b, a))), 0L)
  # When both state the license as written, a change to it counts.
  b <- a
  b$components$license_as_written[at] <- "MIT"
  ch <- as.data.frame(sbom_diff(a, b))
  expect_equal(ch$change, "license")
  expect_equal(c(ch$old, ch$new), c("MIT + file LICENSE", "MIT"))
  # An expression on one side and only the license as written on the other
  # are the same license when that translates to the expression.
  a$components$license_as_written[at] <- NA
  b <- a
  b$components$license_spdx[at] <- NA
  b$components$license_as_written[at] <- "MIT"
  expect_equal(nrow(as.data.frame(sbom_diff(a, b))), 0L)
  b$components$license_as_written[at] <- "file LICENSE"
  ch <- as.data.frame(sbom_diff(a, b))
  expect_equal(ch$change, "license")
  expect_equal(c(ch$old, ch$new), c("MIT", NA))
})

test_that("sbom_diff() compares package URLs when both have one, and else known ecosystems", {
  a <- fixture_sbom()
  # A document leaves sbom's own ecosystems unknown, and gives a repository
  # package the type of its package URL.
  b <- a
  b$components$ecosystem[b$components$ecosystem %in% c("r", "base-r", "local")] <- "unknown"
  b$components$ecosystem[b$components$name == "suggestpkg"] <- "repository"
  expect_equal(nrow(as.data.frame(sbom_diff(a, b))), 0L)
  expect_equal(nrow(as.data.frame(sbom_diff(b, a))), 0L)
  b <- a
  b$components$ecosystem[b$components$name == "localpkg"] <- "git"
  ch <- as.data.frame(sbom_diff(a, b))
  expect_equal(ch$change, "source")
  expect_equal(c(ch$old, ch$new), c("local", "git"))
  # Without a package URL on one side, the ecosystems are compared.
  b <- a
  at <- b$components$name == "suggestpkg"
  b$components$purl[at] <- NA
  b$components$ecosystem[at] <- "local"
  ch <- as.data.frame(sbom_diff(a, b))
  expect_equal(ch$change, "source")
  expect_equal(c(ch$old, ch$new), c("cran", "local"))
  b$components$ecosystem[at] <- "unknown"
  expect_equal(nrow(as.data.frame(sbom_diff(a, b))), 0L)
})
