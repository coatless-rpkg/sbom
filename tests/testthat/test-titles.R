ts <- as.POSIXct("2026-01-01", tz = "UTC")

test_that("an R package's description is its Title, on one line", {
  lib <- local_fake_lib(list(
    titled = c(Version = "1.0.0", Repository = "CRAN", License = "MIT + file LICENSE",
      Title = "Tools for\n    Testing Titles", Imports = "methods"),
    methods = c(Version = "4.6.2", Priority = "base")
  ))
  x <- sbom_installed("titled", lib = lib, system = FALSE, timestamp = ts)
  comps <- sbom_components(x)
  expect_equal(comps$description[comps$name == "titled"], "Tools for Testing Titles")
  expect_equal(package_title(c(Package = "a")), NA_character_)
})

test_that("SPDX writes an R package's Title as its summary, and it reads back", {
  lib <- local_fake_lib(list(
    titled = c(Version = "1.0.0", Repository = "CRAN", License = "MIT + file LICENSE",
      Title = "Tools for Testing Titles", Imports = "methods")
  ))
  x <- sbom_installed("titled", lib = lib, system = FALSE, timestamp = ts)
  spdx <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(x, spdx)
  doc <- jsonlite::fromJSON(spdx, simplifyVector = FALSE)
  summaries <- vapply(doc$packages, function(p) if (is.null(p$summary)) NA_character_ else p$summary, "")
  names(summaries) <- vapply(doc$packages, function(p) p$name, "")
  expect_equal(unname(summaries["titled"]), "Tools for Testing Titles")
  expect_true(all(is.na(summaries[names(summaries) != "titled"])))
  for (ext in c(".spdx.json", ".spdx", ".spdx3.jsonld", ".cdx.json")) {
    f <- withr::local_tempfile(fileext = ext)
    write_sbom(x, f)
    back <- sbom_components(read_sbom(f))
    expect_equal(back$description[back$name == "titled"], "Tools for Testing Titles", info = ext)
  }
})
