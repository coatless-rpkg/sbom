# A maintainer may set sbom.swid_xsd in .Rprofile, as the docs invite; the
# tests expect it unset unless a test sets it.
withr::local_options(sbom.swid_xsd = NULL, .local_envir = testthat::teardown_env())
