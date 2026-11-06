# Absolute timing assertions are opt-in. They run only when the environment
# variable SBOM_TIMING_TESTS is "true", and never on CRAN: unrelated load on a
# busy machine has pushed calls past bounds three to five times their
# measured time. Run them at a quiet time:
#
#   SBOM_TIMING_TESTS=true Rscript -e 'devtools::test()'
#
# A test measures its times first, makes its other assertions, which always
# run, and calls skip_unless_timing() just before the assertions on the times.
skip_unless_timing <- function() {
  skip_on_cran()
  if (!identical(Sys.getenv("SBOM_TIMING_TESTS"), "true")) {
    skip("Timing assertions run only when SBOM_TIMING_TESTS is \"true\".")
  }
  invisible(TRUE)
}
