# Makes the Nix commands answer from the fixtures in `dir` (see its
# README.md): Nix is installed, and every output is built when `built` is
# TRUE and none is when it is FALSE; a function of the paths says which. The mocks last until `env` ends.
local_nix_store <- function(dir, built = TRUE, env = parent.frame()) {
  text <- function(file) {
    readLines(file.path(dir, file), encoding = "UTF-8", warn = FALSE)
  }
  testthat::local_mocked_bindings(
    sys_nix_available = function() TRUE,
    sys_nix_instantiate = function(file) text("instantiate.txt"),
    sys_nix_query = function(args) {
      switch(args[[1L]],
        "--references" = text("references.txt"),
        "--outputs" = text("outputs.txt"),
        "--requisites" = text("requisites.txt"),
        "--graph" = text("graph.dot"),
        NULL
      )
    },
    nix_store_exists = function(paths) {
      if (is.function(built)) built(paths) else rep(built, length(paths))
    },
    nix_store_description = function(out, pkg) {
      file <- file.path(dir, "descriptions", paste0(pkg, ".dcf"))
      if (file.exists(file)) read_description(file)
    },
    .package = "sbom", .env = env
  )
}
