#' Example projects and files
#'
#' sbom comes with small example projects and files to try it on, the ones its
#' guides use. `sbom_example()` lists them, and returns the path of one.
#'
#' The examples are:
#'
#' * `"analysis"`: an analysis script and an renv lockfile that misses one of
#'   the packages the script uses.
#' * `"analysis-manifest.json"`: the Posit Connect manifest of that analysis,
#'   which pins a newer cli than the lockfile.
#' * `"connect-app"`: an app deployed to Posit Connect, with its `app.R`, its
#'   `manifest.json` and its `renv.lock`, which disagree.
#' * `"dashboard.cdx.json"`: a CycloneDX SBOM of a Python app, as another tool
#'   might write it.
#' * `"library"`: a library holding one package, cli. A library is a folder of
#'   package folders with `DESCRIPTION` files, which is all sbom reads.
#' * `"nix-project"`: a project with a `default.nix` written by rix.
#' * `"PACKAGES"`: a CRAN `PACKAGES` file that gives the versions of the
#'   packages in that `default.nix`, for the `snapshot` argument of
#'   [sbom_nix()].
#' * `"osv-all.zip"`: an OSV advisory export, as `advisories` takes it, with
#'   one made-up advisory against holeypkg 1.0.0.
#' * `"report-before"` and `"report-after"`: a project before and after an
#'   update of its lockfile.
#' * `"shiny-app"`: a Shiny app with jQuery in its `www` folder. The jQuery
#'   file holds only the library's header comment.
#' * `"study"`: a study that uses an in-house package, inhouse, which uses a
#'   CRAN package, holeypkg.
#' * `"study-overrides.csv"`: overrides that answer what sbom cannot find out
#'   about the study. Copied into the study as `sbom-overrides.csv`, [sbom()]
#'   applies them by itself.
#'
#' The packages are real where an example needs real ones, such as cli and
#' jsonlite, and made up otherwise, such as holeypkg, inhouse and notarealpkg.
#'
#' The examples are installed with sbom and should not be changed. To add a
#' file to a project, as the guides do, ask for a copy.
#'
#' @param name The name of an example, or `NULL` to list them.
#' @param copy If `TRUE`, the example is copied into a new temporary folder,
#'   under the same name, and the path of the copy is returned. R deletes the
#'   copy at the end of the session.
#' @return With `name = NULL`, the names of the examples, as a character
#'   vector. Otherwise the path of the example, a folder or a file.
#' @examples
#' sbom_example()
#' sbom(sbom_example("study"), system = FALSE)
#'
#' # A copy, to change.
#' study <- sbom_example("study", copy = TRUE)
#' file.copy(sbom_example("study-overrides.csv"), file.path(study, "sbom-overrides.csv"))
#' sbom(study, system = FALSE)
#' @export
sbom_example <- function(name = NULL, copy = FALSE) {
  root <- system.file("extdata", "examples", package = "sbom", mustWork = TRUE)
  examples <- sort(list.files(root), method = "radix")
  if (is.null(name)) {
    return(examples)
  }
  if (!is.character(name) || length(name) != 1L || is.na(name)) {
    cli::cli_abort("{.arg name} must be a single string or {.code NULL}, not {.obj_type_friendly {name}}.")
  }
  if (!is.logical(copy) || length(copy) != 1L || is.na(copy)) {
    cli::cli_abort("{.arg copy} must be {.code TRUE} or {.code FALSE}.")
  }
  if (!name %in% examples) {
    cli::cli_abort(c(
      "There is no example called {.val {name}}.",
      i = "The examples are {.val {examples}}."
    ))
  }
  path <- file.path(root, name)
  if (!copy) {
    return(path)
  }
  dest <- tempfile("sbom-example-")
  dir.create(dest)
  if (!file.copy(path, dest, recursive = TRUE)) {
    cli::cli_abort("Could not copy the example {.val {name}} to {.file {dest}}.")
  }
  file.path(dest, name)
}
