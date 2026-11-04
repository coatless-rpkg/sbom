run_app <- function(...) {
  cli::cli_text("Starting myapp")
  golem::with_golem_options(app = NULL, golem_opts = list(...))
}
