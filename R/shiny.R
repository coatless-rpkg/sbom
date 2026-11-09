# Shiny apps: recognizing an app folder, giving the app its own root, and
# recording the JavaScript and CSS it ships. Detection reads files as text and
# runs no code from the app.

#' Build an SBOM for a Shiny app
#'
#' `sbom_shiny()` describes a Shiny app folder: the app is the root
#' component, an application, the R packages it needs come from the strongest
#' source in the folder, and the JavaScript and CSS libraries the app ships
#' are recorded under it. It runs no code from the app unless you ask for
#' `evaluate_ui = TRUE`, and it makes no network requests, except that, with
#' Nix installed, a `default.nix` is read by running `nix-instantiate` (see
#' [sbom_nix()]), which may download nixpkgs, and that `snapshot` and
#' `advisories = TRUE`, passed through `...`, look up a CRAN snapshot and
#' download OSV's advisory data.
#'
#' The layouts it recognizes, checked in this order:
#'
#' 1. `rhino`: the folder has `rhino.yml`. Its static files are in
#'    `app/static`.
#' 2. `golem`: a `DESCRIPTION` with a `Package` field, and either
#'    `inst/golem-config.yml` or both `R/app_ui.R` and `R/app_server.R`.
#'    The root is the app, named and versioned by its `DESCRIPTION`, which
#'    also gives its license and maintainer whatever source the packages come
#'    from. Its static files are in `inst/app/www`.
#' 3. `app.R`: the folder has an `app.R`. Its static files are in `www`.
#' 4. `ui-server`: the folder has both `ui.R` and `server.R`. Its static
#'    files are in `www`.
#'
#' The R packages come from the strongest source, as for [sbom()]: `renv.lock`,
#' then a Posit Connect `manifest.json`, then `default.nix`, then a package
#' `DESCRIPTION` (a golem app's declared Imports are stronger than a code
#' scan), then a scan of the code. Every other source present cross-checks
#' it. When the folder holds a Posit Connect manifest, a note says the app
#' was deployed there.
#'
#' The libraries in the static folder are found by the header comments of
#' their files, as for the JavaScript in a package, with the same bounds: six
#' levels, no symlinked folders, a fixed number of files. They are inferred
#' components under the root. A rhino app's npm dependencies are not read;
#' when the app has a `package.json` or `package-lock.json`, an issue records
#' that they were left out.
#'
#' @param path A Shiny app folder.
#' @param evaluate_ui Whether to run the app's code to find the html
#'   dependencies (JavaScript and CSS) its UI holds. `FALSE` by default.
#'
#'   `evaluate_ui = TRUE` runs the app's code in a separate R process, which
#'   is stopped after 60 seconds. It works for `app.R` and `ui.R` apps. For an
#'   `app.R` app the whole of `app.R` runs, not only its UI code; for a `ui.R`
#'   app, `ui.R` runs. `global.R` and the app's `R/` folder are not sourced,
#'   so an app that relies on them fails, with the issue below. The process
#'   starts R with `--vanilla` and inherits this session's environment
#'   variables, except that `R_LIBS` is set to the library given by `lib`, or
#'   else [.libPaths()]; R also adds the user and site libraries after it. It
#'   needs the htmltools package in those libraries. What it finds are
#'   observed components, nested under the R package that ships each one. A
#'   dependency whose name, version or package sbom does not accept is left
#'   out, and one issue counts them. If the UI cannot be evaluated, an issue
#'   gives the reason and the SBOM keeps the static result.
#'
#'   It finds only the dependencies the UI holds when it is built, and
#'   misses any that `renderUI()` or other server code inserts later.
#' @param ... The named arguments of [sbom()].
#' @return An `<sbom>` object. See [sbom_components()] to read it.
#' @examples
#' app <- file.path(tempdir(), "app")
#' dir.create(app)
#' writeLines("shiny::shinyApp(shiny::fluidPage(), function(input, output) {})",
#'   file.path(app, "app.R"))
#' sbom_shiny(app, system = FALSE, lib = character())
#' @export
sbom_shiny <- function(path = ".", evaluate_ui = FALSE, ...) {
  args <- check_project_args(path, list(...))
  layout <- shiny_layout(path)
  if (is.na(layout)) {
    cli::cli_abort(paste0(
      "{.file {path}} does not look like a Shiny app: it has no app.R, ",
      "no ui.R and server.R, no golem structure and no rhino.yml."
    ))
  }
  if (!isTRUE(evaluate_ui) && !isFALSE(evaluate_ui)) {
    cli::cli_abort("{.arg evaluate_ui} must be {.code TRUE} or {.code FALSE}.")
  }
  sbom_project(path, args, layout, evaluate_ui = evaluate_ui)
}

# The layout of the Shiny app in `path`: "rhino", "golem", "app.R" or
# "ui-server", checked in that order, or NA for a folder that is not an app.
shiny_layout <- function(path) {
  has <- function(...) {
    f <- file.path(path, ...)
    file.exists(f) && !dir.exists(f)
  }
  if (has("rhino.yml")) {
    return("rhino")
  }
  if (has("DESCRIPTION") && identical(description_status(file.path(path, "DESCRIPTION")), "package") &&
    (has("inst", "golem-config.yml") || (has("R", "app_ui.R") && has("R", "app_server.R")))) {
    return("golem")
  }
  if (has("app.R")) {
    return("app.R")
  }
  if (has("ui.R") && has("server.R")) {
    return("ui-server")
  }
  NA_character_
}

# The folders of an app's own static files, relative to the app folder.
app_static_dirs <- function(layout) {
  switch(layout,
    golem = file.path("inst", "app", "www"),
    rhino = file.path("app", "static"),
    "www"
  )
}

# The root component of the app in `path`, and its issues: a golem app is
# named for its package, every other layout for its folder.
app_root <- function(path, layout) {
  if (!identical(layout, "golem")) {
    return(project_root_component(path))
  }
  d <- read_description(file.path(path, "DESCRIPTION"))
  name <- enc2utf8_bytes(desc_field(d, "Package"))
  version <- desc_field(d, "Version")
  version <- if (is.na(version) || !nzchar(trimws(version))) NA_character_ else enc2utf8_bytes(trimws(version))
  ref <- paste0("project/", name)
  # The license and maintainer, read as for any package, whatever source the
  # packages come from.
  license <- desc_field(d, "License")
  row <- component_row(
    ref = ref, name = name, version = version,
    version_is = if (is.na(version)) NA_character_ else "exact",
    type = "application", ecosystem = "local", is_root = TRUE,
    scope = "required", evidence = "declared", source_input = "project",
    maintainer = unname(desc_maintainer(d)[["name"]]),
    license_as_written = if (!is.na(license)) license_normalize(license),
    license_spdx = if (!is.na(license)) license_spdx(license),
    license_comment = if (!is.na(license)) license_comment(license)
  )
  issues <- empty_issues()
  if (is.na(version)) {
    issues <- add_issue(
      issues, ref, "version", "version-missing",
      paste0("The DESCRIPTION of ", name, " has no Version field, so the app has no version.")
    )
  }
  list(component = row, issues = issues)
}

# The JavaScript and CSS libraries in the app's static folder, as components
# under `root` (its component row), with their relationships and issues.
app_assets <- function(path, layout, root) {
  js <- javascript_components(path, root, dirs = app_static_dirs(layout))
  list(components = js$components, relationships = js$relationships, issues = js$issues)
}

# The html dependencies that the UI of the app in `path` holds, found by
# running its UI code in a child process (see sys_ui_dependencies()), added to
# `components`. Each is an observed component `<parent ref>#js/<name>@<version>`,
# where the parent is the top-level package component that ships it, else the
# root (`root`, its row). A static component with the same ref is kept, with
# its evidence raised to observed. Returns list(components, relationships,
# issues, observed): all the components, the new relationships only, the
# issues, and the refs of every component the UI confirmed or added.
ui_dependencies <- function(path, layout, components, root, lib = .libPaths()) {
  none <- list(
    components = components, relationships = empty_relationships(),
    issues = empty_issues(), observed = character()
  )
  if (!layout %in% c("app.R", "ui-server")) {
    none$issues <- add_issue(
      none$issues, root$ref, "dependencies", "evaluate-ui-unsupported",
      paste0(
        "sbom can evaluate the UI only of app.R and ui.R apps, so this ", layout,
        " app's browser assets come from static detection only."
      ),
      severity = "info"
    )
    return(none)
  }
  deps <- sys_ui_dependencies(path, layout, lib = lib)
  if (!is.data.frame(deps)) {
    reason <- attr(deps, "reason")
    if (is.null(reason) || length(reason) != 1L || is.na(reason)) {
      reason <- "the UI evaluation did not finish"
    }
    none$issues <- add_issue(
      none$issues, root$ref, "dependencies", "evaluate-ui-failed",
      paste0(
        "sbom could not evaluate the app's UI (", reason, "), so its browser ",
        "assets come from static detection only."
      )
    )
    return(none)
  }
  deps <- deps[!duplicated(deps[c("name", "version", "package")]), , drop = FALSE]
  # The child ran the app's code, so its text is checked before it becomes a
  # ref or a purl.
  bad <- !ui_dependency_ok(deps)
  if (any(bad)) {
    n <- sum(bad)
    none$issues <- add_issue(
      none$issues, root$ref, "dependencies", "evaluate-ui-skipped",
      paste0(
        n, if (n == 1L) " html dependency from the evaluated UI has a name or version" else
          " html dependencies from the evaluated UI have names or versions",
        " sbom does not accept, so ", if (n == 1L) "it is" else "they are", " not listed."
      ),
      severity = "info"
    )
    deps <- deps[!bad, , drop = FALSE]
  }
  if (nrow(deps) == 0L) {
    return(none)
  }
  deps <- deps[order(deps$name, deps$version, method = "radix"), , drop = FALSE]
  rules <- javascript_rules()
  packages <- components[!grepl("#", components$ref, fixed = TRUE) & !components$is_root, , drop = FALSE]
  new <- list()
  observed <- character()
  added <- character()
  for (i in seq_len(nrow(deps))) {
    name <- deps$name[[i]]
    version <- deps$version[[i]]
    known <- !is.na(version) && nzchar(version)
    pkg <- packages[!is.na(deps$package[[i]]) & packages$name == deps$package[[i]], , drop = FALSE]
    parent <- if (nrow(pkg) > 0L) pkg[1L, , drop = FALSE] else components[components$ref == root$ref, , drop = FALSE]
    ref <- paste0(parent$ref, "#js/", name, if (known) paste0("@", version))
    if (ref %in% added) {
      next
    }
    hit <- components$ref == ref
    if (any(hit)) {
      components$evidence[hit] <- "observed"
      observed <- c(observed, ref)
      next
    }
    added <- c(added, ref)
    npm <- rules$npm[tolower(rules$name) == tolower(name)]
    npm <- if (length(npm) == 1L) npm else ""
    new[[length(new) + 1L]] <- component_row(
      ref = ref, name = name,
      version = if (known) version, version_is = if (known) "exact",
      type = "library", ecosystem = "npm", scope = parent$scope,
      parent_ref = parent$ref,
      purl = if (known && nzchar(npm)) npm_purl(npm, version),
      description = paste0(
        "Held by the UI of ", root$name, " when it is built, as an html ",
        "dependency", if (!is.na(deps$package[[i]])) paste0(" of ", deps$package[[i]]), "."
      ),
      evidence = "observed", source_input = parent$source_input
    )
  }
  rel <- empty_relationships()
  if (length(new) > 0L) {
    new <- do.call(rbind, new)
    components <- rbind(components, new)
    rel <- data.frame(
      from = new$parent_ref, to = new$ref, field = "contains",
      spec = NA_character_, evidence = "observed", stringsAsFactors = FALSE
    )
  }
  list(
    components = components, relationships = rel, issues = none$issues,
    observed = unique(c(observed, rel$to))
  )
}

# Whether each evaluated html dependency (a row of name, version and package)
# has text sbom accepts: a name and, when given, a version of conservative
# characters, and a package that is an R package name or empty.
ui_dependency_ok <- function(deps) {
  given <- function(x) !is.na(x) & nzchar(x)
  name_ok <- given(deps$name) & grepl("^[A-Za-z0-9][A-Za-z0-9._@/+-]{0,99}$", deps$name)
  version_ok <- !given(deps$version) | grepl("^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,49}$", deps$version)
  package_ok <- !given(deps$package) | grepl("^[A-Za-z][A-Za-z0-9.]*[A-Za-z0-9]$", deps$package)
  name_ok & version_ok & package_ok
}

# `x` with the app as its root, its own assets, and the notes a Shiny app
# adds. Run after the cross-checks and before the overrides.
apply_app_layout <- function(x, path, layout, evaluate_ui = FALSE, lib = .libPaths()) {
  root <- app_root(path, layout)
  # The old root's issues about what it is (its version, supplier, maintainer
  # and package URL) are no longer true of the app, which says its own.
  identity <- c("version", "supplier", "maintainer", "purl")
  stale <- x$issues$ref %in% x$metadata$root & x$issues$field %in% identity
  x$issues <- x$issues[!stale, , drop = FALSE]
  x <- replace_root(x, root$component)
  x$issues <- rbind(x$issues, root$issues)

  assets <- app_assets(path, layout, root$component)
  fresh <- !assets$components$ref %in% x$components$ref
  assets$issues <- assets$issues[
    !assets$issues$ref %in% assets$components$ref[!fresh], , drop = FALSE
  ]
  x$components <- rbind(x$components, assets$components[fresh, , drop = FALSE])
  x$relationships <- rbind(
    x$relationships, assets$relationships[fresh, , drop = FALSE]
  )
  x$issues <- rbind(x$issues, assets$issues)

  if (evaluate_ui) {
    ui <- ui_dependencies(path, layout, x$components, root$component, lib = lib)
    x$components <- ui$components
    x$relationships$evidence[x$relationships$to %in% ui$observed] <- "observed"
    x$relationships <- rbind(x$relationships, ui$relationships)
    x$issues <- rbind(x$issues, ui$issues)
  }

  if (identical(layout, "rhino")) {
    npm <- c("package.json", "package-lock.json", file.path(".rhino", c("package.json", "package-lock.json")))
    npm <- npm[file.exists(file.path(path, npm)) & !dir.exists(file.path(path, npm))]
    if (length(npm) > 0L) {
      x$issues <- add_issue(
        x$issues, x$metadata$root, "dependencies", "npm-not-covered",
        paste0(
          "The app's npm dependencies in ", npm[[1L]], " are not in this SBOM, ",
          "because sbom does not read npm files yet."
        )
      )
    }
  }

  manifest <- file.path(path, "manifest.json")
  if (file.exists(manifest) && !dir.exists(manifest) && is_connect_manifest(manifest)) {
    sentence <- connect_sentence(jsonlite::read_json(manifest))
    x$metadata$notes <- unique(c(x$metadata$notes, enc2utf8_bytes(sentence)))
  }
  rownames(x$components) <- NULL
  rownames(x$relationships) <- NULL
  rownames(x$issues) <- NULL
  x
}

# `x` with its root component replaced by `new`, and every ref that is the
# old root, or is nested in it, moved to the new one (rewrite_refs()). The
# new row keeps what the old root recorded that it does not say itself: its
# dependencies, license, maintainer and the like.
replace_root <- function(x, new) {
  old <- x$metadata$root
  comps <- x$components
  i <- which(comps$ref == old)
  row <- new
  if (length(i) == 1L) {
    keep <- setdiff(
      component_columns(),
      c("ref", "name", "version", "version_is", "type", "ecosystem", "is_root", "scope",
        "parent_ref", "purl", "evidence", "source_input", "supplier_name", "supplier_url")
    )
    for (col in keep) {
      if (is.list(comps[[col]])) {
        row[[col]] <- comps[[col]][i]
      } else if (is.na(row[[col]])) {
        row[[col]] <- comps[[col]][[i]]
      }
    }
    comps <- rbind(comps[seq_len(nrow(comps)) < i, , drop = FALSE], row,
      comps[seq_len(nrow(comps)) > i, , drop = FALSE])
  }
  x$components <- comps
  rewrite_refs(x, ref_mover(old, new$ref))
}
