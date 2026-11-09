# What CRAN's reviewers ask of a release, beyond R CMD check.

# The path of a file at the top of the package, from the source tree or the
# installed package; the test skips when the installation does not hold it.
release_file <- function(name) {
  path <- system.file(name, package = "sbom")
  if (!nzchar(path)) {
    skip(paste("The installed package holds no", name))
  }
  path
}

release_description <- function() {
  read.dcf(release_file("DESCRIPTION"), fields = c("Version", "Title", "Description"))[1L, ]
}

# The Rd pages, from man/ in the source tree or the installed help.
release_rd <- function() {
  root <- dirname(release_file("DESCRIPTION"))
  if (dir.exists(file.path(root, "man"))) tools::Rd_db(dir = root) else tools::Rd_db("sbom", lib.loc = dirname(root))
}

rd_tags <- function(rd) vapply(rd, function(section) attr(section, "Rd_tag"), "")

test_that("the version is 0.1.0, and NEWS opens with it", {
  expect_identical(release_description()[["Version"]], "0.1.0")
  news <- readLines(release_file("NEWS.md"), warn = FALSE, encoding = "UTF-8")
  expect_identical(grep("^# ", news, value = TRUE)[[1L]], "# sbom 0.1.0")
})

test_that("the Title is short, in title case, and names no redundant phrase", {
  title <- release_description()[["Title"]]
  expect_identical(title, "Create, Read and Validate Software Bills of Materials")
  expect_lt(nchar(title), 65L)
  # Quoted names keep their own case.
  masked <- gsub("'[^']*'", "'X'", title)
  expect_identical(gsub("'[^']*'", "'X'", tools::toTitleCase(masked)), masked)
  expect_false(grepl("Tools for|Toolkit for|for R\\b", title))
})

test_that("the Description opens well, quotes software names and expands every acronym", {
  desc <- gsub("\\s+", " ", release_description()[["Description"]])
  expect_false(grepl("^(This package|sbom|Functions for|The sbom)", desc, ignore.case = TRUE))
  sentences <- length(gregexpr("[.!?]( |$)", desc)[[1L]])
  expect_gte(sentences, 3L)
  expect_lte(sentences, 5L)
  # Each name is quoted wherever it appears.
  for (name in c("R", "CycloneDX", "SPDX", "SWID", "OSV", "renv", "Posit Connect", "Nix", "rix", "Shiny")) {
    unquoted <- gsub(paste0("'", name, "'"), "", desc, fixed = TRUE)
    expect_false(grepl(paste0("\\b", name, "\\b"), unquoted), label = name)
    expect_true(grepl(paste0("'", name, "'"), desc, fixed = TRUE), label = name)
  }
  # Each acronym is spelled out where it first appears.
  for (acronym in list(
    c("SPDX", "Software Package Data Exchange ('"),
    c("SWID", "Software Identification ('"),
    c("CSV", "comma-separated values ("),
    c("OSV", "Open Source Vulnerabilities ('"),
    c("NTIA", "National Telecommunications and Information Administration (")
  )) {
    first <- regexpr(paste0("\\b", acronym[[1L]], "\\b"), desc)
    expect_gt(first, 0L, label = acronym[[1L]])
    expect_true(endsWith(substr(desc, 1L, first - 1L), acronym[[2L]]), label = acronym[[1L]])
  }
  # No other acronym goes unexplained.
  expect_false(grepl("\\b(SBOMs?|URL|purl|API|SHACL|ISO|US|JSON|XML|YAML)\\b", desc))
})

test_that("the Description says what each format is checked against, as validate_sbom() does", {
  desc <- gsub("\\s+", " ", release_description()[["Description"]])
  # The schema each specification publishes (SPDX 2's is for JSON, which XML
  # and tag-value are converted to), or structural rules for SWID, whose ISO
  # schema is not bundled.
  expect_match(desc, paste(
    "Check each document against the schema that its specification publishes,",
    "or structural rules where that schema is not bundled, against integrity rules,"
  ), fixed = TRUE)
  # No claim of one bundled schema for every format.
  expect_false(grepl("'SPDX' documents are checked against the bundled schema|schema of each format|every format", desc))

  # validate_sbom()'s schema layer agrees, on sbom's own output.
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  reg <- format_registry()
  formats <- c("cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-yaml", "spdx-xml", "spdx-tv", "spdx3-jsonld", "swid")
  status <- vapply(formats, function(f) {
    path <- withr::local_tempfile(fileext = reg[[f]]$extension)
    write_sbom(fixture_sbom(), path, format = f)
    schema_validate(path, f)$status
  }, "")
  expect_identical(status, stats::setNames(rep(c("pass", "partial"), each = 4L), formats))
})

test_that("every exported function's Rd page has a value and runnable examples", {
  rd <- release_rd()
  exports <- getNamespaceExports("sbom")
  documented <- character()
  dontruns <- character()
  for (name in names(rd)) {
    page <- rd[[name]]
    tags <- rd_tags(page)
    aliases <- unlist(lapply(page[tags == "\\alias"], as.character))
    if (!any(aliases %in% exports)) {
      next
    }
    documented <- c(documented, intersect(aliases, exports))
    expect_true("\\value" %in% tags, label = name)
    expect_true("\\examples" %in% tags, label = name)
    out <- withr::local_tempfile(fileext = ".R")
    tools::Rd2ex(page, out, commentDontrun = FALSE, commentDonttest = FALSE)
    code <- readLines(out, warn = FALSE, encoding = "UTF-8")
    code <- code[!startsWith(code, "### ")]
    # No commented-out code: a comment never starts with a call or an
    # assignment.
    commented <- grepl("^\\s*#+\\s*([[:alpha:].][[:alnum:]._]*(::[[:alpha:].][[:alnum:]._]*)?\\s*\\(|[[:alpha:].][[:alnum:]._]*\\s*<-)", code)
    expect_identical(code[commented], character(), label = name)
    # \dontrun{} only for what needs the network, with a comment saying so,
    # and no \donttest{}.
    tools::Rd2ex(page, out, commentDontrun = TRUE, commentDonttest = TRUE)
    marked <- readLines(out, warn = FALSE, encoding = "UTF-8")
    dontrun <- grep("^## Not run:", marked)
    expect_identical(trimws(marked[dontrun]), rep("## Not run:", length(dontrun)), label = name)
    expect_true(all(startsWith(marked[dontrun + 1L], "##D # Needs the network")), label = name)
    expect_false(any(startsWith(marked, "## No test:")), label = name)
    dontruns <- c(dontruns, if (length(dontrun) > 0L) name)
  }
  # The network forms of advisories = TRUE and snapshot.
  expect_setequal(dontruns, c("sbom_advisories.Rd", "sbom_nix.Rd"))
  expect_setequal(documented, exports)
})

test_that("the README installs from CRAN and links only by full https URLs", {
  readme <- paste(readLines(release_file("README.md"), warn = FALSE, encoding = "UTF-8"), collapse = "\n")
  expect_match(readme, 'install.packages("sbom")', fixed = TRUE)
  links <- regmatches(readme, gregexpr("\\]\\([^)]*\\)", readme))[[1L]]
  expect_identical(links[!startsWith(links, "](https://")], character())
  expect_false(grepl("http://", readme, fixed = TRUE))
})

# Timing tests are opt-in ----------------------------------------------------------

test_that("skip_unless_timing() skips unless SBOM_TIMING_TESTS is true, and always on CRAN", {
  withr::local_envvar(NOT_CRAN = "true", SBOM_TIMING_TESTS = NA)
  expect_condition(skip_unless_timing(), class = "skip")
  withr::local_envvar(SBOM_TIMING_TESTS = "TRUE")
  expect_condition(skip_unless_timing(), class = "skip")
  withr::local_envvar(SBOM_TIMING_TESTS = "true")
  expect_no_condition(skip_unless_timing())
  withr::local_envvar(NOT_CRAN = NA)
  expect_condition(skip_unless_timing(), class = "skip")
})

# The calls in `x`, `x` among them, at every depth.
calls_in <- function(x) {
  if (!is.call(x)) {
    return(list())
  }
  c(list(x), unlist(lapply(as.list(x)[-1L], calls_in), recursive = FALSE))
}

lhs_name <- function(x) if (is.name(x)) as.character(x) else lhs_name(x[[2L]])

test_that("every absolute timing assertion waits for skip_unless_timing(), and nothing else does", {
  files <- list.files(test_path(), pattern = "^test-.*[.]R$", full.names = TRUE)
  timed <- 0L
  for (file in files) {
    for (e in parse(file, keep.source = FALSE)) {
      if (!is.call(e) || !identical(e[[1L]], as.name("test_that")) || !"system.time" %in% all.names(e)) {
        next
      }
      timed <- timed + 1L
      label <- paste0(basename(file), ": ", e[[2L]])
      statements <- as.list(e[[3L]])[-1L]
      # The variables that hold a measured time.
      times <- character()
      for (call in calls_in(e[[3L]])) {
        assigns <- identical(call[[1L]], as.name("<-")) || identical(call[[1L]], as.name("="))
        if (assigns && "system.time" %in% all.names(call[[3L]])) {
          times <- c(times, lhs_name(call[[2L]]))
        }
      }
      is_skip <- vapply(statements, identical, TRUE, quote(skip_unless_timing()))
      expect_identical(sum(is_skip), 1L, label = label)
      if (sum(is_skip) != 1L) {
        next
      }
      at <- which(is_skip)
      timing <- function(call) any(all.names(call) %in% c(times, "system.time"))
      expectations <- function(s) Filter(function(call) startsWith(as.character(call[[1L]])[[1L]], "expect_"), calls_in(s))
      # Before the skip, no expectation reads a time.
      for (s in statements[seq_len(at - 1L)]) {
        for (call in expectations(s)) {
          expect_false(timing(call), label = paste(label, deparse1(call)))
        }
      }
      # After it, every expectation reads one.
      for (s in statements[-seq_len(at)]) {
        for (call in expectations(s)) {
          expect_true(timing(call), label = paste(label, deparse1(call)))
        }
      }
    }
  }
  expect_gt(timed, 0L)
})
