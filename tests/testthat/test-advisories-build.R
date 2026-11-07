osv_zip <- function() test_path("fixtures", "osv", "all.zip")

osv_url <- "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip"

bioc_note <- "The advisory database does not cover Bioconductor packages yet."
file_note <- paste0(
  "Advisory data is OSV's CRAN export, read from all.zip, with records modified up to ",
  "2099-06-30T12:00:00.5Z."
)

# A package folder whose DESCRIPTION imports fakepkg, and a fake library that
# holds fakepkg from CRAN at `version`, as list(pkg, lib).
local_fakepkg_project <- function(version = "1.0.0", env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  pkg <- file.path(dir, "rootpkg")
  dir.create(pkg)
  write_text("Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: fakepkg\n", file.path(pkg, "DESCRIPTION"))
  lib <- write_fake_lib(file.path(dir, "lib"), list(
    fakepkg = c(Version = version, Repository = "CRAN", License = "MIT", Maintainer = "A B <a@example.org>")
  ))
  list(pkg = pkg, lib = lib)
}

# sbom_package() of that project, with `...` passed on.
fakepkg_sbom <- function(..., env = parent.frame()) {
  p <- local_fakepkg_project(env = env)
  sbom_package(
    p$pkg, lib = p$lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE, ...
  )
}

# Mocks osv_download() to copy the fixture zip to its destination, recording
# each URL in calls$urls.
local_osv_download <- function(calls = new.env(), env = parent.frame()) {
  zip <- osv_zip()
  local_mocked_bindings(osv_download = function(url, dest, ...) {
    calls$urls <- c(calls$urls, url)
    file.copy(zip, dest, overwrite = TRUE)
  }, .env = env)
  invisible(calls)
}

# An upstream record as osv_lookup() returns it: parsed JSON with one severity.
upstream_record <- function(id, vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", type = "CVSS_V3") {
  json_parse_strict(sprintf('{"id": "%s", "severity": [{"type": "%s", "score": "%s"}]}', id, type, vector))
}

# Mocks osv_lookup() to return `record(id)`, recording each id in calls$ids.
local_osv_lookup <- function(calls = new.env(), record = upstream_record, env = parent.frame()) {
  local_mocked_bindings(osv_lookup = function(id, ...) {
    calls$ids <- c(calls$ids, id)
    record(id)
  }, .env = env)
  invisible(calls)
}

# minimal_sbom() with the components given added.
with_components <- function(...) {
  x <- minimal_sbom()
  x$components <- rbind(x$components, ...)
  x
}

cran_row <- function(name, version, version_is = "exact", ecosystem = "cran") {
  purl <- paste0("pkg:cran/", name, if (!is.na(version)) paste0("@", version))
  component_row(
    ref = purl, name = name, version = version,
    version_is = if (!is.na(version)) version_is, type = "library",
    ecosystem = ecosystem, purl = purl
  )
}

# The value of `expr`, a build under advisories_on_error = "continue" whose
# advisory data cannot be read, checking that it raised exactly one warning,
# of class sbom_advisories_unavailable. The warning's text goes to
# `seen$text`.
expect_unavailable <- function(expr, seen = new.env()) {
  seen$text <- character()
  value <- withCallingHandlers(expr, warning = function(w) {
    seen$text <- c(seen$text, cli::ansi_strip(conditionMessage(w)))
    expect_s3_class(w, "sbom_advisories_unavailable")
    invokeRestart("muffleWarning")
  })
  expect_length(seen$text, 1L)
  value
}

# The text of the message of the condition `expr` signals, or NA.
condition_text <- function(expr) {
  tryCatch(
    {
      expr
      NA_character_
    },
    condition = function(cnd) cli::ansi_strip(conditionMessage(cnd))
  )
}

# The issue messages of `x` with code `code`.
issue_messages <- function(x, code) {
  x$issues$message[x$issues$code %in% code]
}

# Every sentence that sbom writes or prints about `x`'s advisories: notes,
# issues, the inform text of sbom_advisories(), and print() and summary().
advisory_text <- function(x) {
  inform <- new.env()
  inform$text <- character()
  withCallingHandlers(
    sbom_advisories(x),
    message = function(m) {
      inform$text <- c(inform$text, cli::ansi_strip(conditionMessage(m)))
      invokeRestart("muffleMessage")
    }
  )
  c(
    x$metadata$notes, x$issues$message, inform$text,
    utils::capture.output(print(x)), utils::capture.output(print(summary(x)))
  )
}

test_that("a local advisory file lists the advisories of exact versions without the network", {
  local_mocked_bindings(
    osv_download = function(...) stop("osv_download() must not run for a local file."),
    osv_lookup = function(...) stop("osv_lookup() must not run for a local file.")
  )
  x <- fakepkg_sbom(advisories = osv_zip())
  adv <- sbom_advisories(x)
  expect_identical(adv$id, "RSEC-9000-1")
  expect_identical(adv$name, "fakepkg")
  expect_identical(adv$version, "1.0.0")
  expect_identical(adv$ref, "pkg:cran/fakepkg@1.0.0")
  expect_identical(adv$fixed, "1.1.0")
  expect_identical(adv$cves, "CVE-2099-0001")
  expect_identical(adv$summary, "Synthetic flaw in fakepkg")
  expect_identical(adv$published, "2099-01-02")
  expect_identical(adv$url, "https://osv.dev/vulnerability/RSEC-9000-1")
  expect_identical(adv$source_url, "https://example.org/r-advisory-database/vulns/fakepkg/RSEC-9000-1.yaml")

  notes <- x$metadata$notes
  expect_true(listed_note %in% notes)
  expect_true(file_note %in% notes)
  expect_false(no_data_note %in% notes)
  expect_false(bioc_note %in% notes)
  # The notes name the file by its basename, never by its path.
  expect_false(any(grepl(dirname(normalizePath(osv_zip())), notes, fixed = TRUE)))
  expect_identical(tail(notes, 2L), c(listed_note, file_note))

  inputs <- x$metadata$inputs
  expect_identical(inputs$path[inputs$kind == "advisories"], osv_zip())
  meta <- x$metadata$advisories
  expect_identical(meta$status, "listed")
  expect_true(meta$requested)
  expect_identical(meta$source, "all.zip")
  expect_true(is.na(meta$fetched))
  expect_identical(meta$newest_modified, "2099-06-30T12:00:00.5Z")

  # Offline, no rating is looked up, so none is listed and no issue says so.
  expect_identical(nrow(x$advisories$ratings[[1]]), 0L)
  expect_false("advisories-ratings-unavailable" %in% x$issues$code)
})

test_that("advisories = TRUE downloads OSV's export and looks up each upstream id once", {
  downloads <- local_osv_download()
  lookups <- local_osv_lookup()
  x <- fakepkg_sbom(advisories = TRUE)

  expect_identical(downloads$urls, osv_url)
  expect_identical(sbom_advisories(x)$id, "RSEC-9000-1")
  ratings <- x$advisories$ratings[[1]]
  expect_identical(ratings$upstream, "CVE-2099-0001")
  expect_identical(ratings$score, 8.8)
  expect_identical(ratings$severity, "high")
  expect_identical(ratings$method, "CVSSv3")
  expect_identical(ratings$vector, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")

  # Every upstream id of the export's live records is looked up once, so that
  # the lookups do not show which advisories matched, and no package name is
  # sent.
  expect_identical(sort(lookups$ids), c("CVE-2099-0001", "CVE-2099-0003", "GHSA-xxxx-yyyy-zzzz"))
  expect_false(any(lookups$ids %in% c(x$components$name, x$components$ref)))

  pattern <- paste0(
    "^Advisory data is OSV's CRAN export, downloaded from ", gsub(".", "[.]", osv_url, fixed = TRUE),
    " on [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z[.]$"
  )
  expect_identical(sum(grepl(pattern, x$metadata$notes)), 1L)
  expect_identical(x$metadata$inputs$path[x$metadata$inputs$kind == "advisories"], osv_url)
  expect_identical(x$metadata$advisories$source, osv_url)
  expect_s3_class(x$metadata$advisories$fetched, "POSIXct")
  expect_false(is.na(x$metadata$advisories$fetched))
})

test_that("a CVSS 4.0 vector is a rating without a score or severity", {
  local_osv_download()
  local_osv_lookup(record = function(id) {
    upstream_record(id, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS_V4")
  })
  ratings <- fakepkg_sbom(advisories = TRUE)$advisories$ratings[[1]]
  expect_identical(ratings$method, "CVSSv4")
  expect_true(is.na(ratings$score))
  expect_true(is.na(ratings$severity))
  expect_identical(ratings$vector, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
})

test_that("a failed download is an error, or with 'continue' an issue and a note", {
  # The suite's mock of osv_download() fails.
  expect_error(fakepkg_sbom(advisories = TRUE), class = "sbom_advisories_error")

  seen <- new.env()
  x <- expect_unavailable(fakepkg_sbom(advisories = TRUE, advisories_on_error = "continue"), seen)
  expect_identical(
    seen$text,
    "OSV's advisory data could not be read (the download failed: not run in tests), so this SBOM lists no advisories."
  )
  expect_identical(
    issue_messages(x, "advisories-unavailable"),
    "sbom could not read OSV's advisory data (the download failed: not run in tests), so this file lists no advisories."
  )
  expect_identical(x$issues$severity[x$issues$code == "advisories-unavailable"], "warning")
  expect_identical(tail(x$metadata$notes, 1L), no_data_note)
  expect_false(listed_note %in% x$metadata$notes)
  expect_identical(x$metadata$advisories$status, "unavailable")
  expect_true(x$metadata$advisories$requested)
  expect_identical(nrow(x$advisories), 0L)
  expect_false("advisories" %in% x$metadata$inputs$kind)

  # sbom_advisories() says why it lists none, so that a script that counts its
  # rows is told.
  expect_message(adv <- sbom_advisories(x), "could not be read")
  expect_identical(nrow(adv), 0L)
  expect_identical(
    trimws(condition_text(sbom_advisories(x))),
    "OSV's advisory data could not be read when this SBOM was built, so it lists no advisories; see `sbom_issues()`."
  )
})

test_that("a damaged local file under 'continue' names it by its basename", {
  seen <- new.env()
  x <- expect_unavailable(
    fakepkg_sbom(advisories = test_path("fixtures", "osv", "bad-json.zip"), advisories_on_error = "continue"),
    seen
  )
  expect_match(seen$text, "(bad-json.zip is damaged: the record RSEC-9000-90.json is not valid JSON)", fixed = TRUE)
  expect_identical(
    issue_messages(x, "advisories-unavailable"),
    paste0(
      "sbom could not read OSV's advisory data (bad-json.zip is damaged: the record ",
      "RSEC-9000-90.json is not valid JSON), so this file lists no advisories."
    )
  )
  expect_error(
    fakepkg_sbom(advisories = test_path("fixtures", "osv", "bad-json.zip")),
    class = "sbom_advisories_error"
  )
})

test_that("a zip of records sbom cannot read, or without a CRAN record, is an error or with 'continue' a warning", {
  reasons <- c(
    `not-cran.zip` = "it holds no CRAN records",
    `affected-object.zip` = "the record RSEC-9000-96.json is not an OSV record",
    `empty-affected.zip` = "the record RSEC-9000-97.json is not an OSV record",
    `no-package.zip` = "the record RSEC-9000-98.json is not an OSV record"
  )
  for (zip in names(reasons)) {
    path <- test_path("fixtures", "osv", zip)
    reason <- paste0(zip, " is damaged: ", reasons[[zip]])
    err <- tryCatch(fakepkg_sbom(advisories = path), sbom_advisories_error = identity)
    expect_s3_class(err, "sbom_advisories_error")
    expect_identical(err$sentence, paste0("The OSV advisory file ", reason, "."), label = zip)

    seen <- new.env()
    x <- expect_unavailable(fakepkg_sbom(advisories = path, advisories_on_error = "continue"), seen)
    expect_identical(
      seen$text, paste0("OSV's advisory data could not be read (", reason, "), so this SBOM lists no advisories."),
      label = zip
    )
    expect_identical(
      issue_messages(x, "advisories-unavailable"),
      paste0("sbom could not read OSV's advisory data (", reason, "), so this file lists no advisories."),
      label = zip
    )
    # Nothing says that the file is OSV's CRAN export, or that it lists what
    # OSV lists.
    expect_identical(tail(x$metadata$notes, 1L), no_data_note, label = zip)
    expect_false(listed_note %in% x$metadata$notes, label = zip)
    expect_false(any(startsWith(x$metadata$notes, "Advisory data is OSV's CRAN export")), label = zip)
    expect_identical(x$metadata$advisories$status, "unavailable", label = zip)
  }
})

test_that("failed rating lookups are one issue, and the advisories are still listed", {
  local_osv_download()
  # The suite's mock of osv_lookup() finds nothing.
  x <- fakepkg_sbom(advisories = TRUE)
  expect_identical(sbom_advisories(x)$id, "RSEC-9000-1")
  expect_identical(nrow(x$advisories$ratings[[1]]), 0L)
  expect_identical(
    issue_messages(x, "advisories-ratings-unavailable"),
    "The CVSS rating of 1 upstream record could not be looked up, so it is not listed (CVE-2099-0001)."
  )
  expect_identical(x$issues$severity[x$issues$code == "advisories-ratings-unavailable"], "info")

  y <- apply_advisories(with_components(cran_row("fakepkg", "1.0.0"), cran_row("lastpkg", "1.1")), TRUE, "error")
  expect_identical(sbom_advisories(y)$id, c("RSEC-9000-1", "RSEC-9000-3"))
  expect_identical(
    issue_messages(y, "advisories-ratings-unavailable"),
    paste0(
      "The CVSS ratings of 3 upstream records could not be looked up, so they are not listed ",
      "(CVE-2099-0001, CVE-2099-0003 and GHSA-xxxx-yyyy-zzzz)."
    )
  )
})

test_that("the lookups stop after one fails at the connection, and the rest count as unavailable", {
  local_osv_download()
  calls <- new.env()
  calls$ids <- character()
  local_mocked_bindings(osv_lookup = function(id, ...) {
    calls$ids <- c(calls$ids, id)
    structure(FALSE, reason = "the connection failed")
  })
  y <- apply_advisories(with_components(cran_row("fakepkg", "1.0.0"), cran_row("lastpkg", "1.1")), TRUE, "error")
  expect_identical(calls$ids, "CVE-2099-0001")
  expect_identical(sbom_advisories(y)$id, c("RSEC-9000-1", "RSEC-9000-3"))
  expect_identical(
    issue_messages(y, "advisories-ratings-unavailable"),
    paste0(
      "The CVSS ratings of 3 upstream records could not be looked up, so they are not listed ",
      "(CVE-2099-0001, CVE-2099-0003 and GHSA-xxxx-yyyy-zzzz)."
    )
  )

  # A record the server did not give, as for an HTTP error, does not stop
  # the others.
  calls$ids <- character()
  local_mocked_bindings(osv_lookup = function(id, ...) {
    calls$ids <- c(calls$ids, id)
    if (id == "CVE-2099-0001") NULL else upstream_record(id)
  })
  y <- apply_advisories(with_components(cran_row("fakepkg", "1.0.0"), cran_row("lastpkg", "1.1")), TRUE, "error")
  expect_identical(calls$ids, c("CVE-2099-0001", "CVE-2099-0003", "GHSA-xxxx-yyyy-zzzz"))
  expect_identical(
    issue_messages(y, "advisories-ratings-unavailable"),
    "The CVSS rating of 1 upstream record could not be looked up, so it is not listed (CVE-2099-0001)."
  )
  expect_identical(nrow(y$advisories$ratings[[2]]), 2L)
})

test_that("the lookups together take no longer than the cap, 120 seconds", {
  expect_identical(osv_lookup_seconds(), 120)
  local_osv_download()
  calls <- new.env()
  calls$timeouts <- numeric()
  local_mocked_bindings(osv_lookup = function(id, timeout = 30) {
    calls$timeouts <- c(calls$timeouts, timeout)
    Sys.sleep(0.2)
    upstream_record(id)
  })
  y <- apply_advisories(with_components(cran_row("fakepkg", "1.0.0")), TRUE, "error")
  # Each lookup may take 30 seconds, or what is left of the cap.
  expect_identical(calls$timeouts, c(30, 30, 30))

  calls$timeouts <- numeric()
  withr::local_options(sbom.osv_lookup_seconds = 0.1)
  y <- apply_advisories(with_components(cran_row("fakepkg", "1.0.0")), TRUE, "error")
  expect_identical(calls$timeouts, 1)
  expect_identical(sbom_advisories(y)$id, "RSEC-9000-1")
  expect_identical(nrow(y$advisories$ratings[[1]]), 1L)
  # The ids not looked up count as unavailable; CVE-2099-0001 was looked up.
  expect_false("advisories-ratings-unavailable" %in% y$issues$code)
  z <- apply_advisories(with_components(cran_row("lastpkg", "1.1")), TRUE, "error")
  expect_identical(
    issue_messages(z, "advisories-ratings-unavailable"),
    paste0(
      "The CVSS ratings of 2 upstream records could not be looked up, so they are not listed ",
      "(CVE-2099-0003 and GHSA-xxxx-yyyy-zzzz)."
    )
  )
})

test_that("a download larger than the cap is an advisories error", {
  local_osv_download()
  withr::local_options(sbom.osv_max_mb = 0.001)
  err <- tryCatch(fakepkg_sbom(advisories = TRUE), sbom_advisories_error = identity)
  expect_s3_class(err, "sbom_advisories_error")
  expect_identical(err$sentence, paste0("OSV's advisory data downloaded from ", osv_url, " is larger than 0.001 MB."))
  seen <- new.env()
  x <- expect_unavailable(fakepkg_sbom(advisories = TRUE, advisories_on_error = "continue"), seen)
  expect_identical(
    seen$text,
    "OSV's advisory data could not be read (the download is larger than 0.001 MB), so this SBOM lists no advisories."
  )
  expect_identical(x$metadata$advisories$status, "unavailable")
  # The default cap is 50 MB.
  withr::local_options(sbom.osv_max_mb = NULL)
  expect_identical(osv_max_mb(), 50)
})

test_that("without advisories, the note is in every format and sbom_advisories() says why it is empty", {
  x <- fixture_sbom()
  expect_identical(x$metadata$advisories$status, "not-requested")
  expect_false(x$metadata$advisories$requested)
  expect_identical(tail(x$metadata$notes, 1L), no_data_note)
  expect_identical(nrow(x$advisories), 0L)

  formats <- setdiff(sbom_formats()$format, "csv")
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  for (f in formats) {
    tf <- withr::local_tempfile(fileext = ext[[f]])
    write_sbom(x, tf, format = f)
    text <- gsub("[[:space:]]+", " ", paste(readLines(tf, warn = FALSE), collapse = " "))
    expect_identical(lengths(gregexpr(no_data_note, text, fixed = TRUE)), 1L, label = f)
    expect_true(grepl(no_data_note, text, fixed = TRUE), label = f)
  }

  expect_message(adv <- sbom_advisories(x), "built without advisories")
  expect_identical(nrow(adv), 0L)
  expect_identical(
    names(adv),
    c("id", "ref", "name", "version", "summary", "published", "fixed", "no_fix", "cves", "url", "source_url")
  )
  expect_identical(typeof(adv$no_fix), "logical")
  msg <- tryCatch(sbom_advisories(x), message = function(m) cli::ansi_strip(conditionMessage(m)))
  expect_identical(
    trimws(msg),
    "This SBOM was built without advisories; build it with `advisories = TRUE` to list them."
  )
})

test_that("versions OSV cannot be compared with are named in issues, singular and plural", {
  sha <- strrep("a1", 20)
  one <- apply_advisories(
    with_components(cran_row("minpkg", "1.0", version_is = "minimum"), cran_row("shapkg", sha)),
    osv_zip(), "error"
  )
  expect_identical(
    issue_messages(one, "advisories-no-exact-version"),
    "1 package has no exact version, so OSV's advisories were not looked up for it (minpkg)."
  )
  expect_identical(
    issue_messages(one, "advisories-not-compared"),
    paste0(
      "OSV's advisories could not all be compared with the version of 1 package (shapkg), ",
      "so this file may not list every advisory for it."
    )
  )
  expect_identical(one$issues$severity[startsWith(one$issues$code, "advisories-")], c("info", "info"))

  two <- apply_advisories(
    with_components(
      cran_row("minpkg", "1.0", version_is = "minimum"), cran_row("nonepkg", NA_character_),
      cran_row("shapkg", sha), cran_row("badpkg", "1.0")
    ),
    osv_zip(), "error"
  )
  expect_identical(
    issue_messages(two, "advisories-no-exact-version"),
    "2 packages have no exact version, so OSV's advisories were not looked up for them (minpkg and nonepkg)."
  )
  expect_identical(
    issue_messages(two, "advisories-not-compared"),
    paste0(
      "OSV's advisories could not all be compared with the versions of 2 packages (badpkg and shapkg), ",
      "so this file may not list every advisory for them."
    )
  )
})

test_that("name lists in advisory issues stop at 20", {
  rows <- lapply(sprintf("min%02d", 1:23), cran_row, version = "1.0", version_is = "minimum")
  x <- apply_advisories(do.call(with_components, rows), osv_zip(), "error")
  expect_identical(
    issue_messages(x, "advisories-no-exact-version"),
    paste0(
      "23 packages have no exact version, so OSV's advisories were not looked up for them (",
      paste(sprintf("min%02d", 1:20), collapse = ", "), ", and 3 more)."
    )
  )
})

test_that("a Bioconductor component adds the coverage note", {
  x <- apply_advisories(with_components(cran_row("biocpkg", "1.0", ecosystem = "bioconductor")), osv_zip(), "error")
  expect_true(all(c(listed_note, bioc_note) %in% x$metadata$notes))
  expect_identical(match(bioc_note, x$metadata$notes), match(listed_note, x$metadata$notes) + 1L)
  y <- apply_advisories(minimal_sbom(), osv_zip(), "error")
  expect_false(bioc_note %in% y$metadata$notes)
  # So does a component whose CRAN package URL names Bioconductor, which is
  # not compared.
  purl <- "pkg:cran/biocpkg@1.0?repository_url=https://bioconductor.org/packages/3.20/bioc"
  z <- apply_advisories(
    with_components(component_row(ref = purl, name = "biocpkg", version = "1.0", version_is = "exact",
                                  type = "library", ecosystem = "repository", purl = purl)),
    osv_zip(), "error"
  )
  expect_true(bioc_note %in% z$metadata$notes)
  expect_false(any(startsWith(z$issues$code, "advisories-")))
})

# A package folder whose DESCRIPTION imports `imports`, and a library that
# holds the packages `lib`, a named list of DESCRIPTION fields as
# write_fake_lib() takes them, as list(dir, pkg, lib).
local_root_project <- function(imports, lib = list(), env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  pkg <- file.path(dir, "rootpkg")
  dir.create(pkg)
  write_text(
    paste0("Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: ", paste(imports, collapse = ", "), "\n"),
    file.path(pkg, "DESCRIPTION")
  )
  path <- file.path(dir, "lib")
  if (length(lib) > 0L) write_fake_lib(path, lib) else dir.create(path)
  list(dir = dir, pkg = pkg, lib = path)
}

not_cran_one <- function(name) {
  paste0("1 R package is not known to come from CRAN, so OSV's advisories were not looked up for it (", name, ").")
}

test_that("a dependency given a version and a CRAN package URL by overrides is matched", {
  p <- local_root_project("fakepkg (>= 0.1)")
  overrides <- data.frame(
    component = "fakepkg", field = c("version", "purl"), value = c("1.0.0", "pkg:cran/fakepkg@1.0.0"),
    asserted_by = "Tester", reason = "Known from the deployment.", stringsAsFactors = FALSE
  )
  x <- sbom_package(
    p$pkg, lib = p$lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
    overrides = overrides, advisories = osv_zip()
  )
  comp <- x$components[x$components$name == "fakepkg", , drop = FALSE]
  expect_identical(comp$version_is, "exact")
  expect_identical(comp$ecosystem, "cran")
  adv <- sbom_advisories(x)
  expect_identical(adv$id, "RSEC-9000-1")
  expect_identical(adv$version, "1.0.0")
  expect_identical(adv$fixed, "1.1.0")
  expect_false(any(c("advisories-no-exact-version", "advisories-not-cran") %in% x$issues$code))

  # A version asserted without a package URL leaves the origin unknown, so the
  # package is named instead.
  y <- sbom_package(
    p$pkg, lib = p$lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
    overrides = overrides[1, ], advisories = osv_zip()
  )
  expect_identical(nrow(sbom_advisories(y)), 0L)
  expect_identical(issue_messages(y, "advisories-not-cran"), not_cran_one("fakepkg"))
})

test_that("a package installed from a local source is named, not matched", {
  p <- local_root_project("fakepkg", list(
    fakepkg = c(Version = "1.0.0", License = "MIT", Maintainer = "A B <a@example.org>")
  ))
  x <- sbom_package(
    p$pkg, lib = p$lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
    advisories = osv_zip()
  )
  expect_identical(x$components$ref[x$components$name == "fakepkg"], "local/fakepkg")
  expect_identical(nrow(sbom_advisories(x)), 0L)
  expect_identical(issue_messages(x, "advisories-not-cran"), not_cran_one("fakepkg"))
  expect_identical(x$issues$severity[x$issues$code == "advisories-not-cran"], "info")
  expect_identical(x$issues$ref[x$issues$code == "advisories-not-cran"], x$metadata$root)
})

test_that("a code scan without a library names the packages it found", {
  p <- local_root_project("fakepkg")
  proj <- file.path(p$dir, "proj")
  dir.create(proj)
  write_text("library(fakepkg)\nlibrary(openpkg)\nlibrary(stats)\n", file.path(proj, "app.R"))
  x <- sbom(proj, lib = p$lib, author = "Tester", embedded = FALSE, system = FALSE, advisories = osv_zip())
  expect_identical(nrow(sbom_advisories(x)), 0L)
  expect_identical(
    issue_messages(x, "advisories-not-cran"),
    paste0(
      "2 R packages are not known to come from CRAN, so OSV's advisories were not looked up for them ",
      "(fakepkg and openpkg)."
    )
  )
})

test_that("a package installed from GitHub is named, not matched", {
  p <- local_root_project("fakepkg", list(fakepkg = c(
    Version = "1.0.0", License = "MIT", Maintainer = "A B <a@example.org>", RemoteType = "github",
    RemoteUsername = "someone", RemoteRepo = "fakepkg", RemoteSha = strrep("a1", 20)
  )))
  x <- sbom_package(
    p$pkg, lib = p$lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
    advisories = osv_zip()
  )
  expect_identical(x$components$ecosystem[x$components$name == "fakepkg"], "github")
  expect_identical(nrow(sbom_advisories(x)), 0L)
  expect_identical(issue_messages(x, "advisories-not-cran"), not_cran_one("fakepkg"))
})

test_that("only R packages of unknown or other origin are named, at most 20", {
  row <- function(name, ecosystem, ...) {
    component_row(ref = paste0(ecosystem, "/", name), name = name, type = "library", ecosystem = ecosystem, ...)
  }
  x <- with_components(
    row("unkpkg", "unknown"), row("locpkg", "local", version = "1.0", version_is = "exact"),
    row("gitpkg", "git", version = "1.0"), row("labpkg", "gitlab"), row("bbpkg", "bitbucket"),
    row("repopkg", "repository", version = "1.0"),
    # Not R packages of unknown origin: these are left out.
    row("syspkg", "system"), row("jslib", "npm"), row("vendlib", "vendored"),
    component_row(ref = "R/stats", name = "stats", type = "library", ecosystem = "base-r"),
    component_row(ref = "pkg:cran/fakepkg@1.0.0#embedded/unkcopy", name = "unkcopy", type = "library",
                  ecosystem = "unknown"),
    cran_row("biocpkg", "1.0", ecosystem = "bioconductor")
  )
  # The root is never named.
  x$components$ecosystem[x$components$is_root] <- "local"
  x$components$purl[x$components$is_root] <- NA_character_
  y <- apply_advisories(x, osv_zip(), "error")
  expect_identical(
    issue_messages(y, "advisories-not-cran"),
    paste0(
      "6 R packages are not known to come from CRAN, so OSV's advisories were not looked up for them ",
      "(bbpkg, gitpkg, labpkg, locpkg, repopkg and unkpkg)."
    )
  )
  many <- lapply(sprintf("unk%02d", 1:23), row, ecosystem = "unknown")
  z <- apply_advisories(do.call(with_components, many), osv_zip(), "error")
  expect_identical(
    issue_messages(z, "advisories-not-cran"),
    paste0(
      "23 R packages are not known to come from CRAN, so OSV's advisories were not looked up for them (",
      paste(sprintf("unk%02d", 1:20), collapse = ", "), ", and 3 more)."
    )
  )
})

# A project folder whose renv.lock holds fakepkg 1.0.0 from CRAN.
local_lock_project <- function(env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  write_text(paste0(
    '{"R": {"Version": "4.4.1", "Repositories": [{"Name": "CRAN", "URL": "https://cloud.r-project.org"}]},\n',
    ' "Packages": {"fakepkg": {"Package": "fakepkg", "Version": "1.0.0", "Source": "Repository",\n',
    '   "Repository": "CRAN", "License": "MIT", "Maintainer": "A B <a@example.org>"}}}\n'
  ), file.path(dir, "renv.lock"))
  dir
}

# Mocks osv_read_zip() to count its calls in calls$n.
local_count_reads <- function(env = parent.frame()) {
  calls <- new.env()
  calls$n <- 0L
  real <- osv_read_zip
  local_mocked_bindings(osv_read_zip = function(...) {
    calls$n <- calls$n + 1L
    real(...)
  }, .env = env)
  calls
}

test_that("sbom() matches advisories once, after the overrides, and never in a cross-check", {
  dir <- local_lock_project()
  # A package DESCRIPTION, read by sbom_package() to cross-check renv.lock.
  write_text("Package: lockproj\nVersion: 0.1.0\nLicense: MIT\nImports: fakepkg\n", file.path(dir, "DESCRIPTION"))
  reads <- local_count_reads()
  x <- sbom(dir, advisories = osv_zip(), embedded = FALSE, system = FALSE, author = "Tester")
  expect_identical(sbom_advisories(x)$id, "RSEC-9000-1")
  expect_true(all(c("renv.lock", "DESCRIPTION", "code") %in% x$metadata$inputs$kind))
  expect_identical(reads$n, 1L)
  expect_identical(sum(x$metadata$notes == listed_note), 1L)
  expect_false(no_data_note %in% x$metadata$notes)
  expect_identical(sum(x$metadata$inputs$kind == "advisories"), 1L)

  overrides <- data.frame(
    component = "fakepkg", field = "version", value = "1.1.0", asserted_by = "Tester",
    reason = "The package was upgraded.", stringsAsFactors = FALSE
  )
  y <- sbom(dir, advisories = osv_zip(), overrides = overrides, embedded = FALSE, system = FALSE, author = "Tester")
  expect_identical(reads$n, 2L)
  expect_false("RSEC-9000-1" %in% sbom_advisories(y)$id)
  expect_identical(y$components$version[y$components$name == "fakepkg"], "1.1.0")

  # Without advisories, the note appears once, at the end.
  z <- sbom(dir, embedded = FALSE, system = FALSE, author = "Tester")
  expect_identical(reads$n, 2L)
  expect_identical(sum(z$metadata$notes == no_data_note), 1L)
  expect_identical(tail(z$metadata$notes, 1L), no_data_note)
  expect_identical(z$metadata$advisories$status, "not-requested")

  # advisories_on_error passes through `...` too; the suite's download fails.
  expect_error(sbom(dir, advisories = TRUE, embedded = FALSE, system = FALSE), class = "sbom_advisories_error")
  u <- expect_unavailable(
    sbom(dir, advisories = TRUE, advisories_on_error = "continue", embedded = FALSE, system = FALSE)
  )
  expect_identical(u$metadata$advisories$status, "unavailable")
  expect_identical(sum(u$metadata$notes == no_data_note), 1L)
  expect_identical(sum(u$issues$code == "advisories-unavailable"), 1L)
})

test_that("sbom_shiny() matches advisories once, after the app layout", {
  dir <- local_lock_project()
  write_text("shiny::shinyApp(shiny::fluidPage(), function(input, output) {})\n", file.path(dir, "app.R"))
  reads <- local_count_reads()
  x <- sbom_shiny(dir, advisories = osv_zip(), embedded = FALSE, system = FALSE, author = "Tester")
  expect_identical(reads$n, 1L)
  expect_identical(sbom_advisories(x)$id, "RSEC-9000-1")
  expect_identical(x$components$type[x$components$is_root], "application")
  expect_identical(sum(x$metadata$notes == listed_note), 1L)
})

test_that("every builder takes advisories", {
  p <- local_fakepkg_project()
  lock <- file.path(local_lock_project(), "renv.lock")
  nix <- withr::local_tempfile(fileext = ".nix")
  write_text(paste0(
    "# This file was generated by the {rix} R package v0.18.6 on 2026-11-05\n",
    "let\n",
    "  pkgs = import (fetchTarball \"https://github.com/rstats-on-nix/nixpkgs/archive/2024-10-01.tar.gz\") {};\n",
    "  rpkgs = builtins.attrValues {\n",
    "    inherit (pkgs.rPackages) fakepkg;\n",
    "  };\n",
    "in rpkgs\n"
  ), nix)
  built <- list(
    installed = sbom_installed("fakepkg", lib = p$lib, embedded = FALSE, system = FALSE, advisories = osv_zip()),
    renv = sbom_renv(lock, embedded = FALSE, system = FALSE, advisories = osv_zip()),
    rsconnect = sbom_rsconnect(
      file.path(sbom_example("connect-app"), "manifest.json"), embedded = FALSE, system = FALSE,
      advisories = osv_zip()
    ),
    nix = sbom_nix(nix, nix = FALSE, embedded = FALSE, system = FALSE, advisories = osv_zip())
  )
  for (name in names(built)) {
    x <- built[[name]]
    expect_identical(x$metadata$advisories$status, "listed", label = name)
    expect_true(listed_note %in% x$metadata$notes, label = name)
    expect_false(no_data_note %in% x$metadata$notes, label = name)
  }
  expect_identical(sbom_advisories(built$installed)$id, "RSEC-9000-1")
  expect_identical(sbom_advisories(built$renv)$id, "RSEC-9000-1")
  # The Nix file names fakepkg without a version.
  expect_identical(
    issue_messages(built$nix, "advisories-no-exact-version"),
    "1 package has no exact version, so OSV's advisories were not looked up for it (fakepkg)."
  )
})

test_that("the advisory arguments are checked before anything is read", {
  missing <- file.path(withr::local_tempdir(), "missing.zip")
  folder <- withr::local_tempdir()
  nowhere <- file.path(withr::local_tempdir(), "nowhere")
  # Each reader is pointed at a source that does not exist, so the error shows
  # that the advisory arguments were checked first.
  builders <- list(
    package = function(...) sbom_package(nowhere, ...),
    installed = function(...) sbom_installed(lib = nowhere, ...),
    renv = function(...) sbom_renv(file.path(nowhere, "renv.lock"), ...),
    rsconnect = function(...) sbom_rsconnect(file.path(nowhere, "manifest.json"), ...),
    nix = function(...) sbom_nix(file.path(nowhere, "default.nix"), ...),
    sbom = function(...) sbom(nowhere, ...),
    shiny = function(...) sbom_shiny(nowhere, ...)
  )
  for (name in names(builders)) {
    build <- builders[[name]]
    expect_error(build(advisories = missing), "The OSV advisory file .* does not exist", label = name)
    expect_error(build(advisories = folder), "is a folder, not OSV's all.zip", label = name)
    expect_error(build(advisories = 5), "advisories", label = name)
    expect_error(build(advisories_on_error = "x"), "advisories_on_error", label = name)
    expect_error(build(advisories_on_error = NULL), "advisories_on_error", label = name)
  }
  for (bad in list(5, NA, c(TRUE, TRUE), "", NA_character_, NULL)) {
    expect_error(sbom_package(nowhere, advisories = bad), "advisories", label = deparse(bad))
  }
  for (bad in list(c("continue", "error"), "continue ", NA_character_, TRUE, character())) {
    expect_error(sbom_package(nowhere, advisories_on_error = bad), "advisories_on_error", label = deparse(bad))
  }
})

test_that("print() and summary() show the advisory count without safety wording", {
  x <- fakepkg_sbom(advisories = osv_zip())
  line <- "Advisories: 1 listed by OSV for these exact versions."
  expect_true(line %in% utils::capture.output(print(x)))
  expect_true(line %in% cli::ansi_strip(utils::capture.output(print(summary(x)))))
  expect_identical(summary(x)$advisories, list(status = "listed", n = 1L))

  y <- fakepkg_sbom()
  expect_true("Advisories: not requested." %in% utils::capture.output(print(y)))
  expect_true("Advisories: not requested." %in% cli::ansi_strip(utils::capture.output(print(summary(y)))))

  z <- expect_unavailable(fakepkg_sbom(advisories = TRUE, advisories_on_error = "continue"))
  expect_true("Advisories: unavailable (see sbom_issues())." %in% utils::capture.output(print(z)))
})

test_that("read_sbom(), sbom_diff() and sbom_tree() take an <sbom> with advisories", {
  x <- fakepkg_sbom(advisories = osv_zip())
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf)
  back <- read_sbom(tf)
  expect_identical(back$metadata$advisories$status, "listed")
  expect_identical(sbom_advisories(back)$id, "RSEC-9000-1")
  expect_s3_class(sbom_diff(back, x), "sbom_diff")
  expect_output(sbom_tree(x), "fakepkg")
})

test_that("the advisory metadata leaves a document's id unchanged", {
  x <- minimal_sbom()
  y <- x
  y$metadata$advisories <- advisories_metadata(requested = TRUE, source = "all.zip", status = "listed")
  expect_identical(sbom_uuid(y), sbom_uuid(x))
})

test_that("the advisories are part of a document's id, and an empty table leaves it as it was", {
  x <- minimal_sbom()
  # The id minimal_sbom() has had since before advisories existed, as the
  # version of sbom then wrote it: the tool's version is part of the content.
  x$metadata$tool_version <- "0.0.0.9000"
  expect_identical(sbom_uuid(x), "78317bc3-587c-5476-89a9-75cd7899944b")
  y <- x
  y$advisories <- empty_advisories()
  expect_identical(sbom_uuid(y), sbom_uuid(x))

  a <- widgetframe_sbom()
  b <- a
  b$advisories$id <- "RSEC-2026-1"
  c <- a
  c$advisories$affects[[1]]$fixed <- "0.3.2"
  d <- a
  d$advisories <- empty_advisories()
  ids <- vapply(list(a, b, c, d), sbom_uuid, "")
  expect_identical(anyDuplicated(ids), 0L)
  expect_false(identical(cdx_document(a)$serialNumber, cdx_document(b)$serialNumber))
})

test_that("sbom_advisories() tells a version with no fix from one whose fix is not known", {
  # RSEC-9000-1 is fixed for fakepkg 1.0.0 in 1.1.0; RSEC-9000-2 has no fix
  # for openpkg 2.0; listpkg 2.0.1 is only listed by RSEC-9000-4.
  x <- apply_advisories(
    with_components(cran_row("fakepkg", "1.0.0"), cran_row("openpkg", "2.0"), cran_row("listpkg", "2.0.1")),
    osv_zip(), "error"
  )
  adv <- sbom_advisories(x)
  expect_identical(adv$id, c("RSEC-9000-1", "RSEC-9000-2", "RSEC-9000-4"))
  expect_identical(adv$fixed, c("1.1.0", NA, NA))
  expect_identical(adv$no_fix, c(FALSE, TRUE, FALSE))

  # SPDX 2 carries both; CycloneDX and SPDX 3 carry neither.
  back <- function(ext) {
    tf <- withr::local_tempfile(fileext = ext, .local_envir = parent.frame())
    write_sbom(x, tf)
    sbom_advisories(read_sbom(tf))
  }
  spdx <- back(".spdx.json")
  expect_identical(spdx$fixed, c("1.1.0", NA, NA))
  expect_identical(spdx$no_fix, c(FALSE, TRUE, FALSE))
  for (ext in c(".cdx.json", ".spdx3.jsonld")) {
    got <- back(ext)
    expect_identical(got$fixed, rep(NA_character_, 3L), label = ext)
    expect_identical(got$no_fix, rep(NA, 3L), label = ext)
  }
})

test_that("new_sbom() checks the advisories table", {
  x <- minimal_sbom()
  expect_identical(x$advisories, empty_advisories())
  expect_identical(
    names(empty_advisories()),
    c("id", "summary", "published", "source_url", "upstream", "ratings", "affects")
  )
  expect_error(
    new_sbom(x$metadata, x$components, x$relationships, x$issues, empty_advisories()[, -1]),
    "id"
  )
})

test_that("no advisory sentence, message or doc states or implies that a package is safe", {
  local_osv_download()
  sha <- strrep("a1", 20)
  warned <- new.env()
  text <- c(
    advisory_text(fakepkg_sbom(advisories = osv_zip())),
    advisory_text(fakepkg_sbom()),
    advisory_text(fakepkg_sbom(advisories = TRUE)),
    advisory_text(expect_unavailable(
      fakepkg_sbom(advisories = test_path("fixtures", "osv", "bad-json.zip"), advisories_on_error = "continue"),
      warned
    )),
    warned$text,
    advisory_text(apply_advisories(
      with_components(
        cran_row("minpkg", "1.0", version_is = "minimum"), cran_row("shapkg", sha),
        cran_row("biocpkg", "1.0", ecosystem = "bioconductor"), cran_row("lastpkg", "1.1")
      ),
      TRUE, "error"
    ))
  )
  # The errors of the error mode and of the argument checks.
  nowhere <- file.path(withr::local_tempdir(), "nowhere")
  text <- c(
    text,
    condition_text(fakepkg_sbom(advisories = test_path("fixtures", "osv", "bad-json.zip"))),
    condition_text(fakepkg_sbom(advisories = test_path("fixtures", "osv", "evil-names.zip"))),
    condition_text(fakepkg_sbom(advisories = test_path("fixtures", "osv", "not-cran.zip"))),
    condition_text(fakepkg_sbom(advisories = test_path("fixtures", "osv", "no-package.zip"))),
    condition_text(osv_fetch(osv_source(file.path(nowhere, "all.zip")))),
    condition_text(sbom_package(nowhere, advisories = 5)),
    condition_text(sbom_package(nowhere, advisories = file.path(nowhere, "all.zip"))),
    condition_text(sbom_package(nowhere, advisories = withr::local_tempdir())),
    condition_text(sbom_package(nowhere, advisories_on_error = "x"))
  )
  local_mocked_bindings(osv_download = function(url, dest, ...) structure(FALSE, reason = "HTTP status 404"))
  text <- c(
    text,
    condition_text(fakepkg_sbom(advisories = TRUE)),
    advisory_text(expect_unavailable(fakepkg_sbom(advisories = TRUE, advisories_on_error = "continue"), warned)),
    warned$text
  )
  # Each kind of sentence was collected.
  for (expected in c(
    listed_note, no_data_note, bioc_note, file_note, "downloaded from", "sbom could not read",
    "no exact version", "could not all be compared", "could not be looked up", "built without advisories",
    "Advisories: 1 listed", "Advisories: not requested.", "Advisories: unavailable",
    "so this SBOM lists no advisories", "could not be read when this SBOM was built",
    "could not be downloaded from", "is damaged", "holds no CRAN records", "is not an OSV record",
    "does not exist", "is a folder",
    "must be `TRUE`", "advisories_on_error"
  )) {
    expect_true(any(grepl(expected, text, fixed = TRUE)), label = expected)
  }
  expect_identical(grep(safety_words, text, perl = TRUE, value = TRUE), character())

  # And the help topics this task wrote or changed.
  docs <- rd_text(c(
    "sbom", "sbom_package", "sbom_renv", "sbom_rsconnect", "sbom_nix", "sbom_shiny",
    "summary.sbom", "sbom_advisories"
  ))
  expect_true(all(grepl("advisories", docs, fixed = TRUE)))
  expect_identical(names(docs)[grepl(safety_words, docs, perl = TRUE)], character())
})
