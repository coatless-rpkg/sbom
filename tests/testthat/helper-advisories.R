# What the advisory tests share: R Observatory's notes, and SBOMs with
# advisories built from the synthetic OSV fixtures.

no_data_note <- "No advisory data was on hand for this file, so it lists no advisories."
listed_note <- "Advisories are those OSV lists for these exact versions."
swid_note <- "A SWID tag has no place for advisories, so this tag lists none; the other formats list them."
cvss_vector <- "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

# The words that would state or imply that a package is safe (spec §9a).
safety_words <- "(?i)\\b(safe|unaffected|secure|approved|clean|no known|no vulnerabilit)"

# An upstream record as osv_lookup() returns it: parsed JSON with one CVSS 3
# severity.
rated_record <- function(id) {
  json_parse_strict(sprintf('{"id": "%s", "severity": [{"type": "CVSS_V3", "score": "%s"}]}', id, cvss_vector))
}

# sbom_package() of a package that imports fakepkg 1.0.0 and openpkg 2.0,
# from a fake library, with `advisories`.
two_package_sbom <- function(advisories) {
  dir <- withr::local_tempdir()
  pkg <- file.path(dir, "rootpkg")
  dir.create(pkg)
  write_text(
    "Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: fakepkg, openpkg\n",
    file.path(pkg, "DESCRIPTION")
  )
  lib <- write_fake_lib(file.path(dir, "lib"), list(
    fakepkg = c(Version = "1.0.0", Repository = "CRAN", License = "MIT", Maintainer = "A B <a@example.org>"),
    openpkg = c(Version = "2.0", Repository = "CRAN", License = "MIT", Maintainer = "C D <c@example.org>")
  ))
  sbom_package(
    pkg, lib = lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
    advisories = advisories
  )
}

# That SBOM, built with OSV's advisories from the fixture zip as if it had
# been downloaded, and with every upstream record rated 8.8. RSEC-9000-1
# affects fakepkg, fixed in 1.1.0, with CVE-2099-0001 and a source URL;
# RSEC-9000-2 affects openpkg, with no fix, no upstream record and no source
# URL.
two_advisory_sbom <- function() {
  zip <- test_path("fixtures", "osv", "all.zip")
  local_mocked_bindings(
    osv_download = function(url, dest, ...) file.copy(zip, dest, overwrite = TRUE),
    osv_lookup = function(id, ...) rated_record(id)
  )
  two_package_sbom(advisories = TRUE)
}

# minimal_sbom() with widgetframe 0.3.1 and R Observatory's RSEC-2026-0 on it,
# as OSV's export and the CVE record give it.
widgetframe_sbom <- function() {
  x <- minimal_sbom()
  ref <- "pkg:cran/widgetframe@0.3.1"
  x$components <- rbind(x$components, component_row(
    ref = ref, name = "widgetframe", version = "0.3.1", version_is = "exact",
    type = "library", ecosystem = "cran", purl = ref
  ))
  adv <- data.frame(
    id = "RSEC-2026-0", summary = "Cross-site Request Forgery (CSRF) vulnerability",
    published = "2026-02-18",
    source_url = "https://github.com/RConsortium/r-advisory-database/blob/main/vulns/widgetframe/RSEC-2026-0.yaml",
    stringsAsFactors = FALSE
  )
  adv$upstream <- list("CVE-2018-1000086")
  adv$ratings <- list(upstream_ratings("CVE-2018-1000086", rated_record("CVE-2018-1000086")))
  adv$affects <- list(data.frame(
    ref = ref, version = "0.3.1", fixed = NA_character_, no_fix = TRUE, stringsAsFactors = FALSE
  ))
  x$advisories <- adv
  x$metadata$advisories$status <- "listed"
  x$metadata$notes <- listed_note
  x
}

# The text of sbom's help topics, read from the man folder of the source
# package when the tests run from it, otherwise from the installed package.
rd_text <- function(topics) {
  root <- test_path("..", "..")
  db <- if (dir.exists(file.path(root, "man"))) tools::Rd_db(dir = root) else tools::Rd_db("sbom")
  names(db) <- sub("[.]Rd$", "", basename(names(db)))
  vapply(topics, function(topic) paste(as.character(db[[topic]]), collapse = ""), "")
}
