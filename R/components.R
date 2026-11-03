# Component rows built from DESCRIPTION fields and from R itself.

empty_hashes <- function() {
  data.frame(alg = character(), content = character(), of = character(),
    stringsAsFactors = FALSE)
}

empty_deps <- function() {
  data.frame(field = character(), spec = character(), stringsAsFactors = FALSE)
}

empty_asserted <- function() {
  data.frame(field = character(), value = character(), asserted_by = character(),
    reason = character(), stringsAsFactors = FALSE)
}

# One component row with exactly component_columns(), in order. Anything not
# given is NA, or a typed empty data frame for the list columns.
component_row <- function(...) {
  given <- list(...)
  unknown <- setdiff(names(given), component_columns())
  if (length(unknown) > 0L) {
    cli::cli_abort("Unknown component column{?s}: {.val {unknown}}.")
  }
  row <- lapply(component_columns(), function(col) {
    if (col == "is_root") {
      isTRUE(given[[col]])
    } else if (col %in% c("hashes", "deps", "asserted")) {
      list(switch(col, hashes = empty_hashes(), deps = empty_deps(),
        asserted = empty_asserted()))
    } else if (!is.null(given[[col]])) {
      as.character(given[[col]])
    } else {
      NA_character_
    }
  })
  names(row) <- component_columns()
  for (col in intersect(names(given), c("hashes", "deps", "asserted"))) {
    row[[col]] <- list(given[[col]])
  }
  out <- data.frame(row[!names(row) %in% c("hashes", "deps", "asserted")],
    stringsAsFactors = FALSE)
  for (col in c("hashes", "deps", "asserted")) {
    out[[col]] <- row[[col]]
  }
  out[component_columns()]
}

# "name version" for issue messages, or the name alone without a version.
pkg_label <- function(name, version) {
  ifelse(is.na(version), name, paste(name, version))
}

desc_field <- function(desc, field) {
  if (field %in% names(desc) && !is.na(desc[[field]]) && nzchar(trimws(desc[[field]]))) {
    trimws(desc[[field]])
  } else {
    NA_character_
  }
}

bioc_release <- function(git_branch) {
  if (is.na(git_branch) || !grepl("^RELEASE_[0-9]+_[0-9]+$", git_branch)) {
    return(NA_character_)
  }
  sub("^RELEASE_([0-9]+)_([0-9]+)$", "\\1.\\2", git_branch)
}

github_repo_url <- function(text) {
  m <- regmatches(text, regexpr("https://(github|gitlab)\\.com/[^/[:space:],;<>()#?]+/[^/[:space:],;<>()#?]+", text))
  if (length(m) == 0L) {
    return(NA_character_)
  }
  sub("\\.git$", "", m)
}

# The host of a GitHub Enterprise server named by RemoteHost, or NA for
# github.com. remotes records the API address, such as
# https://github.acme.com/api/v3, so the scheme and API path are dropped.
github_enterprise_host <- function(remote_host) {
  if (is.na(remote_host)) {
    return(NA_character_)
  }
  host <- sub("^[A-Za-z][A-Za-z0-9+.-]*://", "", remote_host)
  host <- sub("/api(/v3)?$", "", sub("/+$", "", host))
  if (!nzchar(host) || tolower(host) %in% c("api.github.com", "github.com")) {
    return(NA_character_)
  }
  host
}

# Ecosystem, purl, supplier and homepage, by the first rule that matches.
# `purl_inferred` is TRUE when the purl assumes a CRAN package of that name
# because no repository URL was recorded.
package_ecosystem <- function(desc) {
  f <- function(field) desc_field(desc, field)
  name <- f("Package")
  version <- f("Version")
  repository <- f("Repository")
  result <- function(ecosystem, purl, supplier_name = NA_character_,
                     supplier_url = NA_character_, homepage = NA_character_,
                     bioc_release = NA_character_, purl_inferred = FALSE) {
    list(ecosystem = ecosystem, purl = purl, supplier_name = supplier_name,
      supplier_url = supplier_url, homepage = homepage, bioc_release = bioc_release,
      purl_inferred = purl_inferred)
  }
  git_url <- f("git_url")

  if (identical(repository, "CRAN")) {
    return(result("cran", purl(name, version), "CRAN", "https://cran.r-project.org",
      paste0("https://cran.r-project.org/package=", name)))
  }
  if (!is.na(git_url) && startsWith(git_url, "https://git.bioconductor.org")) {
    rel <- bioc_release(f("git_branch"))
    base <- if (is.na(rel)) {
      "https://bioconductor.org"
    } else {
      paste0("https://bioconductor.org/packages/", rel, "/bioc")
    }
    homepage <- if (is.na(rel)) NA_character_ else paste0(base, "/html/", name, ".html")
    return(result("bioconductor", purl(name, version, repository_url = base),
      "Bioconductor", "https://bioconductor.org", homepage, rel))
  }
  if (identical(f("RemoteType"), "github")) {
    user <- f("RemoteUsername")
    repo <- f("RemoteRepo")
    host <- github_enterprise_host(f("RemoteHost"))
    site <- if (is.na(host)) "https://github.com" else paste0("https://", host)
    url <- if (is.na(user) || is.na(repo)) {
      NA_character_
    } else {
      paste0(site, "/", user, "/", repo)
    }
    id <- purl(repo, f("RemoteSha"), "github", user,
      repository_url = if (is.na(host)) NULL else site)
    return(result("github", id, if (is.na(host)) "GitHub" else host, url, url))
  }
  if (!is.na(repository)) {
    remote <- f("RemoteRepos")
    repo_url <- if (!is.na(remote)) {
      remote
    } else if (grepl("^http", repository)) {
      repository
    } else {
      NULL
    }
    supplier <- if (identical(repository, "RSPM")) "Posit Package Manager" else repository
    return(result("repository", purl(name, version, repository_url = repo_url),
      supplier, remote, purl_inferred = is.null(repo_url)))
  }
  result("local", NA_character_)
}

# Returns list(component = <1-row data.frame>, issues = <data.frame>).
package_component <- function(desc, evidence, source_input, is_root = FALSE,
                              scope = "required") {
  name <- desc_field(desc, "Package")
  version <- desc_field(desc, "Version")
  eco <- package_ecosystem(desc)
  ref <- if (is.na(eco$purl)) paste0(eco$ecosystem, "/", name) else eco$purl

  vcs_url <- if (eco$ecosystem == "github") {
    eco$supplier_url
  } else {
    url <- github_repo_url(desc_field(desc, "URL"))
    if (is.na(url)) url <- github_repo_url(desc_field(desc, "BugReports"))
    url
  }
  license <- desc_field(desc, "License")
  published <- desc_field(desc, "Date/Publication")
  maintainer <- unname(desc_maintainer(desc)[["name"]])

  deps <- do.call(rbind, c(list(empty_deps()), lapply(
    c("Depends", "Imports", "LinkingTo", "Suggests"),
    function(field) {
      p <- parse_dep_field(if (field %in% names(desc)) desc[[field]] else NA_character_, field)
      data.frame(field = p$field, spec = p$spec, stringsAsFactors = FALSE)
    }
  )))

  spdx <- if (is.na(license)) NA_character_ else license_spdx(license)
  # Only repositories name their files <name>_<version>.tar.gz.
  has_file_name <- eco$ecosystem %in% c("cran", "bioconductor", "repository") && !is.na(version)
  component <- component_row(
    ref = ref, name = name, version = version, version_is = "exact",
    type = "library", ecosystem = eco$ecosystem, is_root = is_root,
    scope = scope, purl = eco$purl, supplier_name = eco$supplier_name,
    supplier_url = eco$supplier_url, maintainer = maintainer,
    license_as_written = if (is.na(license)) NA_character_ else license_normalize(license),
    license_spdx = spdx,
    license_comment = if (is.na(license)) NA_character_ else license_comment(license),
    published = if (is.na(published)) NA_character_ else substr(published, 1L, 10L),
    homepage = eco$homepage, vcs_url = vcs_url,
    package_file_name = if (has_file_name) paste0(name, "_", version, ".tar.gz") else NA_character_,
    doi = if (eco$ecosystem == "cran") cran_doi(name) else NA_character_,
    bioc_release = eco$bioc_release, evidence = evidence,
    source_input = source_input, deps = deps
  )

  label <- pkg_label(name, version)
  issues <- empty_issues()
  if (is.na(version)) {
    issues <- add_issue(issues, ref, "version", "version-missing",
      paste0(name, " declares no version."))
  }
  if (is.na(license)) {
    issues <- add_issue(issues, ref, "license", "license-missing",
      paste0(label, " declares no licence."))
  } else if (is.na(spdx)) {
    issues <- add_issue(issues, ref, "license", "license-no-spdx",
      paste0("The licence of ", label, ", ", license_normalize(license),
        ", has no SPDX expression, so it is recorded as NOASSERTION."))
  }
  if (eco$ecosystem == "local") {
    issues <- add_issue(issues, ref, "supplier", "supplier-unknown",
      paste0(label, " was installed from a local source, so it has no supplier on record."))
  }
  if (isTRUE(eco$purl_inferred)) {
    issues <- add_issue(issues, ref, "purl", "purl-inferred",
      paste0(label, " came from ", eco$supplier_name, " without a recorded repository URL, ",
        "so its package URL assumes it is the CRAN package of that name."))
  }
  if (is.na(maintainer)) {
    issues <- add_issue(issues, ref, "maintainer", "maintainer-missing",
      paste0(label, " names no maintainer."))
  }
  list(component = component, issues = issues)
}

# The R row, then one row per base package used. Sorted by ref, R first.
r_components <- function(version, version_is, stated_spec, base_used) {
  have_version <- !is.na(version)
  r_license <- "GPL-2 | GPL-3"
  description <- if (!have_version) {
    "R is listed without a version, since no minimum is stated."
  } else if (identical(version_is, "minimum")) {
    paste0("The lowest R version stated, ", stated_spec, ".")
  } else {
    NA_character_
  }
  r <- component_row(
    ref = "R", name = "R", version = if (have_version) version else NA_character_,
    version_is = if (have_version) version_is else NA_character_,
    type = "platform", ecosystem = "r", scope = "required",
    license_as_written = r_license, license_spdx = license_spdx(r_license),
    license_comment = license_comment(r_license),
    homepage = "https://www.r-project.org", description = description,
    evidence = if (!have_version) "unknown" else if (version_is == "exact") "observed" else "declared",
    source_input = "r"
  )
  base_used <- sort(unique(base_used[!is.na(base_used)]), method = "radix")
  base <- lapply(base_used, function(pkg) {
    component_row(
      ref = paste0("R/", pkg), name = pkg, version_is = NA_character_,
      type = "library", ecosystem = "base-r", scope = "required",
      parent_ref = "R", license_comment = "Part of R, under R's own licence.",
      description = "Part of R. It comes with R and has no file of its own.",
      evidence = "inferred", source_input = "r"
    )
  })
  out <- do.call(rbind, c(list(r), base))
  rownames(out) <- NULL
  out
}

unknown_component <- function(name) {
  component_row(
    ref = paste0("unknown/", name), name = name, type = "library",
    ecosystem = "unknown", scope = "required", evidence = "unknown"
  )
}
