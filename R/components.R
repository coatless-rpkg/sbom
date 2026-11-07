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
# given is NA, or a typed empty data frame for the list columns. Its
# dependencies are known (`deps_known`) unless it says otherwise.
component_row <- function(...) {
  given <- list(...)
  unknown <- setdiff(names(given), component_columns())
  if (length(unknown) > 0L) {
    cli::cli_abort("Unknown component column{?s}: {.val {unknown}}.")
  }
  row <- lapply(component_columns(), function(col) {
    if (col == "is_root") {
      isTRUE(given[[col]])
    } else if (col == "deps_known") {
      !isFALSE(given[[col]])
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

# Items for a sentence: "a", "a and b", "a, b and c".
and_list <- function(x) {
  n <- length(x)
  if (n <= 1L) {
    return(paste(x, collapse = ""))
  }
  paste(paste(x[-n], collapse = ", "), "and", x[[n]])
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

# A git remote's URL as a vcs reference: only a URL with a scheme other than
# file://, without credentials, query or fragment. An scp-style remote,
# user@host:path, becomes ssh://host/path. A local or relative path, or a
# file:// URL, would leak a machine path, so it gives NA.
remote_vcs_url <- function(url) {
  scp <- regmatches(url, regexec("^[^/@[:space:]]+@([^/:[:space:]]+):([^[:space:]]+)$", url))[[1]]
  if (!is_url(url) && length(scp) == 3L) {
    url <- paste0("ssh://", scp[2], "/", sub("^/+", "", scp[3]))
  }
  if (!is_url(url) || startsWith(tolower(url), "file://")) {
    return(NA_character_)
  }
  strip_url(url)
}

# The host of a GitHub Enterprise server named by RemoteHost, or NA for
# github.com. remotes records the API address, such as
# https://github.acme.com/api/v3, so the scheme and API path are dropped.
github_enterprise_host <- function(remote_host) {
  own_host(remote_host, c("api.github.com", "github.com"))
}

# The same for a GitLab server of one's own: NA for gitlab.com.
gitlab_own_host <- function(remote_host) {
  own_host(remote_host, "gitlab.com")
}

own_host <- function(remote_host, public) {
  if (is.na(remote_host)) {
    return(NA_character_)
  }
  host <- sub("^[A-Za-z][A-Za-z0-9+.-]*://", "", remote_host)
  host <- sub("/api(/v[0-9]+)?$", "", sub("/+$", "", host))
  if (!nzchar(host) || tolower(host) %in% public) {
    return(NA_character_)
  }
  host
}

# A Bioconductor release such as "3.12", or NA.
bioc_version <- function(x) {
  if (is.na(x) || !grepl("^[0-9]+\\.[0-9]+$", x)) NA_character_ else x
}

# Ecosystem, purl, supplier, homepage and source repository, by the first
# rule that matches. `purl_inferred` is TRUE when the purl assumes a CRAN
# package of that name because no repository URL was recorded.
#
# Besides DESCRIPTION fields, a record from a lockfile or manifest may carry
# `Source` ("Bioconductor", or "unknown" when it does not say where the
# package came from) and `Bioconductor.Version`, the Bioconductor release a
# lockfile names for all of its Bioconductor packages.
package_ecosystem <- function(desc) {
  f <- function(field) desc_field(desc, field)
  name <- f("Package")
  version <- f("Version")
  repository <- f("Repository")
  result <- function(ecosystem, purl, supplier_name = NA_character_,
                     supplier_url = NA_character_, homepage = NA_character_,
                     bioc_release = NA_character_, purl_inferred = FALSE,
                     vcs_url = supplier_url) {
    list(ecosystem = ecosystem, purl = purl, supplier_name = supplier_name,
      supplier_url = supplier_url, homepage = homepage, bioc_release = bioc_release,
      purl_inferred = purl_inferred, vcs_url = vcs_url)
  }
  git_url <- f("git_url")
  source <- tolower(f("Source"))
  remote_type <- tolower(f("RemoteType"))
  forge_url <- function(site) {
    user <- f("RemoteUsername")
    repo <- f("RemoteRepo")
    if (is.na(user) || is.na(repo)) NA_character_ else paste0(site, "/", user, "/", repo)
  }
  # A forge package's supplier is the account that owns its repository, a user
  # or an organization, with its page on the forge; without an owner on
  # record, the forge itself.
  forge_supplier <- function(site, forge) {
    owner <- f("RemoteUsername")
    if (is.na(owner)) {
      list(name = forge, url = NA_character_)
    } else {
      list(name = owner, url = paste0(site, "/", owner))
    }
  }

  if (identical(repository, "CRAN")) {
    return(result("cran", purl(name, version), "CRAN", "https://cran.r-project.org",
      paste0("https://cran.r-project.org/package=", name), vcs_url = NA_character_))
  }
  if ((!is.na(git_url) && startsWith(git_url, "https://git.bioconductor.org")) ||
    identical(source, "bioconductor")) {
    rel <- bioc_release(f("git_branch"))
    if (is.na(rel)) rel <- bioc_version(f("Bioconductor.Version"))
    base <- if (is.na(rel)) {
      "https://bioconductor.org"
    } else {
      paste0("https://bioconductor.org/packages/", rel, "/bioc")
    }
    homepage <- if (is.na(rel)) NA_character_ else paste0(base, "/html/", name, ".html")
    return(result("bioconductor", purl(name, version, repository_url = base),
      "Bioconductor", "https://bioconductor.org", homepage, rel, vcs_url = NA_character_))
  }
  if (identical(remote_type, "github") || identical(remote_type, "gitlab")) {
    host <- if (remote_type == "github") {
      github_enterprise_host(f("RemoteHost"))
    } else {
      gitlab_own_host(f("RemoteHost"))
    }
    public <- if (remote_type == "github") "github.com" else "gitlab.com"
    site <- paste0("https://", if (is.na(host)) public else host)
    url <- forge_url(site)
    id <- purl(f("RemoteRepo"), f("RemoteSha"), remote_type, f("RemoteUsername"),
      repository_url = if (is.na(host)) NULL else site)
    sup <- forge_supplier(site, if (!is.na(host)) host else if (remote_type == "github") "GitHub" else "GitLab")
    return(result(remote_type, id, sup$name, sup$url, url, vcs_url = url))
  }
  if (identical(remote_type, "bitbucket")) {
    url <- forge_url("https://bitbucket.org")
    id <- purl(f("RemoteRepo"), f("RemoteSha"), "bitbucket", f("RemoteUsername"))
    sup <- forge_supplier("https://bitbucket.org", "Bitbucket")
    return(result("bitbucket", id, sup$name, sup$url, url, vcs_url = url))
  }
  if (remote_type %in% c("git", "git2r", "xgit")) {
    return(result("git", NA_character_, vcs_url = remote_vcs_url(f("RemoteUrl"))))
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
      supplier, remote, purl_inferred = is.null(repo_url), vcs_url = NA_character_))
  }
  if (identical(source, "unknown")) {
    return(result("unknown", NA_character_))
  }
  result("local", NA_character_)
}

# Returns list(component = <1-row data.frame>, issues = <data.frame>).
# `source_input` names where the record came from. A record from renv.lock or
# manifest.json that lacks a license or maintainer says that the file does
# not record it, and, when `library_checked`, that no installed copy of that
# version was found either.
package_component <- function(desc, evidence, source_input, is_root = FALSE,
                              scope = "required", library_checked = FALSE) {
  name <- desc_field(desc, "Package")
  version <- desc_field(desc, "Version")
  eco <- package_ecosystem(desc)
  ref <- package_ref(eco, name)

  vcs_url <- if (eco$ecosystem %in% c("github", "gitlab", "bitbucket", "git")) {
    eco$vcs_url
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
    source_input = source_input, deps = deps,
    system_requirements = desc_field(desc, "SystemRequirements")
  )

  label <- pkg_label(name, version)
  recorded_in <- if (source_input %in% c("renv.lock", "manifest.json")) source_input
  unrecorded <- function(what) {
    paste0(
      recorded_in, " does not record the ", what, " of ", label,
      if (library_checked) {
        paste0(", and no installed copy", if (!is.na(version)) " of that version", " was found.")
      } else {
        "."
      }
    )
  }
  issues <- empty_issues()
  if (is.na(version)) {
    issues <- add_issue(issues, ref, "version", "version-missing",
      paste0(name, " declares no version."))
  }
  if (is.na(license)) {
    issues <- add_issue(issues, ref, "license", "license-missing",
      if (is.null(recorded_in)) paste0(label, " declares no license.") else unrecorded("license"))
  } else if (is.na(spdx)) {
    issues <- add_issue(issues, ref, "license", "license-no-spdx",
      paste0("The license of ", label, ", ", license_normalize(license),
        ", has no SPDX expression, so it is recorded as NOASSERTION."))
  }
  if (eco$ecosystem == "local") {
    issues <- add_issue(issues, ref, "supplier", "supplier-unknown",
      paste0(label, " was installed from a local source, so it has no supplier on record."))
  }
  if (eco$ecosystem == "git") {
    issues <- add_issue(issues, ref, "purl", "source-git",
      paste0(label, " was installed from a git repository, so it has no package URL."))
  }
  if (eco$ecosystem == "unknown") {
    issues <- add_issue(issues, ref, "supplier", "source-unknown",
      paste0(if (is.null(recorded_in)) "Its DESCRIPTION" else recorded_in,
        " does not record where ", label, " came from."))
  }
  if (isTRUE(eco$purl_inferred)) {
    issues <- add_issue(issues, ref, "purl", "purl-inferred",
      paste0(label, " came from ", eco$supplier_name, " without a recorded repository URL, ",
        "so its package URL assumes it is the CRAN package of that name."))
  }
  if (is.na(maintainer)) {
    issues <- add_issue(issues, ref, "maintainer", "maintainer-missing",
      if (is.null(recorded_in)) paste0(label, " names no maintainer.") else unrecorded("maintainer"))
  }
  list(component = component, issues = issues)
}

# The ref of package `name` from its package_ecosystem() `eco`: its package
# URL, or "<ecosystem>/<name>" when it has none.
package_ref <- function(eco, name) {
  if (is.na(eco$purl)) paste0(eco$ecosystem, "/", name) else eco$purl
}

# The R row, then one row per base package used. Sorted by ref, R first.
# When R's version is exact, each base package has that version and R's
# evidence, since it comes with R; otherwise it has no version.
r_components <- function(version, version_is, stated_spec, base_used, evidence = NULL) {
  have_version <- !is.na(version)
  exact <- have_version && identical(version_is, "exact")
  r_license <- "GPL-2 | GPL-3"
  description <- if (!have_version) {
    "R is listed without a version, since no minimum is stated."
  } else if (identical(version_is, "minimum")) {
    paste0("The lowest R version stated, ", stated_spec, ".")
  } else {
    NA_character_
  }
  r_evidence <- if (!have_version) {
    "unknown"
  } else if (!is.null(evidence) && exact) {
    evidence
  } else if (exact) {
    "observed"
  } else {
    "declared"
  }
  r <- component_row(
    ref = "R", name = "R", version = if (have_version) version else NA_character_,
    version_is = if (have_version) version_is else NA_character_,
    type = "platform", ecosystem = "r", scope = "required",
    license_as_written = r_license, license_spdx = license_spdx(r_license),
    license_comment = license_comment(r_license),
    homepage = "https://www.r-project.org", description = description,
    evidence = r_evidence, source_input = "r"
  )
  base_used <- sort(unique(base_used[!is.na(base_used)]), method = "radix")
  base <- lapply(base_used, function(pkg) {
    component_row(
      ref = paste0("R/", pkg), name = pkg,
      version = if (exact) version else NA_character_,
      version_is = if (exact) "exact" else NA_character_,
      type = "library", ecosystem = "base-r", scope = "required",
      parent_ref = "R", license_comment = "Part of R, under R's own license.",
      description = "Part of R. It comes with R and has no file of its own.",
      evidence = if (exact) r_evidence else "inferred", source_input = "r"
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
