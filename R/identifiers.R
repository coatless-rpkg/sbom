#' Package URLs and CRAN DOIs
#'
#' `purl()` builds a Package URL (purl) for an R package. `cran_doi()` builds
#' the DataCite DOI that CRAN assigns to each package.
#'
#' Unknown values give `NA_character_` for that element. A package name that
#' is `NA` or `""`, or a namespace that is `NA` or `""`, is unknown.
#' Other elements of the vector are unaffected.
#' A version that is `NA` or `""` is left out of the purl.
#'
#' @param name Package names, as a character vector.
#' @param version Package versions, as a character vector. `NA` or `""` omits
#'   the version.
#' @param source Where the package comes from: `"cran"`, `"github"`,
#'   `"gitlab"` or `"bitbucket"`.
#' @param namespace Owner of the source repository. Required when `source` is
#'   `"github"`, `"gitlab"` or `"bitbucket"`.
#' @param repository_url Optional repository URL, written unencoded as a
#'   `repository_url` qualifier. Use this for packages from repositories other
#'   than CRAN, such as Bioconductor, or from a GitHub Enterprise or GitLab
#'   server of one's own.
#' @param pkg Package names, as a character vector.
#'
#' @return A character vector. `purl()` recycles `name`, `version`,
#'   `namespace` and `repository_url` to a common length: each must have
#'   length 1 or the length of the longest, otherwise it is an error.
#' @export
#' @examples
#' purl("dplyr", "1.2.1")
#' purl("srcpkg", "abc123", source = "github", namespace = "example")
#' cran_doi("dplyr")
purl <- function(name, version = NA, source = "cran", namespace = NULL,
                 repository_url = NULL) {
  source <- match.arg(source, c("cran", "github", "gitlab", "bitbucket"))
  if (source != "cran" && length(namespace) == 0L) {
    cli::cli_abort("{.arg namespace} is required when {.arg source} is {.val {source}}.")
  }
  if (length(name) == 0L || length(version) == 0L) {
    return(character(0))
  }

  args <- list(name = name, version = version, namespace = namespace,
               repository_url = repository_url)
  n <- max(lengths(args))
  for (arg in names(args)) {
    len <- length(args[[arg]])
    if (len > 1L && len != n) {
      cli::cli_abort(
        "{.arg {arg}} must have length 1 or the same length as the longest argument."
      )
    }
  }
  name <- rep_len(name, n)
  version <- rep_len(version, n)

  if (source != "cran") {
    namespace <- rep_len(namespace, n)
    base <- paste0("pkg:", source, "/", namespace, "/", name)
    unknown <- is_unknown(name) | is_unknown(namespace)
  } else {
    base <- paste0("pkg:cran/", name)
    unknown <- is_unknown(name)
  }
  at <- ifelse(is_unknown(version), "", paste0("@", version))
  query <- if (length(repository_url) == 0L) {
    rep("", n)
  } else {
    repository_url <- rep_len(repository_url, n)
    ifelse(is.na(repository_url), "", paste0("?repository_url=", repository_url))
  }
  out <- paste0(base, at, query)
  out[unknown] <- NA_character_
  out
}

#' @rdname purl
#' @export
cran_doi <- function(pkg) {
  if (length(pkg) == 0L) {
    return(character(0))
  }
  out <- paste0("10.32614/CRAN.package.", pkg)
  out[is_unknown(pkg)] <- NA_character_
  out
}

# An identifier part is unknown when it is NA or the empty string.
is_unknown <- function(x) {
  is.na(x) | !nzchar(x)
}
