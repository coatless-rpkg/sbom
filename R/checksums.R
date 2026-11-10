# Opt-in checksums of source packages: the SHA-256 and MD5 of each R
# package's source tarball, from the repository metadata that pak keeps.

# Aborts, with errors named for `call`, unless `checksums` is TRUE or FALSE.
check_checksums_arg <- function(checksums, call = parent.frame()) {
  if (!isTRUE(checksums) && !isFALSE(checksums)) {
    cli::cli_abort(
      "{.arg checksums} must be {.code TRUE} or {.code FALSE}, not {.obj_type_friendly {checksums}}.",
      call = call
    )
  }
  invisible(checksums)
}

# The repository metadata that pak keeps, from pak::meta_list(): one row per
# package file in the repositories pak is set up for, with its `sha256` and
# `md5sum`. pak downloads the metadata when its copy is out of date. Tests
# replace this function, so that none reaches pak or the network.
repo_metadata <- function(call = parent.frame()) {
  meta_list <- pak_function("meta_list")
  if (is.null(meta_list)) {
    cli::cli_abort(
      "{.code checksums = TRUE} reads repository metadata with the {.pkg pak} package, which is not installed.",
      call = call
    )
  }
  tryCatch(
    in_session_tmpdir(suppressMessages(meta_list())),
    error = function(e) {
      cli::cli_abort(
        c("pak could not read the repository metadata, so no checksums were looked up.",
          "x" = conditionMessage(e)),
        call = call
      )
    }
  )
}

# `x` with the SHA-256 and MD5 of the source tarball of each R package with a
# CRAN or Bioconductor package URL and an exact version, from the repository
# metadata that pak reads (repo_metadata()), when `checksums` is TRUE. Each
# package found also gets its file name and download location, unless it
# already has one. The packages the metadata lacks at their versions, as an
# archived version is, are named in one `checksums-not-found` issue, and the
# notes and inputs say where the checksums came from.
apply_checksums <- function(x, checksums = FALSE, call = parent.frame()) {
  if (isFALSE(checksums)) {
    return(x)
  }
  meta <- repo_metadata(call = call)
  meta <- meta[meta$platform %in% "source" & !is.na(meta$sha256) & nzchar(trimws(meta$sha256)), ,
    drop = FALSE]
  comps <- x$components
  parsed <- purl_parse(comps$purl)
  eligible <- parsed$valid %in% TRUE & tolower(parsed$type) %in% c("cran", "bioconductor") &
    comps$version_is %in% "exact" & !is.na(comps$version) & !comps$is_root
  hit <- match(paste(comps$name, comps$version), paste(meta$package, meta$version))
  hit[!eligible] <- NA_integer_
  mirrors <- character()
  for (i in which(!is.na(hit))) {
    m <- meta[hit[[i]], , drop = FALSE]
    file <- basename(m$target)
    new <- data.frame(
      alg = c("SHA-256", "MD5"),
      content = trimws(c(m$sha256, if (is.null(m$md5sum)) NA_character_ else m$md5sum)),
      of = "source tarball", stringsAsFactors = FALSE
    )
    new <- new[!is.na(new$content) & nzchar(new$content), , drop = FALSE]
    all <- rbind(comps$hashes[[i]], new)
    comps$hashes[[i]] <- all[!duplicated(all[c("alg", "content")]), , drop = FALSE]
    rownames(comps$hashes[[i]]) <- NULL
    if (is.na(comps$package_file_name[[i]])) {
      comps$package_file_name[[i]] <- file
    }
    if (is.na(comps$download_location[[i]]) && !is.na(m$mirror)) {
      comps$download_location[[i]] <- paste0(sub("/+$", "", m$mirror), "/", m$target)
    }
    mirrors <- c(mirrors, m$mirror)
  }
  x$components <- comps

  missing <- which(eligible & is.na(hit))
  if (length(missing) > 0L) {
    one <- length(missing) == 1L
    x$issues <- add_issue(
      x$issues, x$metadata$root, "hashes", "checksums-not-found",
      paste0(
        "The repository metadata that pak read has no source package for ", length(missing),
        if (one) " package" else " packages", " at the recorded version (",
        capped_list(pkg_label(comps$name[missing], comps$version[missing])), "), so ",
        if (one) "it has" else "they have",
        " no checksum; the metadata lists only the versions each repository offers now."
      ),
      severity = "info"
    )
    rownames(x$issues) <- NULL
  }

  found <- sum(!is.na(hit))
  if (found > 0L) {
    notes <- as.character(x$metadata$notes)
    from_metadata <- "Checksums of source packages come from the repository metadata that pak read."
    notes[notes == checksum_note()] <- paste(
      from_metadata, "Any other checksum is of a file sbom read itself."
    )
    if (!any(startsWith(notes, from_metadata))) {
      notes <- c(notes, from_metadata)
    }
    notes[notes == download_note()] <- paste0(
      "Download locations of source packages come from the same repository metadata; ",
      "the others are not recorded."
    )
    x$metadata$notes <- notes
    mirrors <- unique(mirrors[!is.na(mirrors)])
    if (length(mirrors) > 0L) {
      inputs <- rbind(
        x$metadata$inputs,
        data.frame(kind = "checksums", path = mirrors, stringsAsFactors = FALSE)
      )
      x$metadata$inputs <- inputs[!duplicated(inputs), , drop = FALSE]
      rownames(x$metadata$inputs) <- NULL
    }
  }
  x
}
