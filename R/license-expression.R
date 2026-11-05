# The SPDX License List and SPDX license expressions (SPDX 2.3 Annex D; SPDX 3 uses the same grammar).

spdx_license_list <- function() {
  if (is.null(the$spdx_license_list)) {
    path <- system.file("extdata", "spdx-licenses.csv", package = "sbom")
    lst <- utils::read.csv(path, colClasses = c("character", "character", "logical"))
    the$spdx_license_list <- lst
    the$spdx_license_lower <- tolower(lst$id)
  }
  the$spdx_license_list
}

spdx_license_list_version <- function() {
  if (is.null(the$spdx_license_list_version)) {
    path <- system.file("extdata", "spdx-licenses.dcf", package = "sbom")
    the$spdx_license_list_version <- unname(read.dcf(path, fields = "Version")[1L, 1L])
  }
  the$spdx_license_list_version
}

# Checks license expressions against the SPDX grammar and the bundled License List.
#
# One row per element of `x`. `valid` says whether the expression parses; `problem` is a lower-case
# clause saying why not. Ids that are not on the list are syntactically fine and are listed in
# `unknown`, as are an exception id used as a license and a license id used after WITH. `licenses` and
# `exceptions` hold the known ids in the list's spelling (matched case-insensitively, `+` dropped, in
# order of appearance, listed once), `refs` every LicenseRef-, AdditionRef- and DocumentRef- reference,
# and `deprecated` the known ids that the list marks deprecated. `special` accepts NONE and NOASSERTION
# as a whole expression. No input makes this function throw.
license_expression_check <- function(x, special = TRUE) {
  x <- as.character(x)
  ux <- unique(x)
  parts <- lapply(ux, license_expression_parse, special = special)
  i <- match(x, ux)

  # Resolve every id of every expression against the list in one pass.
  lst <- spdx_license_list()
  lic_n <- vapply(parts, function(p) length(p$licenses), integer(1))
  exc_n <- vapply(parts, function(p) length(p$exceptions), integer(1))
  lic_all <- as.character(unlist(lapply(parts, `[[`, "licenses"), use.names = FALSE))
  exc_all <- as.character(unlist(lapply(parts, `[[`, "exceptions"), use.names = FALSE))
  lic_k <- match(tolower(lic_all), the$spdx_license_lower)
  exc_k <- match(tolower(exc_all), the$spdx_license_lower)
  lic_ok <- !is.na(lic_k) & lst$kind[lic_k] == "license"
  exc_ok <- !is.na(exc_k) & lst$kind[exc_k] == "exception"
  lic_group <- rep.int(seq_along(parts), lic_n)
  exc_group <- rep.int(seq_along(parts), exc_n)
  slice <- function(values, keep, group) {
    out <- rep(list(character()), length(parts))
    pieces <- split(values[keep], group[keep])
    out[as.integer(names(pieces))] <- pieces
    lapply(out, unique)
  }
  lic_known <- slice(lst$id[lic_k], lic_ok, lic_group)
  exc_known <- slice(lst$id[exc_k], exc_ok, exc_group)
  lic_unknown <- slice(lic_all, !lic_ok, lic_group)
  exc_unknown <- slice(exc_all, !exc_ok, exc_group)
  lic_dep <- slice(lst$id[lic_k], lic_ok & lst$deprecated[lic_k] %in% TRUE, lic_group)
  exc_dep <- slice(lst$id[exc_k], exc_ok & lst$deprecated[exc_k] %in% TRUE, exc_group)

  # The unknown ids keep their order: licenses first, then exceptions.
  unknown <- Map(function(a, b) unique(c(a, b)), lic_unknown, exc_unknown)
  deprecated <- Map(function(a, b) unique(c(a, b)), lic_dep, exc_dep)
  data.frame(
    expression = x,
    valid = vapply(parts, `[[`, logical(1), "valid")[i],
    problem = vapply(parts, `[[`, character(1), "problem")[i],
    licenses = I(unname(lic_known[i])),
    exceptions = I(unname(exc_known[i])),
    refs = I(unname(lapply(parts, `[[`, "refs")[i])),
    unknown = I(unname(unknown[i])),
    deprecated = I(unname(deprecated[i])),
    stringsAsFactors = FALSE
  )
}

license_expression_max_depth <- 100L

# Token kinds, as integers so that the parsing loop stays cheap.
lex <- c(open = 1L, close = 2L, and = 3L, or = 4L, with = 5L, special = 6L,
         license_ref = 7L, addition_ref = 8L, id = 9L, bad = 10L)

# Parses one expression with a state machine, not recursion, so nesting costs no stack. Returns the
# raw ids (not yet resolved against the list) in `licenses` and `exceptions`, and the references.
license_expression_parse <- function(expr, special) {
  fail <- function(problem) {
    list(valid = FALSE, problem = problem, licenses = character(), exceptions = character(),
         refs = character())
  }
  if (is.na(expr)) {
    return(fail("it is missing"))
  }
  if (!validUTF8(expr)) {
    return(fail("it is not valid UTF-8 text"))
  }
  Encoding(expr) <- "UTF-8"
  trimmed <- trimws(expr)
  if (!nzchar(trimmed)) {
    return(fail("it is empty"))
  }
  if (special && trimmed %in% c("NONE", "NOASSERTION")) {
    res <- fail(NA_character_)
    res$valid <- TRUE
    return(res)
  }

  tokens <- regmatches(trimmed, gregexpr("[()]|[^()[:space:]]+", trimmed))[[1]]
  n <- length(tokens)
  idstring <- "[A-Za-z0-9.-]+"
  kind <- rep(lex[["bad"]], n)
  kind[grepl(paste0("^[A-Za-z0-9.-]+[+]?$"), tokens)] <- lex[["id"]]
  kind[grepl("^(DocumentRef-|LicenseRef-|AdditionRef-)", tokens)] <- lex[["bad"]]
  kind[grepl(paste0("^(DocumentRef-", idstring, ":)?LicenseRef-", idstring, "$"), tokens)] <-
    lex[["license_ref"]]
  kind[grepl(paste0("^(DocumentRef-", idstring, ":)?AdditionRef-", idstring, "$"), tokens)] <-
    lex[["addition_ref"]]
  kind[tokens == "NONE" | tokens == "NOASSERTION"] <- lex[["special"]]
  kind[tokens == "AND"] <- lex[["and"]]
  kind[tokens == "OR"] <- lex[["or"]]
  kind[tokens == "WITH"] <- lex[["with"]]
  kind[tokens == "("] <- lex[["open"]]
  kind[tokens == ")"] <- lex[["close"]]

  licenses <- character(n)
  exceptions <- character(n)
  refs <- character(n)
  n_lic <- 0L
  n_exc <- 0L
  n_ref <- 0L
  depth <- 0L
  max_depth <- license_expression_max_depth
  want_operand <- TRUE
  problem <- NA_character_
  k <- 1L
  while (k <= n) {
    kd <- kind[[k]]
    tok <- tokens[[k]]
    if (want_operand) {
      if (kd == 1L) {
        depth <- depth + 1L
        if (depth > max_depth) {
          problem <- paste0("it nests parentheses more than ", max_depth, " deep")
          break
        }
      } else if (kd == 9L) {
        n_lic <- n_lic + 1L
        licenses[[n_lic]] <- sub("[+]$", "", tok)
        want_operand <- FALSE
        if (k < n && kind[[k + 1L]] == 5L) {
          if (k + 1L == n) {
            problem <- "it ends where an exception was expected after WITH"
            break
          }
          k <- k + 2L
          ekd <- kind[[k]]
          etok <- tokens[[k]]
          if (ekd == 9L && !endsWith(etok, "+")) {
            n_exc <- n_exc + 1L
            exceptions[[n_exc]] <- etok
          } else if (ekd == 9L) {
            problem <- paste0("it has a + after the exception ", quote_value(sub("[+]$", "", etok)))
            break
          } else if (ekd == 8L) {
            n_ref <- n_ref + 1L
            refs[[n_ref]] <- etok
          } else {
            problem <- license_expression_unexpected(ekd, etok, "an exception was expected after WITH")
            break
          }
        }
      } else if (kd == 7L) {
        n_ref <- n_ref + 1L
        refs[[n_ref]] <- tok
        want_operand <- FALSE
        if (k < n && kind[[k + 1L]] == 5L) {
          problem <- paste0("it uses WITH after the reference ", quote_value(tok), ", which is not a license id")
          break
        }
      } else if (kd == 8L) {
        problem <- paste0("it uses ", quote_value(tok), " as a license, but an AdditionRef is only allowed after WITH")
        break
      } else {
        problem <- license_expression_unexpected(kd, tok, "a license was expected", special)
        break
      }
    } else if (kd == 3L || kd == 4L) {
      want_operand <- TRUE
    } else if (kd == 2L) {
      if (depth == 0L) {
        problem <- "it has a closing parenthesis with no opening one"
        break
      }
      depth <- depth - 1L
    } else if (kd == 5L) {
      problem <- "it has WITH where it does not follow a single license"
      break
    } else {
      problem <- license_expression_unexpected(kd, tok, "an operator was expected", special)
      break
    }
    k <- k + 1L
  }
  if (is.na(problem)) {
    if (want_operand) {
      problem <- "it ends where a license was expected"
    } else if (depth > 0L) {
      problem <- "it has an unclosed parenthesis"
    }
  }
  if (!is.na(problem)) {
    return(fail(problem))
  }
  list(
    valid = TRUE,
    problem = NA_character_,
    licenses = licenses[seq_len(n_lic)],
    exceptions = exceptions[seq_len(n_exc)],
    refs = unique(refs[seq_len(n_ref)])
  )
}

# The problem clause for a token that cannot stand where it is. The token
# comes from a document, so it is quoted short, its control characters shown
# as spaces, and in plain double quotes, the same in every locale.
license_expression_unexpected <- function(kd, tok, wanted, special = TRUE) {
  tok <- quote_value(tok)
  if (kd == lex[["special"]]) {
    if (special) {
      return(paste0("it uses ", tok, ", which is only allowed as the whole expression"))
    }
    return(paste0("it uses ", tok, ", which is not a license"))
  }
  if (kd == lex[["bad"]]) {
    return(paste0("it has an invalid license identifier or reference, \"", tok, "\""))
  }
  paste0("it has \"", tok, "\" where ", wanted)
}
