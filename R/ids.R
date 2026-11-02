# Reproducible identifiers: the same content always gives the same ids.

#' RFC 4122 version-5 UUID
#'
#' Length-1 in `name`: `name` must be a single string.
#' @param name A single string.
#' @param namespace A UUID string. Defaults to the URL namespace.
#' @return A single UUID string.
#' @noRd
uuid5 <- function(name, namespace = "6ba7b811-9dad-11d1-80b4-00c04fd430c8") {
  if (!is.character(name) || length(name) != 1L || is.na(name)) {
    cli::cli_abort("{.arg name} must be a single string.")
  }
  hex_ns <- gsub("-", "", namespace, fixed = TRUE)
  if (!is.character(namespace) || length(namespace) != 1L ||
        !grepl("^[0-9a-fA-F]{32}$", hex_ns) ||
        !grepl("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", namespace)) {
    cli::cli_abort("{.arg namespace} must be a UUID string, not {.val {namespace}}.")
  }
  ns_bytes <- as.raw(strtoi(substring(hex_ns, seq(1, 31, 2), seq(2, 32, 2)), 16L))
  h <- cli::hash_raw_sha1(c(ns_bytes, charToRaw(enc2utf8(name))))
  hex <- tolower(substr(h, 1, 32))
  variant <- sprintf(
    "%x", bitwOr(8L, bitwAnd(strtoi(substr(hex, 17, 17), 16L), 3L))
  )
  paste0(
    substr(hex, 1, 8), "-", substr(hex, 9, 12), "-",
    "5", substr(hex, 14, 16), "-",
    variant, substr(hex, 18, 20), "-",
    substr(hex, 21, 32)
  )
}

# UUID of the content of an sbom. Excludes the timestamp and `inputs`
# (machine-specific paths), so identical content gives an identical id.
sbom_uuid <- function(x) {
  comps <- x$components
  comps <- comps[order(comps$ref, method = "radix"), , drop = FALSE]
  rownames(comps) <- NULL
  meta <- x$metadata[setdiff(names(x$metadata), c("timestamp", "inputs"))]
  content <- list(
    components = comps,
    relationships = x$relationships,
    issues = x$issues,
    metadata = meta
  )
  json <- jsonlite::toJSON(
    content, auto_unbox = FALSE, null = "null", na = "null",
    digits = NA, POSIXt = "ISO8601", dataframe = "rows"
  )
  uuid5(enc2utf8(as.character(json)))
}

spdx_namespace <- function(x) {
  base <- getOption("sbom.namespace", "https://spdx.org/spdxdocs")
  root <- x$components[x$components$ref == x$metadata$root, , drop = FALSE][1, ]
  name <- utils::URLencode(root$name, reserved = TRUE)
  if (!is.na(root$version)) {
    name <- paste0(name, "-", utils::URLencode(root$version, reserved = TRUE))
  }
  paste0(base, "/", name, "-", sbom_uuid(x))
}

format_timestamp <- function(t) {
  format(as.POSIXct(t), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
}
