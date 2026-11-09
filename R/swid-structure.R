# The structural rules of a SWID tag (ISO/IEC 19770-2:2015) that sbom can
# state without the ISO schema, which it does not bundle: ISO's notice grants
# use of the schema for implementing the standard, not clearly its
# redistribution. schema_validate() applies them unless the option
# sbom.swid_xsd names the ISO schema as ISO publishes it. They are no stricter
# than that schema, apart from the standard's own rule that a tag has a
# tagCreator, which the schema only documents.

swid_no_creator <- "No Entity element has the role tagCreator."

# Sentences for the attributes among `required` that `attrs` lacks, and for
# those among `tokens`, attributes of an NMTOKEN or NMTOKENS type, that it
# holds empty, on an element described as `element`.
swid_attr_problems <- function(attrs, element, required = character(), tokens = character()) {
  keys <- names(attrs)
  c(
    sprintf("The %s element has no %s attribute.", element, setdiff(required, keys)),
    sprintf(
      "The %s element has an empty %s attribute.", element,
      tokens[tokens %in% keys & !nzchar(attrs[tokens[tokens %in% keys]])]
    )
  )
}

# The roles of an Entity, whose role attribute is a list of NMTOKENs.
swid_roles <- function(attrs) {
  role <- if ("role" %in% names(attrs)) attrs[["role"]] else ""
  roles <- strsplit(role, "[ \t\r\n]+")[[1]]
  roles[nzchar(roles)]
}

# The Entity and Link children of a SoftwareIdentity element in the ISO
# namespace, as swid_model() reads them: list(kinds, attrs, creator), where
# `creator` says which are Entity elements with the role tagCreator.
swid_children <- function(root, ns) {
  kids <- xml_kids_in(root, ns, names(ns)[ns == swid_iso_ns])
  kinds <- names(kids)
  if (is.null(kinds)) kinds <- character()
  keep <- kinds %in% c("Entity", "Link")
  attrs <- lapply(kids[keep], swid_attrs, ns = ns, ext = character())
  kinds <- kinds[keep]
  creator <- kinds == "Entity" & vapply(attrs, function(a) "tagCreator" %in% swid_roles(a), logical(1))
  list(kinds = kinds, attrs = attrs, creator = creator)
}

# Whether `root` is a SoftwareIdentity element in the ISO namespace.
swid_is_root <- function(root) {
  xml2::xml_find_chr(root, "string(local-name(.))") == "SoftwareIdentity" &&
    xml2::xml_find_chr(root, "string(namespace-uri(.))") == swid_iso_ns
}

#' The structural findings of a SWID tag
#'
#' Applies the rules of ISO/IEC 19770-2:2015 that sbom states without the
#' ISO schema, no stricter than that schema:
#'
#' * the root is `SoftwareIdentity` in the 2015 namespace, with a `name` and
#'   a `tagId`;
#' * at least one `Entity` has a `role` that contains `tagCreator`, as the
#'   standard requires;
#' * every `Entity` has a `name` and a non-empty `role`;
#' * every `Link` has an `href` and a non-empty `rel`;
#' * `versionScheme`, when present, is a single token (an NMTOKEN);
#' * `tagVersion`, when present, is an integer.
#'
#' Elements and attributes are read as `swid_model()` reads them: only Entity
#' and Link elements in the ISO namespace count, and the values of a token
#' type (`role`, `rel`, `versionScheme`) are trimmed, as is `tagVersion`, an
#' `xs:integer`.
#'
#' @param doc An xml2 document, parsed with the options `NOBLANKS` and
#'   `NONET`.
#' @return A data frame with columns `location` and `message`, one row per
#'   broken rule, in document order. The location is XPath-like, such as
#'   `/SoftwareIdentity/Entity[2]` for the second Entity, or `""` when the
#'   root is not a SWID tag at all.
#' @noRd
swid_structure_findings <- function(doc) {
  root <- xml2::xml_root(doc)
  local <- xml2::xml_find_chr(root, "string(local-name(.))")
  if (local != "SoftwareIdentity") {
    return(swid_findings("", sprintf("The root element is <%s>, not <SoftwareIdentity>.", quote_value(local))))
  }
  if (!swid_is_root(root)) {
    return(swid_findings(
      "", "The root element <SoftwareIdentity> is not in the ISO/IEC 19770-2:2015 namespace."
    ))
  }
  ns <- xml_ns_map(root)
  tag <- swid_attrs(root, ns, character())
  messages <- swid_attr_problems(tag, "SoftwareIdentity", c("name", "tagId"), "versionScheme")
  scheme <- unname(tag["versionScheme"])
  if (!is.na(scheme) && grepl("[ \t\r\n]", scheme)) {
    messages <- c(messages, sprintf("The versionScheme %s is not a single token.", quote_value(scheme)))
  }
  tag_version <- unname(tag["tagVersion"])
  if (!is.na(tag_version)) {
    trimmed <- trimws(tag_version, whitespace = "[ \t\r\n]")
    messages <- c(messages, if (!nzchar(trimmed)) {
      "The SoftwareIdentity element has an empty tagVersion attribute."
    } else if (!grepl("^[+-]?[0-9]+$", trimmed)) {
      sprintf("The tagVersion %s is not an integer.", quote_value(tag_version))
    })
  }

  kids <- swid_children(root, ns)
  if (!any(kids$creator)) {
    messages <- c(messages, swid_no_creator)
  }
  # Each child's findings are gathered in a list and joined once, so that a
  # tag of many broken children takes linear time.
  found <- lapply(seq_along(kids$kinds), function(i) {
    if (kids$kinds[[i]] == "Entity") {
      swid_attr_problems(kids$attrs[[i]], "Entity", c("name", "role"), "role")
    } else {
      swid_attr_problems(kids$attrs[[i]], "Link", c("href", "rel"), "rel")
    }
  })
  index <- stats::ave(seq_along(kids$kinds), kids$kinds, FUN = seq_along)
  where <- sprintf("/SoftwareIdentity/%s[%d]", kids$kinds, index)
  swid_findings(
    c(rep("/SoftwareIdentity", length(messages)), rep(where, lengths(found))),
    c(messages, unlist(found))
  )
}

# The finding of a tag that names no tagCreator, a rule the standard states
# and its schema only documents; none when it names one, or when its root is
# not a SWID tag, which the schema reports.
swid_creator_findings <- function(doc) {
  root <- xml2::xml_root(doc)
  if (!swid_is_root(root) || any(swid_children(root, xml_ns_map(root))$creator)) {
    return(swid_findings(character(), character()))
  }
  swid_findings("/SoftwareIdentity", swid_no_creator)
}

# A findings table of `location` and `message`, both as text.
swid_findings <- function(location, message) {
  data.frame(location = as.character(location), message = as.character(message), stringsAsFactors = FALSE)
}
