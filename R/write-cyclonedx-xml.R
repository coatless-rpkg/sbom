# CycloneDX XML writer. Walks the list from `cdx_document()` in order, so the
# element sequence follows the XSD. The text is built as libxml2 formats a
# document (two spaces of indent a level, at most sixty), and each kind of
# element is written for all its items at once, the components of a large
# SBOM among them: an xml2 node, or a few function calls, for each element
# took minutes for a large SBOM. A function that writes items takes a list of
# them and returns their lines as a list, one character vector an item.

# The indent of an element at `level`: libxml2 indents by two spaces a level
# and stops at sixty.
xml_pad <- function(level) {
  strrep("  ", min(level, 30L))
}

# U+FFFE and U+FFFF in UTF-8: the bytes EF BF BE and EF BF BF.
xml_nonchar_pattern <- "\xef\xbf[\xbe\xbf]"

# Text and attribute values escaped as libxml2 2.14 writes them: &, < and >
# always; in an attribute also the double quote, tab, line feed and carriage
# return, which elsewhere only the carriage return needs; and a control
# character that XML 1.0 does not allow as the reference of U+FFFD. So are
# U+FFFE and U+FFFF, the other characters XML 1.0 does not allow, which
# libxml2 writes as they are, making a document no parser reads. The bytes
# are matched as they are, and each string keeps its encoding.
xml_escape <- function(x, attr = FALSE) {
  x <- enc2utf8(as.character(x))
  special <- if (attr) "[&<>\"\001-\037]" else "[&<>\r\001-\010\013\014\016-\037]"
  hit <- !is.na(x) & (grepl(special, x, useBytes = TRUE) | grepl(xml_nonchar_pattern, x, useBytes = TRUE))
  if (!any(hit)) {
    return(x)
  }
  y <- x[hit]
  enc <- Encoding(y)
  sub_all <- function(y, from, to) gsub(from, to, y, fixed = TRUE, useBytes = TRUE)
  y <- sub_all(y, "&", "&amp;")
  y <- sub_all(y, "<", "&lt;")
  y <- sub_all(y, ">", "&gt;")
  y <- sub_all(y, "\r", "&#13;")
  if (attr) {
    y <- sub_all(y, "\"", "&quot;")
    y <- sub_all(y, "\t", "&#9;")
    y <- sub_all(y, "\n", "&#10;")
  }
  y <- gsub("[\001-\010\013\014\016-\037]", "&#xFFFD;", y, useBytes = TRUE)
  y <- gsub(xml_nonchar_pattern, "&#xFFFD;", y, useBytes = TRUE)
  Encoding(y) <- enc
  x[hit] <- y
  x
}

# A value as xml2 gave it to an element or attribute: a string as it is, and
# anything else (NA, a number, a vector) as paste() writes it.
xml_value <- function(value) {
  value <- enc2utf8(as.character(value))
  if (length(value) == 1L && !is.na(value)) value else paste(list(value), collapse = "")
}

# xml_value() of each of a list of values, the strings among them at once.
xml_values <- function(values) {
  values <- unname(values)
  out <- character(length(values))
  one <- lengths(values) == 1L & vapply(values, is.character, NA)
  if (any(one)) {
    out[one] <- enc2utf8(as.character(unlist(values[one])))
  }
  rest <- !one | is.na(out)
  if (any(rest)) {
    out[rest] <- vapply(values[rest], xml_value, "")
  }
  out
}

# The lines of entries (a list, one vector an entry) gathered by the item
# each belongs to, `owner`, one of 1 to `n`: a list of `n` vectors, in order.
xml_group <- function(lines, owner, n) {
  if (n == 0L) {
    return(list())
  }
  owner <- factor(rep.int(owner, lengths(lines)), levels = seq_len(n))
  unname(split(as.character(unlist(lines, use.names = FALSE)), owner))
}

# The attributes of `n` items as text, ` name="value"` each, from `attrs`: a
# named list holding, for each name, a list of the items' values, NULL for
# an item that has none.
xml_attr_text <- function(attrs, n) {
  out <- character(n)
  for (a in names(attrs)) {
    v <- attrs[[a]]
    has <- !vapply(v, is.null, NA)
    if (any(has)) {
      out[has] <- paste0(out[has], " ", a, "=\"", xml_escape(xml_values(v[has]), attr = TRUE), "\"")
    }
  }
  out
}

# Elements `name`, one an item, with the attributes `attr_text` and the child
# lines `children` (a list, one vector an item); with no children, the tag
# closes at once.
xml_nodes <- function(level, name, children, attr_text = "") {
  n <- length(children)
  if (n == 0L) {
    return(list())
  }
  pad <- xml_pad(level)
  has <- lengths(children) > 0L
  open <- paste0(pad, "<", name, attr_text, ifelse(has, ">", "/>"))
  close <- paste0(pad, "</", name, ">")
  .mapply(function(o, ch, h) if (h) c(o, ch, close) else o, list(open, children, has), NULL)
}

# Elements `name` (one name, or one an item) with the text `values` (a
# list, one an item) and the attributes `attrs` (see xml_attr_text()); empty
# text closes the tag at once. One line an item.
xml_leaves <- function(level, name, values, attrs = list()) {
  n <- length(values)
  if (n == 0L) {
    return(character())
  }
  text <- xml_values(values)
  start <- paste0(xml_pad(level), "<", name, xml_attr_text(attrs, n))
  ifelse(nzchar(text), paste0(start, ">", xml_escape(text), "</", name, ">"), paste0(start, "/>"))
}

# Items as elements `tag` whose scalar entries are children, in order, except
# for `attrs`, which become XML attributes. Container entries are routed
# through `special`, a function of a level and a list of the items' values
# for that entry, which returns their lines as a list.
xml_items <- function(level, tag, items, attrs = character(), special = list()) {
  n <- length(items)
  if (n == 0L) {
    return(list())
  }
  keys_of <- lapply(items, names)
  named <- !vapply(keys_of, is.null, NA)
  owner <- rep.int(seq_len(n), lengths(keys_of))
  keys <- as.character(unlist(keys_of, use.names = FALSE))
  values <- do.call(c, lapply(items[named], as.list))
  # An entry repeated within an item is written once, from its first value.
  first <- !duplicated(paste(owner, keys, sep = "\r"))
  is_attr <- keys %in% attrs
  child <- first & !is_attr
  routed <- child & keys %in% names(special)
  leaf <- child & !routed
  lines <- vector("list", length(keys))
  if (any(leaf)) {
    lines[leaf] <- as.list(xml_leaves(level + 1L, keys[leaf], values[leaf]))
  }
  for (key in unique(keys[routed])) {
    at <- which(routed & keys == key)
    lines[at] <- special[[key]](level + 1L, values[at])
  }
  attr_values <- lapply(attrs, function(a) {
    v <- vector("list", n)
    at <- first & is_attr & keys == a
    v[owner[at]] <- values[at]
    v
  })
  names(attr_values) <- attrs
  children <- xml_group(lines[child], owner[child], n)
  xml_nodes(level, tag, children, xml_attr_text(attr_values, n))
}

# For each list of items in `lists`, a container `container` holding the
# lines `fn` writes for its items (a function of a level and a list of
# items, like xml_items()).
xml_each <- function(level, container, lists, fn) {
  lists <- lapply(lists, as.list)
  n <- length(lists)
  if (n == 0L) {
    return(list())
  }
  items <- do.call(c, lists)
  item_lines <- if (length(items) > 0L) fn(level + 1L, items) else list()
  xml_nodes(level, container, xml_group(item_lines, rep.int(seq_len(n), lengths(lists)), n))
}

# The XML lines of the organizations `orgs`, each an element `name` with a
# `name` child and any `url` children.
xml_orgs <- function(level, name, orgs) {
  n <- length(orgs)
  names <- xml_leaves(level + 1L, "name", lapply(orgs, function(org) org$name))
  urls <- lapply(orgs, function(org) as.list(org$url))
  url_lines <- xml_leaves(level + 1L, "url", do.call(c, urls))
  children <- xml_group(
    c(as.list(names), as.list(url_lines)), c(seq_len(n), rep.int(seq_len(n), lengths(urls))), n
  )
  xml_nodes(level, name, children)
}

# The XML lines of the license choices `items`, one list element each: an
# `expression` element, or a `license` element holding a `name`.
xml_licenses <- function(level, items) {
  expression <- vapply(items, function(item) !is.null(item$expression), NA)
  out <- vector("list", length(items))
  if (any(expression)) {
    out[expression] <- as.list(xml_leaves(
      level, "expression", lapply(items[expression], function(item) item$expression)
    ))
  }
  if (any(!expression)) {
    out[!expression] <- xml_nodes(level, "license", as.list(xml_leaves(
      level + 1L, "name", lapply(items[!expression], function(item) item$license$name)
    )))
  }
  out
}

# The XML lines of the external references `refs`: a `reference` element
# each, with a `type` attribute, a `url` child and any `comment` child.
xml_references <- function(level, refs) {
  n <- length(refs)
  urls <- xml_leaves(level + 1L, "url", lapply(refs, function(ref) ref$url))
  comments <- lapply(refs, function(ref) ref$comment)
  has <- !vapply(comments, is.null, NA)
  children <- xml_group(
    c(as.list(urls), as.list(xml_leaves(level + 1L, "comment", comments[has]))),
    c(seq_len(n), which(has)), n
  )
  xml_nodes(level, "reference", children, xml_attr_text(list(type = lapply(refs, function(ref) ref$type)), n))
}

# The XML lines of one `properties` container for each list in `lists`, with
# a `property` element per name and value.
xml_properties <- function(level, lists) {
  xml_each(level, "properties", lists, function(level, props) {
    as.list(xml_leaves(
      level, "property", lapply(props, function(prop) prop$value),
      list(name = lapply(props, function(prop) prop$name))
    ))
  })
}

xml_component_special <- list(
  supplier = function(level, v) xml_orgs(level, "supplier", v),
  hashes = function(level, v) {
    xml_each(level, "hashes", v, function(level, hs) {
      as.list(xml_leaves(
        level, "hash", lapply(hs, function(h) h$content), list(alg = lapply(hs, function(h) h$alg))
      ))
    })
  },
  licenses = function(level, v) xml_each(level, "licenses", v, xml_licenses),
  externalReferences = function(level, v) xml_each(level, "externalReferences", v, xml_references),
  properties = function(level, v) xml_properties(level, v),
  components = function(level, v) xml_each(level, "components", v, xml_components)
)

# The XML lines of the CycloneDX components `comps`, each an element `tag`
# at indent `level`.
xml_components <- function(level, comps, tag = "component") {
  xml_items(level, tag, comps, attrs = c("type", "bom-ref"), special = xml_component_special)
}

# The XML lines of the CycloneDX `metadata` object `meta`: timestamp,
# tools, authors and the root component, at indent `level`.
xml_metadata <- function(level, meta) {
  inner <- level + 1L
  tools <- if (!is.null(meta$tools$components)) {
    xml_nodes(inner, "tools", xml_each(inner + 1L, "components", list(meta$tools$components), xml_components))
  } else {
    xml_each(inner, "tools", list(meta$tools), function(level, tools) xml_items(level, "tool", tools))
  }
  children <- c(
    xml_leaves(inner, "timestamp", list(meta$timestamp)),
    unlist(tools),
    if (!is.null(meta$authors)) {
      unlist(xml_each(inner, "authors", list(meta$authors), function(level, a) xml_items(level, "author", a)))
    },
    unlist(xml_components(inner, list(meta$component))),
    if (!is.null(meta$manufacturer)) unlist(xml_items(inner, "manufacturer", list(meta$manufacturer))),
    if (!is.null(meta$properties)) unlist(xml_properties(inner, list(meta$properties)))
  )
  unlist(xml_nodes(level, "metadata", list(children)))
}

# The XML lines of the dependency list `deps`: one `dependency` element
# per entry, with a child per `dependsOn` target.
xml_dependencies <- function(level, deps) {
  n <- length(deps)
  targets <- lapply(deps, function(dep) as.list(dep$dependsOn))
  m <- sum(lengths(targets))
  inner <- xml_nodes(
    level + 1L, "dependency", rep(list(character()), m), xml_attr_text(list(ref = do.call(c, targets)), m)
  )
  children <- xml_group(inner, rep.int(seq_len(n), lengths(targets)), n)
  xml_nodes(level, "dependency", children, xml_attr_text(list(ref = lapply(deps, function(dep) dep$ref)), n))
}

# The XML lines of the vulnerabilities `vulns`, each a `vulnerability`
# element with its nested source, references, ratings and advisories.
xml_vulnerability_items <- function(level, vulns) {
  sources <- function(level, s) xml_items(level, "source", s)
  xml_items(level, "vulnerability", vulns, attrs = "bom-ref", special = list(
    source = sources,
    references = function(level, v) {
      xml_each(level, "references", v, function(level, refs) {
        xml_items(level, "reference", refs, special = list(source = sources))
      })
    },
    ratings = function(level, v) {
      xml_each(level, "ratings", v, function(level, r) xml_items(level, "rating", r))
    },
    advisories = function(level, v) {
      xml_each(level, "advisories", v, function(level, a) xml_items(level, "advisory", a))
    },
    affects = function(level, v) {
      xml_each(level, "affects", v, function(level, a) xml_items(level, "target", a))
    }
  ))
}

# The CycloneDX XML text of `x` at spec `version`, built from the same
# document list as the JSON writer, ending in a newline.
cdx_xml <- function(x, version = "1.6") {
  doc <- cdx_document(x, version)
  children <- c(
    xml_metadata(1L, doc$metadata),
    unlist(xml_each(1L, "components", list(doc$components), xml_components)),
    unlist(xml_each(1L, "dependencies", list(doc$dependencies), xml_dependencies)),
    if (!is.null(doc$vulnerabilities)) {
      unlist(xml_each(1L, "vulnerabilities", list(doc$vulnerabilities), xml_vulnerability_items))
    }
  )
  attrs <- list(
    xmlns = list(sprintf("http://cyclonedx.org/schema/bom/%s", version)),
    serialNumber = list(doc$serialNumber), version = list(as.character(doc$version))
  )
  root <- unlist(xml_nodes(0L, "bom", list(children), xml_attr_text(attrs, 1L)))
  out <- paste(c('<?xml version="1.0" encoding="UTF-8"?>', root), collapse = "\n")
  # The text is UTF-8, as xml2 marked it. As when xml2 wrote it, bytes that
  # are not UTF-8 stop the writer here, with R's error, rather than make a
  # document no XML parser reads.
  Encoding(out) <- "UTF-8"
  enc2utf8(paste0(sub("\n+$", "", out), "\n"))
}
