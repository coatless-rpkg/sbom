# The values read_sbom() takes from the elements of each format: fields,
# refs, ecosystems, licenses and relationships.

# A data frame of the columns `cols`, list columns included, built without
# data.frame()'s per-column work.
read_frame <- function(cols) {
  structure(cols, class = "data.frame", row.names = c(NA_integer_, -length(cols[[1L]])))
}

# The first value of `value` for each of `n` owners, among the items `keep`;
# NA for an owner with none.
read_first <- function(value, owner, n, keep) {
  out <- rep(NA_character_, n)
  keep <- keep & !is.na(value)
  hit <- owner[keep]
  first <- !duplicated(hit)
  out[hit[first]] <- value[keep][first]
  out
}

# The kinds of value that are not kept, as the read-values-dropped issue
# names them, in this order and separated by semicolons, since each but local
# paths ends in a clause that an "and" would run on into the next.
read_dropped_kinds <- c(
  iri = "URLs that are not valid IRI references", path = "local paths",
  hash = "checksums of algorithms or lengths sbom does not write",
  doi = "DOIs that cannot form a valid URL", cpe = "CPE identifiers"
)

# A file: URL or a local path: absolute, from the home folder, relative to the
# current folder or its parent, or on a Windows drive.
read_path_pattern <- "^(file:|/|\\\\|~|\\.\\.?([/\\\\]|$)|[A-Za-z]:[/\\\\])"

# URLs as sbom keeps its own (remote_vcs_url()): without credentials, query or
# fragment (strip_url()). A file: URL or a local path would leak a machine
# path, and a value that cannot be an IRI reference cannot be written where a
# format needs one, so those are dropped. Returns list(value, dropped), with
# the kind of each value dropped.
read_urls <- function(x) {
  x <- strip_url(tables_present(x))
  path <- !is.na(x) & grepl(read_path_pattern, x, ignore.case = TRUE)
  bad <- !is.na(x) & !path
  bad[bad] <- iri_reference_bad(x[bad])
  x[path | bad] <- NA_character_
  dropped <- c(rep(read_dropped_kinds[["path"]], sum(path)), rep(read_dropped_kinds[["iri"]], sum(bad)))
  list(value = x, dropped = dropped)
}

# Purls as read_sbom() keeps them, as it keeps URLs (read_urls()): a
# qualifier whose value is a URL, holding "://", loses its credentials, query
# and fragment (strip_url()), and a qualifier whose value is a file: URL or a
# local path is dropped. Values are compared percent-decoded, and a value
# that changes is written again with %, &, #, ? and spaces encoded. Each
# distinct purl is cleaned once. Returns list(value, dropped), with the kind
# of each qualifier dropped.
read_purls <- function(x) {
  has <- !is.na(x) & grepl("?", x, fixed = TRUE)
  if (!any(has)) {
    return(list(value = x, dropped = character()))
  }
  distinct <- unique(x[has])
  cleaned <- lapply(distinct, read_purl_qualifiers)
  at <- match(x[has], distinct)
  x[has] <- vapply(cleaned, `[[`, character(1), "value")[at]
  n <- vapply(cleaned, `[[`, integer(1), "dropped")[at]
  list(value = x, dropped = rep(read_dropped_kinds[["path"]], sum(n)))
}

# One purl with a `?`, cleaned as read_purls() says: list(value, dropped),
# the number of qualifiers dropped.
read_purl_qualifiers <- function(purl) {
  head <- sub("\\?.*$", "", purl)
  rest <- substring(purl, nchar(head) + 2L)
  subpath <- if (grepl("#", rest, fixed = TRUE)) sub("^[^#]*", "", rest) else ""
  qualifiers <- sub("#.*$", "", rest)
  pairs <- strsplit(qualifiers, "&", fixed = TRUE)[[1]]
  value <- sub("^[^=]*=", "", pairs)
  key <- substr(pairs, 1L, nchar(pairs) - nchar(value))
  valued <- grepl("=", pairs, fixed = TRUE)
  decoded <- value
  ok <- valued & !grepl("%(?![0-9A-Fa-f]{2})", value, perl = TRUE)
  decoded[ok] <- pct_decode(value[ok])
  decoded[!validUTF8(decoded)] <- value[!validUTF8(decoded)]
  path <- valued & grepl(read_path_pattern, decoded, ignore.case = TRUE)
  url <- valued & !path & grepl("://", decoded, fixed = TRUE)
  stripped <- strip_url(decoded)
  changed <- url & stripped != decoded
  pairs[changed] <- paste0(key[changed], read_purl_encode(stripped[changed]))
  pairs <- pairs[!path]
  value <- paste0(head, if (length(pairs) > 0L) paste0("?", paste(pairs, collapse = "&")), subpath)
  list(value = value, dropped = sum(path))
}

# Percent-encodes the characters a purl qualifier's value cannot hold as
# they are.
read_purl_encode <- function(x) {
  for (ch in c("%", "&", "#", "?", " ")) {
    x <- gsub(ch, sprintf("%%%02X", utf8ToInt(ch)), x, fixed = TRUE)
  }
  x
}

# DOIs, which the writers also give as https://doi.org/<doi>: one that cannot
# be part of an IRI reference is dropped. Returns list(value, dropped).
read_dois <- function(x) {
  x <- tables_present(x)
  bad <- !is.na(x)
  bad[bad] <- iri_reference_bad(x[bad])
  x[bad] <- NA_character_
  list(value = x, dropped = rep(read_dropped_kinds[["doi"]], sum(bad)))
}

# The date part, YYYY-MM-DD, of a date or timestamp; NA for anything else.
read_date <- function(x) {
  x <- tables_present(x)
  ifelse(grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}", x), substr(x, 1L, 10L), NA_character_)
}

# NONE and NOASSERTION are SPDX's words for no value.
read_spdx_value <- function(x) {
  x <- tables_present(x)
  x[x %in% c("NONE", "NOASSERTION")] <- NA_character_
  x
}

# One checksum table per owner, of the checksums whose algorithm every format
# takes (`alg` in CycloneDX's spelling) and whose value has that algorithm's
# number of hex digits. Returns list(value, dropped): a checksum with an
# algorithm and a value that is not kept is dropped.
read_hashes <- function(alg, content, owner, n) {
  out <- rep(list(empty_hashes()), n)
  alg <- unname(alg)
  digits <- unname(read_hash_digits[alg])
  ok <- !is.na(digits) & !is.na(content) & nchar(content) == digits & grepl("^[0-9A-Fa-f]+$", content)
  groups <- split(which(ok), owner[ok])
  out[as.integer(names(groups))] <- lapply(groups, function(i) {
    structure(
      list(alg = alg[i], content = content[i], of = rep(NA_character_, length(i))),
      class = "data.frame", row.names = c(NA_integer_, -length(i))
    )
  })
  stated <- !is.na(tables_present(alg)) & !is.na(tables_present(content))
  list(value = out, dropped = rep(read_dropped_kinds[["hash"]], sum(stated & !ok)))
}

# SPDX's primary purpose as a type. SPDX 2 spells it APPLICATION, SPDX 3
# application; only SPDX 3 has platform.
read_purpose_type <- function(purpose) {
  ifelse(purpose %in% c("APPLICATION", "application"), "application",
    ifelse(purpose %in% c("FILE", "file"), "file", ifelse(purpose %in% "platform", "platform", "library"))
  )
}

# Each returns, for the components `el`, the values the tables do not carry:
# supplier_url, maintainer, license_comment, written (the license as written,
# when the format states it apart from the licenses), homepage, vcs_url,
# download_location, doi, description, published, package_file_name,
# system_requirements, bioc_release, evidence and version_is (as stated),
# hashes, type, optional (whether the element itself is marked optional), and
# dropped (the kind of each value not kept).
read_values <- function(n, ...) {
  none <- rep(NA_character_, n)
  given <- list(...)
  keys <- c(
    "supplier_url", "maintainer", "license_comment", "written", "homepage", "vcs_url",
    "download_location", "doi", "description", "published", "package_file_name",
    "system_requirements", "bioc_release", "evidence", "version_is"
  )
  out <- lapply(stats::setNames(keys, keys), function(key) {
    if (is.null(given[[key]])) none else given[[key]]
  })
  out$hashes <- if (is.null(given$hashes)) rep(list(empty_hashes()), n) else given$hashes
  out$type <- given$type
  out$optional <- if (is.null(given$optional)) rep(FALSE, n) else given$optional
  out$dropped <- if (is.null(given$dropped)) character() else given$dropped
  out
}

# The first URL of a CycloneDX organizational entity.
read_cdx_party_url <- function(party) {
  urls <- json_items(json_member(party, "url"))
  if (length(urls) > 0L) json_string(urls[[1L]]) else NA_character_
}

# The component fields of the CycloneDX elements `el`, read from their raw JSON
# and the document `doc`, as read_values() builds them.
read_cdx_fields <- function(el, doc) {
  raw <- el$raw
  n <- length(raw)
  meta <- json_member(doc, "metadata")
  props <- json_flatten(raw, "properties")
  prop_name <- json_strings(props$items, "name")
  prop_value <- tables_present(json_strings(props$items, "value"))
  prop <- function(key) read_first(prop_value, props$owner, n, prop_name %in% key)
  refs <- json_flatten(raw, "externalReferences")
  ref_type <- json_strings(refs$items, "type")
  read_types <- c(homepage = "website", vcs_url = "vcs", download_location = "distribution")
  ref_url <- read_urls(ifelse(ref_type %in% read_types, json_strings(refs$items, "url"), NA_character_))
  external <- function(type) read_first(ref_url$value, refs$owner, n, ref_type %in% type)
  doi <- read_dois(prop("sbom:doi"))
  hashes <- json_flatten(raw, "hashes")
  hashes <- read_hashes(
    json_strings(hashes$items, "alg"), json_strings(hashes$items, "content"), hashes$owner, n
  )

  # The root takes the metadata's supplier and manufacturer when it names
  # neither itself, as the tables' supplier does.
  supplier_url <- vapply(raw, function(x) read_cdx_party_url(json_member(x, "supplier")), character(1))
  own <- !is.na(tables_present(json_strings(raw, c("supplier", "name"))))
  for_root <- el$is_root & !own
  supplier_url[for_root] <- read_cdx_party_url(json_member(meta, "supplier"))
  supplier_url <- read_urls(supplier_url)
  maintainer <- tables_coalesce(tables_present(json_strings(raw, "publisher")), prop("sbom:maintainer"))
  manufacture <- tables_present(json_string(json_member(json_member(meta, "manufacture"), "name")))
  maintainer[el$is_root] <- tables_coalesce(maintainer[el$is_root], manufacture)

  read_values(n,
    supplier_url = supplier_url$value, maintainer = maintainer,
    written = prop("sbom:license-as-written"), homepage = external("website"),
    vcs_url = external("vcs"), download_location = external("distribution"),
    doi = doi$value, description = tables_present(json_strings(raw, "description")),
    published = prop("sbom:published"), system_requirements = prop("sbom:system-requirements"),
    bioc_release = prop("sbom:bioconductor-release"), evidence = prop("sbom:evidence"),
    version_is = prop("sbom:version-is"), hashes = hashes$value,
    type = ifelse(el$type %in% c("application", "library", "platform", "file"), el$type, "library"),
    optional = el$scope %in% c("optional", "excluded"),
    dropped = c(supplier_url$dropped, ref_url$dropped, doi$dropped, hashes$dropped)
  )
}

# The component fields of the SPDX 2 elements `el`, read from their raw JSON, as
# read_values() builds them.
read_spdx2_fields <- function(el) {
  raw <- el$raw
  n <- length(raw)
  originator <- tables_present(json_strings(raw, "originator"))
  person <- !is.na(originator) & grepl("^Person:", originator)
  refs <- json_flatten(raw, "externalRefs")
  other <- json_strings(refs$items, "referenceCategory") %in% "OTHER"
  ref_type <- json_strings(refs$items, "referenceType")
  locator <- tables_present(json_strings(refs$items, "referenceLocator"))
  vcs <- read_urls(ifelse(other & ref_type %in% "vcs", locator, NA_character_))
  doi <- read_dois(ifelse(other & ref_type %in% "doi", locator, NA_character_))
  homepage <- read_urls(read_spdx_value(json_strings(raw, "homepage")))
  download <- read_urls(read_spdx_value(json_strings(raw, "downloadLocation")))
  checksums <- json_flatten(raw, "checksums")
  alg <- json_strings(checksums$items, "algorithm")
  # The writer's inverse: SHA256 is SHA-256.
  alg <- ifelse(grepl("^SHA(1|256|384|512)$", alg), sub("^SHA", "SHA-", alg), alg)
  hashes <- read_hashes(alg, json_strings(checksums$items, "checksumValue"), checksums$owner, n)

  read_values(n,
    maintainer = ifelse(person, tables_present(sub("^Person:[ \t\r\n]*", "", originator)), NA_character_),
    license_comment = tables_present(json_strings(raw, "licenseComments")),
    homepage = homepage$value,
    vcs_url = read_first(vcs$value, refs$owner, n, rep(TRUE, length(vcs$value))),
    download_location = download$value,
    doi = read_first(doi$value, refs$owner, n, rep(TRUE, length(doi$value))),
    description = tables_coalesce(
      tables_present(json_strings(raw, "description")),
      tables_present(json_strings(raw, "summary"))
    ),
    published = read_date(json_strings(raw, "releaseDate")),
    package_file_name = tables_present(json_strings(raw, "packageFileName")),
    hashes = hashes$value, type = read_purpose_type(el$type),
    dropped = c(homepage$dropped, vcs$dropped, download$dropped, doi$dropped, hashes$dropped)
  )
}

# `ix` is the graph's index, tables_spdx3_index().
read_spdx3_fields <- function(el, ix) {
  raw <- el$raw
  n <- length(raw)
  originators <- json_flatten(raw, "originatedBy")
  agents <- tables_spdx3_agents(originators$items, ix)
  refs <- json_flatten(raw, "externalRef")
  locator <- vapply(refs$items, function(x) {
    locators <- json_items(json_member(x, "locator"))
    if (length(locators) > 0L) json_string(locators[[1L]]) else NA_character_
  }, character(1))
  vcs <- read_urls(ifelse(json_strings(refs$items, "externalRefType") %in% "vcs", locator, NA_character_))
  ids <- json_flatten(raw, "externalIdentifier")
  doi <- read_dois(ifelse(
    json_strings(ids$items, "comment") %in% "DOI", json_strings(ids$items, "identifier"), NA_character_
  ))
  homepage <- read_urls(json_strings(raw, "software_homePage"))
  download <- read_urls(json_strings(raw, "software_downloadLocation"))
  hashes <- json_flatten(raw, "verifiedUsing")
  algorithm <- json_strings(hashes$items, "algorithm")
  # The writer's inverse; any other algorithm is kept as written, to be
  # counted as dropped.
  alg <- unname(read_spdx3_hashes[algorithm])
  alg[is.na(alg)] <- algorithm[is.na(alg)]
  hashes <- read_hashes(alg, json_strings(hashes$items, "hashValue"), hashes$owner, n)

  read_values(n,
    maintainer = read_first(agents$name, originators$owner, n, agents$type %in% "Person"),
    homepage = homepage$value,
    vcs_url = read_first(vcs$value, refs$owner, n, rep(TRUE, length(vcs$value))),
    download_location = download$value,
    doi = read_first(doi$value, ids$owner, n, rep(TRUE, length(doi$value))),
    description = tables_coalesce(
      tables_present(json_strings(raw, "description")),
      tables_present(json_strings(raw, "summary"))
    ),
    published = read_date(json_strings(raw, "releaseTime")),
    hashes = hashes$value, type = read_purpose_type(el$type),
    dropped = c(homepage$dropped, vcs$dropped, download$dropped, doi$dropped, hashes$dropped)
  )
}

# `ent` is what tables_swid_entities() gives.
read_swid_fields <- function(el, doc, ent) {
  n <- nrow(el)
  root <- el$location == "/tag"
  links <- json_items(json_member(doc, "links"))
  meta <- json_items(json_member(doc, "meta"))
  entity_names <- ent$name
  # The first entity with the role and a name.
  entity <- function(role) {
    which(ent$has_role(role) & !is.na(entity_names))[1L]
  }
  distributor <- entity("distributor")
  supplier_url <- read_urls(ent$regid[distributor])
  rel <- tables_swid_values(links, "rel")
  pages <- rel %in% c("describedby", "related", "installationmedia")
  href <- read_urls(ifelse(pages, tables_swid_values(links, "href"), NA_character_))
  link <- function(type) href$value[rel %in% type & !is.na(href$value)][1L]
  media <- which(rel %in% "installationmedia")[1L]
  meta_value <- function(key) {
    values <- tables_present(tables_swid_values(meta, key))
    values[!is.na(values)][1L]
  }
  # The tag describes only its root.
  on_root <- function(value) ifelse(root, value, NA_character_)

  read_values(n,
    supplier_url = on_root(supplier_url$value),
    maintainer = on_root(entity_names[entity("maintainer")]),
    homepage = on_root(link("describedby")), vcs_url = on_root(link("related")),
    download_location = on_root(link("installationmedia")),
    package_file_name = on_root(if (is.na(media)) NA_character_ else {
      tables_present(tables_swid_value(links[[media]], "artifact"))
    }),
    system_requirements = on_root(meta_value("sbom:systemRequirements")),
    version_is = tables_present(tables_swid_values(el$raw, "sbom:versionIs")),
    type = ifelse(root, "application", "library"),
    optional = el$scope %in% "optional",
    dropped = c(supplier_url$dropped, href$dropped)
  )
}

# What the SWID tag creators say: the regid of the first one with a real
# regid, the organization it names, and the authors. A tag creator with the
# placeholder regid http://invalid.unavailable (the default when it has none)
# is an author, unless it is sbom itself, the tool. `ent` is what
# tables_swid_entities() gives.
read_swid_creators <- function(ent) {
  creator <- ent$has_role("tagCreator")
  name <- ent$name[creator]
  # A padded regid, which the schema allows, is the regid without the padding.
  regid <- trimws(ent$regid[creator])
  real <- !is.na(regid) & regid != swid_placeholder_regid
  organization <- which(real & !is.na(name))[1L]
  list(
    regid = regid[real][1L],
    organization = name[organization],
    authors = name[!real & !is.na(name) & name != "sbom"]
  )
}

# The refs of a SWID tag's elements, without what the writer adds: the
# authority of the tag creator's regid before the root's tagId, and swid: and
# that authority before each link's href.
read_swid_ref_ids <- function(id, location, regid) {
  authority <- swid_authority(trimws(regid))
  link <- location != "/tag" & !is.na(id)
  id[link] <- sub("^swid:", "", id[link])
  if (!is.na(authority)) {
    prefix <- paste0(authority, "/")
    strip <- !is.na(id) & startsWith(id, prefix) & nchar(id) > nchar(prefix)
    id[strip] <- substring(id[strip], nchar(prefix) + 1L)
  }
  id
}

# The attribute `which` of the tables `t`, or `default` when they lack it,
# as tables built by hand may.
tables_coalesce_attr <- function(t, which, default) {
  value <- attr(t, which, exact = TRUE)
  if (is.null(value)) default else value
}

# Each element's id, or its purl, then name@version, then component-<n>.
read_fallback_refs <- function(id, purl, name, version) {
  name_version <- ifelse(is.na(name) | is.na(version), NA_character_, paste0(name, "@", version))
  tables_coalesce(id, purl, name_version, paste0("component-", seq_along(id)))
}

# Refs made unique: the first element with a ref keeps it, and the later ones
# get the suffixes after the highest -<k> already taken, so -2, -3 and so on
# when none is. Also, for each ref that was shared, in radix order, the
# number of elements that shared it and the refs the later ones got (at most
# 20 named).
read_unique_refs <- function(ref) {
  first <- !duplicated(ref)
  if (all(first)) {
    return(list(ref = ref, id = character(), count = integer(), renamed = character()))
  }
  later <- which(!first)
  shared <- ref[later]
  # The highest suffix each shared ref already has among all refs.
  pattern <- "^(.*)-([0-9]{1,9})$"
  suffixed <- grepl(pattern, ref)
  stem <- sub(pattern, "\\1", ref[suffixed])
  number <- as.integer(sub(pattern, "\\2", ref[suffixed]))
  hit <- stem %in% shared
  start <- rep(1L, length(later))
  if (any(hit)) {
    highest <- tapply(number[hit], stem[hit], max)
    at <- match(shared, names(highest))
    start[!is.na(at)] <- highest[at[!is.na(at)]]
  }
  o <- order(shared, later, method = "radix")
  rank <- integer(length(later))
  rank[o] <- sequence(rle(shared[o])$lengths)
  out <- ref
  k <- start + rank
  repeat {
    # A suffix can clash only with a ref of more than nine digits.
    out[later] <- paste0(shared, "-", k)
    clash <- out[later] %in% out[first] | duplicated(out[later])
    if (!any(clash)) break
    k[clash] <- k[clash] + length(later)
  }
  groups <- split(out[later], factor(shared, levels = sort(unique(shared), method = "radix")))
  list(
    ref = out, id = names(groups), count = lengths(groups) + 1L,
    renamed = vapply(groups, function(g) read_list(quote_value(g)), character(1), USE.NAMES = FALSE)
  )
}

# The ecosystem of each purl: its type, in lower case, except that a cran purl
# whose repository_url names bioconductor.org is "bioconductor". A component
# without a valid purl is "unknown". Each distinct purl is parsed once.
read_ecosystem <- function(purl) {
  out <- rep("unknown", length(purl))
  has <- !is.na(purl)
  if (!any(has)) {
    return(out)
  }
  distinct <- unique(purl[has])
  parsed <- purl_parse(distinct)
  type <- tolower(parsed$type)
  bioc <- vapply(parsed$qualifiers, function(q) {
    if (is.na(q)) {
      return(FALSE)
    }
    pairs <- strsplit(q, "&", fixed = TRUE)[[1]]
    key <- tolower(sub("=.*$", "", pairs))
    value <- sub("^[^=]*=", "", pairs)
    any(key == "repository_url" & grepl("bioconductor.org", value, fixed = TRUE, useBytes = TRUE))
  }, logical(1), USE.NAMES = FALSE)
  type[type %in% "cran" & bioc] <- "bioconductor"
  type[is.na(type)] <- "unknown"
  out[has] <- type[match(purl[has], distinct)]
  out
}

# license_spdx and license_as_written for the components `el`, from the
# license rows of the field each format declares licenses in. One valid
# expression is license_spdx. The license as written is what the format
# states apart (`written`), or else free text, an expression that does not
# parse, several licenses joined with ", ", or, in CycloneDX, whose writer
# leaves out the license as written when it is the expression, that one
# expression. Each distinct expression is checked once.
read_licenses <- function(licenses, el, family, written) {
  n <- nrow(el)
  field <- switch(family,
    cdx = "licenses", spdx2 = "licenseDeclared", spdx3 = "hasDeclaredLicense", swid = "license"
  )
  keep <- licenses$field == field & !is.na(tables_present(licenses$expression))
  licenses <- licenses[keep, , drop = FALSE]
  owner <- switch(family,
    cdx = match(sub("^(.*)/licenses/[0-9]+/.*$", "\\1", licenses$location), el$location),
    spdx2 = match(sub("/licenseDeclared$", "", licenses$location), el$location),
    spdx3 = match(licenses$id, el$id, incomparables = NA),
    swid = rep(match("/tag", el$location), nrow(licenses))
  )
  expression <- licenses$expression[!is.na(owner)]
  kind <- licenses$kind[!is.na(owner)]
  owner <- owner[!is.na(owner)]
  single <- tabulate(owner, n)[owner] == 1L
  valid <- kind == "expression" & license_expression_check(expression, special = FALSE)$valid
  # A license of another SPDX document needs that document's reference, which
  # is not kept, so it is kept as written only.
  other_document <- grepl("DocumentRef-", expression, fixed = TRUE)
  spdx <- rep(NA_character_, n)
  as_written <- rep(NA_character_, n)
  if (family != "swid") {
    keep <- single & valid & !other_document
    spdx[owner[keep]] <- expression[keep]
  }
  if (family %in% c("spdx2", "spdx3")) {
    as_written[owner[single & other_document]] <- expression[single & other_document]
  } else {
    stated <- single & (family == "cdx" | !valid)
    as_written[owner[stated]] <- expression[stated]
    joined <- vapply(split(expression[!single], owner[!single]), paste, character(1), collapse = ", ")
    as_written[as.integer(names(joined))] <- joined
    as_written <- tables_coalesce(written, as_written)
  }
  list(spdx = spdx, as_written = as_written)
}

# The comment of each relationship row at `location`: SPDX 2's on the
# relationship, SPDX 3's on the relationship node. NA elsewhere.
read_relationship_comments <- function(location, family, doc) {
  out <- rep(NA_character_, length(location))
  pattern <- switch(family, spdx2 = "^/relationships/([0-9]+)$", spdx3 = "^/@graph/([0-9]+)/to/[0-9]+$")
  if (is.null(pattern)) {
    return(out)
  }
  items <- json_items(json_member(doc, if (family == "spdx2") "relationships" else "@graph"))
  hit <- grepl(pattern, location)
  at <- as.integer(sub(pattern, "\\1", location[hit])) + 1L
  out[hit] <- json_strings(items[at], "comment")
  out
}

# The fields the SPDX writers state in a dependency's comment as
# "<Field>: <spec>" (relationship_comment()), each with the field it reads
# back as: those of DESCRIPTION and renv.lock, and SystemRequirements.
read_comment_fields <- c(
  Depends = "Depends", Imports = "Imports", LinkingTo = "LinkingTo",
  Requirements = "Requirements", SystemRequirements = "system_requirement"
)

# The field and spec of each relationship of type `type`, and whether its
# ends are swapped so that `from` is the dependent. A field of NA is a type
# sbom does not model.
read_relationship_fields <- function(type, comment, family) {
  n <- length(type)
  field <- rep(NA_character_, n)
  spec <- rep(NA_character_, n)
  swap <- rep(FALSE, n)
  if (family == "cdx") {
    field[type == "dependsOn"] <- "depends_on"
    field[type == "contains"] <- "contains"
  } else if (family == "swid") {
    field[] <- "depends_on"
  } else {
    pattern <- "^([A-Za-z]+): (.*)$"
    stated <- !is.na(comment) & grepl(pattern, comment)
    stated_field <- ifelse(stated, sub(pattern, "\\1", comment), NA_character_)
    stated_spec <- ifelse(stated, tables_present(sub(pattern, "\\2", comment)), NA_character_)
    s3 <- family == "spdx3"
    depends <- type %in% if (s3) "dependsOn" else "DEPENDS_ON"
    written <- depends & stated_field %in% names(read_comment_fields)
    field[depends] <- "depends_on"
    field[written] <- read_comment_fields[stated_field[written]]
    spec[written] <- stated_spec[written]
    field[type %in% if (s3) "contains" else "CONTAINS"] <- "contains"
    field[type %in% if (s3) "hasDynamicLink" else "DYNAMIC_LINK"] <- "dynamic_link"
    optional <- type %in% if (s3) "hasOptionalDependency" else "OPTIONAL_DEPENDENCY_OF"
    suggests <- optional & stated_field %in% "Suggests"
    field[optional] <- "optional"
    field[suggests] <- "Suggests"
    spec[suggests] <- stated_spec[suggests]
    if (s3) {
      field[type %in% "hasProvidedDependency"] <- "provided_dependency_of"
    } else {
      # SPDX 2 states these from the dependency to the dependent.
      other <- !optional & grepl("^([A-Z]+_)?DEPENDENCY_OF$", type)
      field[other] <- tolower(type[other])
      swap <- optional | other
    }
  }
  list(field = unname(field), spec = spec, swap = swap)
}

# Whether each id is one the document defines, one of another document's
# elements, or SPDX 2's NONE or NOASSERTION.
read_known_ids <- function(x, document, family) {
  known <- x %in% document$ids
  if (family == "spdx2") {
    external <- grepl(":", x, fixed = TRUE) & sub(":.*$", "", x) %in% document$external_ids
    known <- known | x %in% c("NONE", "NOASSERTION") | external
  } else if (family == "spdx3") {
    known <- known | x %in% document$external_ids
  }
  known
}

# The relationships between components, the components the document states
# the dependencies of without an edge (CycloneDX's dependencies entries,
# SPDX 2's DEPENDS_ON NONE), and the counts of relationships skipped for
# their type and of those that name elements the document lacks.
read_relationships <- function(t, doc, family, id, ref) {
  rel <- t$relationships
  # What a CycloneDX vulnerability affects is read as an advisory
  # (read_advisories()).
  if (family == "cdx") rel <- rel[!rel$type %in% "affects", , drop = FALSE]
  ref_of <- function(x) ref[match(x, id, incomparables = NA)]
  stated <- switch(family,
    cdx = ref_of(rel$from[rel$type != "contains"]),
    spdx2 = ref_of(rel$from[rel$type %in% "DEPENDS_ON" & rel$to %in% "NONE"])
  )
  rel <- rel[!is.na(rel$to), , drop = FALSE]
  m <- read_relationship_fields(rel$type, read_relationship_comments(rel$location, family, doc), family)
  from_id <- rel$from
  to_id <- rel$to
  from_id[m$swap] <- rel$to[m$swap]
  to_id[m$swap] <- rel$from[m$swap]
  from <- ref_of(from_id)
  to <- ref_of(to_id)
  known_from <- is.na(from) & read_known_ids(from_id, t$document, family)
  known_to <- is.na(to) & read_known_ids(to_id, t$document, family)
  modeled <- !is.na(m$field)
  edge <- modeled & !is.na(from) & !is.na(to)
  # A relationship that names an element which is not a component but which
  # the document defines (the document itself, a file, an agent) is left out
  # without an issue.
  dangling <- modeled & ((is.na(from) & !known_from) | (is.na(to) & !known_to))
  skipped <- !modeled & !known_from & !known_to
  out <- data.frame(
    from = from[edge], to = to[edge], field = m$field[edge], spec = m$spec[edge],
    evidence = rep("declared", sum(edge)), stringsAsFactors = FALSE
  )
  out <- out[!duplicated(out[c("from", "to", "field")]), , drop = FALSE]
  out <- out[order(out$from, out$to, out$field, method = "radix"), , drop = FALSE]
  rownames(out) <- NULL
  list(
    relationships = out, stated = stated, n_skipped = sum(skipped),
    skipped_types = sort(unique(rel$type[skipped]), method = "radix"), n_dangling = sum(dangling)
  )
}

# The parent of each component that exactly one contains relationship names
# as its target: the source of that relationship.
read_single_parent <- function(rels, ref) {
  contains <- rels[rels$field == "contains", , drop = FALSE]
  single <- !contains$to %in% contains$to[duplicated(contains$to)]
  out <- rep(NA_character_, length(ref))
  out[match(contains$to[single], ref)] <- contains$from[single]
  out
}

# Parents with every cycle broken: a component whose chain of parents never
# ends, because it is in a cycle or below one, gets none. Each step doubles
# the distance of the ancestor looked at, so the work is n log n.
read_acyclic_parents <- function(parent_ref, ref) {
  ancestor <- match(parent_ref, ref)
  for (i in seq_len(ceiling(log2(length(ref) + 1L)))) {
    ancestor <- ancestor[ancestor]
  }
  parent_ref[!is.na(ancestor)] <- NA_character_
  parent_ref
}
