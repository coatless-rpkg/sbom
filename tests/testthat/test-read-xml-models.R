tp <- function(...) test_path("fixtures", "third-party", ...)

# The parts of a CycloneDX JSON model that its XML serialization carries:
# per component, depth-first, its identity, licenses, hashes and external
# references; the dependencies; and the metadata's timestamp, authors, tools
# and component. Arrays are sorted by bom-ref or ref.
by_key <- function(items, key) {
  keys <- vapply(items, function(x) if (is.character(x[[key]])) x[[key]] else "", "")
  items[order(keys, method = "radix")]
}

cdx_component_rows <- function(items) {
  rows <- lapply(by_key(items, "bom-ref"), function(comp) {
    row <- list(
      ref = comp[["bom-ref"]], type = comp[["type"]], name = comp[["name"]],
      version = comp[["version"]], purl = comp[["purl"]],
      licenses = lapply(comp[["licenses"]], function(l) {
        list(expression = l[["expression"]], id = l[["license"]][["id"]], name = l[["license"]][["name"]])
      }),
      hashes = lapply(comp[["hashes"]], function(h) list(alg = h[["alg"]], content = h[["content"]])),
      externalReferences = lapply(comp[["externalReferences"]], function(r) list(type = r[["type"]], url = r[["url"]])),
      properties = lapply(comp[["properties"]], function(p) list(name = p[["name"]], value = p[["value"]]))
    )
    c(list(row), cdx_component_rows(comp[["components"]]))
  })
  unlist(rows, recursive = FALSE)
}

cdx_summary <- function(doc) {
  meta <- doc[["metadata"]]
  tools <- meta[["tools"]]
  if (!is.null(names(tools))) tools <- c(tools[["components"]], tools[["services"]])
  names_of <- function(items) vapply(items, function(x) x[["name"]], "")
  list(
    components = cdx_component_rows(doc[["components"]]),
    dependencies = lapply(by_key(doc[["dependencies"]], "ref"), function(d) {
      list(ref = d[["ref"]], dependsOn = sort(as.character(unlist(d[["dependsOn"]])), method = "radix"))
    }),
    timestamp = meta[["timestamp"]],
    authors = names_of(meta[["authors"]]),
    tools = names_of(tools),
    tools_shape = if (is.null(names(meta[["tools"]]))) "array" else names(meta[["tools"]]),
    component = meta[["component"]][["name"]],
    properties = lapply(meta[["properties"]], function(p) list(name = p[["name"]], value = p[["value"]]))
  )
}

test_that("CycloneDX XML reads to the model of its JSON twin", {
  dir <- tp("cyclonedx")
  files <- list.files(dir)
  stems <- intersect(
    sub("\\.json$", "", files[endsWith(files, ".json")]),
    sub("\\.xml$", "", files[endsWith(files, ".xml")])
  )
  expect_setequal(stems, c(
    "valid-bom-1.6", "valid-component-hashes-1.6", "valid-dependency-1.6",
    "valid-external-reference-1.6", "valid-license-expression-1.6",
    "valid-metadata-author-1.6", "valid-metadata-tool-1.6"
  ))
  for (stem in stems) {
    d <- read_document(file.path(dir, paste0(stem, ".xml")))
    expect_identical(c(d$format, d$version), c("cyclonedx-xml", "1.6"), label = stem)
    want <- cdx_summary(jsonlite::read_json(file.path(dir, paste0(stem, ".json"))))
    expect_identical(cdx_summary(d$doc), want, label = stem)
  }
  # The comparison is not vacuous.
  bom <- cdx_summary(read_document(file.path(dir, "valid-bom-1.6.xml"))$doc)
  expect_length(bom$components, 3L)
  expect_identical(bom$tools, "Awesome Tool")
  # Sorted by bom-ref, the component without one comes first.
  expect_identical(bom$components[[3]]$licenses[[1]]$expression, "EPL-2.0 OR GPL-2.0-with-classpath-exception")
  deps <- cdx_summary(read_document(file.path(dir, "valid-dependency-1.6.xml"))$doc)$dependencies
  expect_identical(deps[[2]], list(ref = "library-b", dependsOn = "library-c"))
  tools <- read_document(file.path(dir, "valid-metadata-tool-1.6.xml"))$doc$metadata$tools
  expect_identical(names(tools), c("components", "services"))
  expect_identical(tools$services[[1]]$provider$url, list("https://example.com"))
})

test_that("our own CycloneDX XML reads to the model of our own CycloneDX JSON", {
  skip_on_cran()
  x <- fixture_sbom()
  for (version in format_registry()[["cyclonedx-xml"]]$versions) {
    json <- withr::local_tempfile(fileext = ".cdx.json")
    xml <- withr::local_tempfile(fileext = ".cdx.xml")
    write_sbom(x, json, version = version)
    write_sbom(x, xml, version = version)
    want <- jsonlite::read_json(json)
    got <- read_document(xml)$doc
    expect_identical(cdx_summary(got), cdx_summary(want), label = version)
    top <- c("bomFormat", "specVersion", "serialNumber", "version")
    expect_identical(got[top], want[top], label = version)
    expect_gt(length(cdx_summary(got)$components), 1L)
  }
})

test_that("a SWID tag reads to its attributes, entities, links and meta", {
  d <- read_document(tp("swid", "hand.swidtag"))
  expect_identical(names(d$doc), c("tag", "entities", "links", "meta"))
  expect_identical(d$doc$tag[["tagId"]], "example.com-example-analyzer-2.1.0")
  expect_identical(d$doc$tag[["xml:lang"]], "en-US")
  expect_false(any(startsWith(names(d$doc$tag), "xmlns")))
  expect_identical(vapply(d$doc$entities, function(e) e[["role"]], ""), c("tagCreator", "softwareCreator"))
  expect_identical(
    vapply(d$doc$links, function(l) l[["href"]], ""),
    c("swid:example.com-example-runtime-3.0.0", "swid:example.org-example-parser-1.4.2")
  )
  expect_identical(d$doc$meta[[1]][["product"]], "Example Analyzer")
  # Our own tag's extension attributes are read from sbom's namespace, under
  # keys that start with "sbom:".
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_sbom(fixture_sbom(), tf)
  d <- read_document(tf)$doc
  requires <- d$links[vapply(d$links, function(l) identical(l[["rel"]], "requires"), logical(1))]
  expect_gt(length(requires), 1L)
  expect_true(all(vapply(requires, function(l) "sbom:name" %in% names(l), logical(1))))
  expect_true(any(vapply(requires, function(l) "sbom:version" %in% names(l), logical(1))))
  expect_true(any(vapply(requires, function(l) startsWith(l["sbom:purl"], "pkg:cran/"), logical(1))))
  keys <- unique(unlist(lapply(c(list(d$tag), d$entities, d$links, d$meta), names)))
  expect_true(all(!grepl(":", keys, fixed = TRUE) | startsWith(keys, "sbom:") | keys == "xml:lang"))
})

test_that("CycloneDX elements and attributes in another namespace are not read", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:x="urn:example:x" version="1" x:version="9">',
    "<components>",
    '<component x:name="FAKE" type="library" x:type="spoof" bom-ref="a">',
    "<name>re<x:i>FAKE3</x:i>al</name><version>1</version><x:name>FAKE2</x:name><x:version>9</x:version>",
    '<x:extension><components><component type="library"><name>hidden</name></component></components></x:extension>',
    "</component>",
    '<x:component type="library"><name>spoof</name></x:component>',
    "</components>",
    '<x:components><component type="library"><name>spoof2</name></component></x:components>',
    '<dependencies><dependency ref="a" x:ref="b"><x:dependency ref="z"/></dependency></dependencies>',
    "</bom>"
  ), tf)
  doc <- read_document(tf)$doc
  expect_length(doc$components, 1L)
  comp <- doc$components[[1]]
  expect_identical(
    comp[c("type", "bom-ref", "name", "version")],
    list(type = "library", `bom-ref` = "a", name = "real", version = "1")
  )
  expect_setequal(names(comp), c("type", "bom-ref", "name", "version"))
  expect_identical(doc$version, 1L)
  expect_identical(doc$dependencies, list(list(ref = "a")))
  expect_false(any(grepl("spoof|FAKE|hidden|^9$|^b$|^z$", unlist(doc))))
})

test_that("SWID elements and attributes in another namespace are not read", {
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_text(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'xmlns:x="urn:example:x" xmlns:sbom="https://cran.r-project.org/package=sbom" ',
    'x:name="FAKE" name="real" tagId="t" version="1.0" sbom:name="ext" xml:lang="en">',
    '<x:Entity name="spoof" regid="x.example" role="tagCreator"/>',
    '<Entity name="Real Org" regid="example.org" role="tagCreator" x:role="softwareCreator"/>',
    '<Link rel="requires" href="swid:a" sbom:name="a" sbom:purl="pkg:cran/a@1" x:href="swid:spoof" x:name="spoof"/>',
    '<x:Link rel="requires" href="swid:spoof"/>',
    '<Meta product="P" sbom:license="MIT"/>',
    "</SoftwareIdentity>"
  ), tf)
  d <- read_document(tf)$doc
  tag <- c(name = "real", tagId = "t", version = "1.0", `sbom:name` = "ext", `xml:lang` = "en")
  expect_setequal(names(d$tag), names(tag))
  expect_identical(d$tag[names(tag)], tag)
  expect_length(d$entities, 1L)
  expect_identical(d$entities[[1]][c("name", "role")], c(name = "Real Org", role = "tagCreator"))
  expect_setequal(names(d$entities[[1]]), c("name", "regid", "role"))
  expect_length(d$links, 1L)
  link <- c(rel = "requires", href = "swid:a", `sbom:name` = "a", `sbom:purl` = "pkg:cran/a@1")
  expect_setequal(names(d$links[[1]]), names(link))
  expect_identical(d$links[[1]][names(link)], link)
  expect_identical(d$meta[[1]][["sbom:license"]], "MIT")
})

test_that("only the top-level dependencies get the dependency shape", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6">',
    "<compositions><composition><aggregate>complete</aggregate>",
    '<dependencies><dependency ref="a"/></dependencies></composition></compositions>',
    '<dependencies><dependency ref="a"/></dependencies>',
    "</bom>"
  ), tf)
  doc <- read_document(tf)$doc
  expect_identical(doc$dependencies, list(list(ref = "a")))
  expect_identical(
    doc$compositions,
    list(composition = list(aggregate = "complete", dependencies = list(dependency = list(ref = "a"))))
  )
})

test_that("only text and attributes of a token type are trimmed", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>\n',
    '  <component type="library" bom-ref=" a " mime-type=" text/plain ">\n',
    "    <name>\n      real\n    </name>\n    <version> 1.0 </version>\n",
    "    <purl> pkg:cran/a@1.0 </purl>\n",
    '    <hashes>\n      <hash alg="SHA-256">\n        0123abcd\n      </hash>\n    </hashes>\n',
    "  </component>\n</components>\n",
    '<dependencies><dependency ref=" a "><dependency ref=" b "/></dependency></dependencies>\n',
    "</bom>\n"
  ), tf)
  doc <- read_document(tf)$doc
  comp <- doc$components[[1]]
  # Hash content and mime-type are tokens; strings keep their spaces.
  expect_identical(comp$hashes, list(list(alg = "SHA-256", content = "0123abcd")))
  expect_identical(comp[["mime-type"]], "text/plain")
  expect_identical(
    comp[c("bom-ref", "name", "version", "purl")],
    list(`bom-ref` = " a ", name = "\n      real\n    ", version = " 1.0 ", purl = " pkg:cran/a@1.0 ")
  )
  expect_identical(doc$dependencies, list(list(ref = " a ", dependsOn = list(" b "))))
})

test_that("SWID attributes of a token type are trimmed, and only those", {
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_text(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'name=" Real " tagId=" t " version=" 1.0 " versionScheme=" semver ">\n',
    '  <Entity name=" Org " regid="example.org" role=" tagCreator  softwareCreator "/>\n',
    '  <Link rel=" requires " use=" required " ownership=" shared " href=" swid:a "/>\n',
    "</SoftwareIdentity>\n"
  ), tf)
  expect_identical(schema_validate(tf, "swid", "2015")$status, "partial")
  d <- read_document(tf)$doc
  # NMTOKEN, NMTOKENS and their restrictions are tokens; strings and URIs
  # keep their spaces.
  expect_identical(
    d$tag[c("name", "tagId", "version", "versionScheme")],
    c(name = " Real ", tagId = " t ", version = " 1.0 ", versionScheme = "semver")
  )
  expect_identical(d$entities[[1]][c("name", "role")], c(name = " Org ", role = "tagCreator  softwareCreator"))
  expect_identical(
    d$links[[1]][c("rel", "use", "ownership", "href")],
    c(rel = "requires", use = "required", ownership = "shared", href = " swid:a ")
  )
})

test_that("nested dependencies lift into entries of their own", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><dependencies>',
    '<dependency ref="a"><dependency ref="b"><dependency ref="c"><dependency ref="d"/>',
    "</dependency></dependency></dependency>",
    '<dependency ref="b"><dependency ref="e"/></dependency>',
    "</dependencies></bom>"
  ), tf)
  expect_identical(read_document(tf)$doc$dependencies, list(
    list(ref = "a", dependsOn = list("b")),
    list(ref = "b", dependsOn = list("e", "c")),
    list(ref = "c", dependsOn = list("d"))
  ))
})

test_that("attributes CycloneDX does not declare are not read", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1" components="x" dependencies="y">',
    "<components>",
    '<component type="library" bom-ref="a" purl="pkg:npm/evil@1" version="6.6.6" group="evil" ',
    'hashes="x" licenses="y" components="z"><name>real</name></component>',
    "</components></bom>"
  ), tf)
  # The schema admits them: its wildcard takes any attribute.
  expect_identical(schema_validate(tf, "cyclonedx-xml", "1.6")$status, "pass")
  doc <- read_document(tf)$doc
  expect_identical(
    doc[setdiff(names(doc), "components")],
    list(bomFormat = "CycloneDX", specVersion = "1.6", version = 1L)
  )
  expect_length(doc$components, 1L)
  expect_identical(doc$components[[1]], list(type = "library", `bom-ref` = "a", name = "real"))
})

test_that("declared attributes are read", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" serialNumber="urn:uuid:x" version="2">',
    '<components><component type="library" bom-ref="a"><name>a</name>',
    '<hashes><hash alg="SHA-1">0123</hash></hashes>',
    '<licenses><license acknowledgement="declared" bom-ref="l"><id>MIT</id></license></licenses>',
    '<externalReferences><reference type="vcs"><url>https://example.org</url></reference></externalReferences>',
    '<properties><property name="k">v</property></properties>',
    "</component></components>",
    '<dependencies><dependency ref="a"><dependency ref="b"/></dependency></dependencies></bom>'
  ), tf)
  doc <- read_document(tf)$doc
  comp <- doc$components[[1]]
  expect_identical(doc[c("serialNumber", "version")], list(serialNumber = "urn:uuid:x", version = 2L))
  expect_identical(comp[c("type", "bom-ref")], list(type = "library", `bom-ref` = "a"))
  expect_identical(comp$hashes, list(list(alg = "SHA-1", content = "0123")))
  expect_identical(comp$licenses, list(list(license = list(acknowledgement = "declared", `bom-ref` = "l", id = "MIT"))))
  expect_identical(comp$externalReferences, list(list(type = "vcs", url = "https://example.org")))
  expect_identical(comp$properties, list(list(name = "k", value = "v")))
  expect_identical(doc$dependencies, list(list(ref = "a", dependsOn = list("b"))))

  swid <- withr::local_tempfile(fileext = ".swidtag")
  write_text(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'name="x" tagId="t" purl="pkg:npm/evil@1">',
    '<Entity name="E" regid="example.org" role="tagCreator" href="evil"/>',
    '<Link rel="requires" href="swid:a" name="evil"/>',
    '<Meta product="P" purl="pkg:npm/evil@1"/></SoftwareIdentity>'
  ), swid)
  d <- read_document(swid)$doc
  expect_identical(d$tag, c(name = "x", tagId = "t"))
  expect_identical(d$entities[[1]], c(name = "E", regid = "example.org", role = "tagCreator"))
  expect_identical(d$links[[1]], c(rel = "requires", href = "swid:a"))
  expect_identical(d$meta[[1]], c(product = "P"))
})

test_that("an attribute named like a child element yields to the child", {
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" specVersion="9.9"><components>',
    '<component type="library" name="FAKE"><name>real</name>',
    '<externalReferences><reference type="vcs" url="https://evil.example"><url>https://example.org</url>',
    "</reference></externalReferences></component></components></bom>"
  ), tf)
  expect_identical(schema_validate(tf, "cyclonedx-xml", "1.6")$status, "pass")
  d <- read_document(tf)
  expect_identical(d$version, "1.6")
  expect_identical(d$doc$specVersion, "1.6")
  comp <- d$doc$components[[1]]
  expect_identical(comp$name, "real")
  expect_identical(comp$externalReferences, list(list(type = "vcs", url = "https://example.org")))
})

# The attributes each element declares in a set of XSDs, as a named list of
# sorted character vectors, keyed by element name, or by "parent/name" where
# one element name declares different attributes under different parents.
# Elements that declare none are left out, and so are attributes declared by
# reference (xml:lang). Also the names of the elements whose text, and of
# the attributes whose value, have a type derived from xs:token: xs:token
# itself, the built-in types XML Schema derives from it (NMTOKEN and the
# like), and named restrictions of any of these.
xsd_token_types <- c(
  "xs:token", "xs:language", "xs:Name", "xs:NCName", "xs:ID", "xs:IDREF",
  "xs:IDREFS", "xs:ENTITY", "xs:ENTITIES", "xs:NMTOKEN", "xs:NMTOKENS"
)
xsd_declarations <- function(paths) {
  xs <- c(xs = "http://www.w3.org/2001/XMLSchema")
  local <- function(x) sub("^.*:", "", x)
  srt <- function(x) if (length(x) == 0L) character() else sort(unique(as.character(x)), method = "radix")
  rows <- list()
  token_text <- character()
  token_attrs <- character()
  for (path in paths) {
    doc <- xml2::read_xml(path)
    owner_of <- function(node) {
      owners <- xml2::xml_find_all(
        node,
        "ancestor::*[(self::xs:element or self::xs:complexType or self::xs:attributeGroup) and @name]",
        xs
      )
      if (length(owners) == 0L) NULL else owners[[length(owners)]]
    }
    # Named types and attribute groups are keyed by name; element
    # declarations, whose names repeat, by their path in the schema.
    owner_key <- function(owner) {
      if (is.null(owner)) {
        return("")
      }
      kind <- xml2::xml_name(owner)
      if (kind == "element") {
        paste0("element:", xml2::xml_path(owner))
      } else {
        paste0(kind, ":", xml2::xml_attr(owner, "name"))
      }
    }
    simple <- xml2::xml_find_all(doc, "/xs:schema/xs:simpleType[@name]", xs)
    simple_base <- vapply(simple, function(s) {
      base <- xml2::xml_attr(xml2::xml_find_first(s, "xs:restriction", xs), "base")
      if (is.na(base)) "" else base
    }, character(1))
    names(simple_base) <- xml2::xml_attr(simple, "name")
    is_token <- function(type) {
      seen <- character()
      while (!is.na(type) && nzchar(type) && !type %in% seen) {
        if (type %in% xsd_token_types) return(TRUE)
        seen <- c(seen, type)
        type <- simple_base[local(type)]
      }
      FALSE
    }
    own <- list()
    groups_of <- list()
    base_of <- list()
    for (a in xml2::xml_find_all(doc, "//xs:attribute[@name]", xs)) {
      key <- owner_key(owner_of(a))
      own[[key]] <- c(own[[key]], xml2::xml_attr(a, "name"))
      if (is_token(xml2::xml_attr(a, "type"))) token_attrs <- c(token_attrs, xml2::xml_attr(a, "name"))
    }
    for (g in xml2::xml_find_all(doc, "//xs:attributeGroup[@ref]", xs)) {
      key <- owner_key(owner_of(g))
      groups_of[[key]] <- c(groups_of[[key]], paste0("attributeGroup:", local(xml2::xml_attr(g, "ref"))))
    }
    for (e in xml2::xml_find_all(doc, "//xs:extension[@base]", xs)) {
      key <- owner_key(owner_of(e))
      base_of[[key]] <- c(base_of[[key]], local(xml2::xml_attr(e, "base")))
    }
    complex_names <- xml2::xml_attr(xml2::xml_find_all(doc, "/xs:schema/xs:complexType[@name]", xs), "name")
    attrs_of <- function(key, seen = character()) {
      if (key %in% seen) {
        return(character())
      }
      seen <- c(seen, key)
      out <- own[[key]]
      for (g in groups_of[[key]]) out <- c(out, attrs_of(g, seen))
      for (b in intersect(base_of[[key]], complex_names)) out <- c(out, attrs_of(paste0("complexType:", b), seen))
      out
    }
    # A named type and the types that derive from it, so that an element
    # declared in a base type has the derived types' elements as parents.
    derived <- function(type) {
      out <- type
      repeat {
        more <- complex_names[vapply(complex_names, function(t) {
          any(base_of[[paste0("complexType:", t)]] %in% out)
        }, logical(1))]
        more <- setdiff(more, out)
        if (length(more) == 0L) {
          return(out)
        }
        out <- c(out, more)
      }
    }
    elements <- xml2::xml_find_all(doc, "//xs:element[@name]", xs)
    el_name <- xml2::xml_attr(elements, "name")
    el_type <- local(xml2::xml_attr(elements, "type"))
    for (i in seq_along(elements)) {
      e <- elements[[i]]
      named <- !is.na(el_type[i]) && el_type[i] %in% complex_names
      attrs <- if (named) {
        attrs_of(paste0("complexType:", el_type[i]))
      } else if (is.na(el_type[i])) {
        attrs_of(owner_key(e))
      }
      content <- if (named) {
        path <- sprintf("/xs:schema/xs:complexType[@name='%s']/xs:simpleContent/xs:extension", el_type[i])
        xml2::xml_find_first(doc, path, xs)
      } else {
        xml2::xml_find_first(e, "xs:complexType/xs:simpleContent/xs:extension", xs)
      }
      text_type <- if (is.na(el_type[i]) || named) xml2::xml_attr(content, "base") else xml2::xml_attr(e, "type")
      if (is_token(text_type)) token_text <- c(token_text, el_name[i])
      owner <- owner_of(e)
      parents <- if (is.null(owner)) {
        ""
      } else if (xml2::xml_name(owner) == "element") {
        xml2::xml_attr(owner, "name")
      } else if (xml2::xml_name(owner) == "complexType") {
        unique(el_name[!is.na(el_type) & el_type %in% derived(xml2::xml_attr(owner, "name"))])
      }
      for (p in parents) rows[[length(rows) + 1L]] <- list(key = paste0(p, "/", el_name[i]), attrs = attrs)
    }
  }
  row_keys <- vapply(rows, function(r) r$key, "")
  keys <- unique(row_keys)
  sets <- lapply(keys, function(k) srt(unlist(lapply(rows[row_keys == k], function(r) r$attrs))))
  names(sets) <- keys
  element <- sub("^.*/", "", keys)
  out <- list()
  for (name in srt(element)) {
    these <- sets[element == name]
    if (all(vapply(these, identical, logical(1), these[[1]]))) {
      if (length(these[[1]]) > 0L) out[[name]] <- these[[1]]
    } else {
      for (k in names(these)) if (length(these[[k]]) > 0L) out[[k]] <- these[[k]]
    }
  }
  list(attrs = out[srt(names(out))], token_text = srt(token_text), token_attrs = srt(token_attrs))
}

test_that("the CycloneDX declared-attribute tables are those of the bundled XSDs", {
  skip_on_cran()
  versions <- format_registry()[["cyclonedx-xml"]]$versions
  cdx <- xsd_declarations(vapply(versions, function(v) schema_file("cyclonedx-xml", v), ""))
  expect_identical(cdx_xml_declared_attrs, cdx$attrs)
  expect_identical(cdx_xml_token_text, cdx$token_text)
  expect_identical(cdx_xml_token_attrs, cdx$token_attrs)
})

test_that("the SWID declared-attribute tables are those of the ISO schema", {
  # sbom does not bundle the ISO schema; SBOM_TEST_SWID_XSD names a copy.
  xsd <- Sys.getenv("SBOM_TEST_SWID_XSD")
  skip_if(!nzchar(xsd), "SBOM_TEST_SWID_XSD names no copy of the ISO schema.")
  swid <- xsd_declarations(xsd)
  expect_identical(swid_declared_attrs, swid$attrs)
  expect_length(swid$token_text, 0L)
  expect_identical(swid_token_attrs, swid$token_attrs)
})
