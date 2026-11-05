tp <- function(...) test_path("fixtures", "third-party", ...)

# The <sbom> read from a file whose text is `text`, written with the
# extension `fileext`.
read_text <- function(text, fileext, name = "doc") {
  dir <- withr::local_tempdir(.local_envir = parent.frame())
  path <- file.path(dir, paste0(name, fileext))
  write_text(text, path)
  read_sbom(path)
}

# The issues of `x` with the code `code`.
issues_with <- function(x, code) {
  x$issues[x$issues$code == code, , drop = FALSE]
}

# fixture_sbom() with checksums and a download location on one component,
# which the fixture has nowhere, so that those columns have values to compare.
round_trip_sbom <- function(env = parent.frame()) {
  x <- fixture_sbom(env = env)
  i <- match("pkg:cran/cranpkg@1.2.0", x$components$ref)
  x$components$hashes[[i]] <- data.frame(
    alg = c("SHA-256", "MD5"), content = c(strrep("ab", 32), strrep("cd", 16)),
    of = NA_character_, stringsAsFactors = FALSE
  )
  x$components$download_location[i] <- "https://cran.r-project.org/src/contrib/cranpkg_1.2.0.tar.gz"
  x
}

# The columns `cols` of the components `comps`, the hashes as text, with the
# rows sorted by every column.
comparable <- function(comps, cols) {
  out <- lapply(stats::setNames(cols, cols), function(col) {
    if (col != "hashes") {
      return(comps[[col]])
    }
    vapply(comps$hashes, function(h) {
      if (nrow(h) == 0L) "" else paste(sort(paste0(h$alg, ":", h$content), method = "radix"), collapse = " ")
    }, character(1))
  })
  out <- data.frame(out, stringsAsFactors = FALSE)
  out <- out[do.call(order, c(unname(out), list(method = "radix"))), , drop = FALSE]
  rownames(out) <- NULL
  out
}

# The relationships of `x` as sorted, unique "from -> to" pairs of names, with
# the columns `cols` of the relationships after them.
name_edges <- function(x, cols = character()) {
  name_of <- function(ref) x$components$name[match(ref, x$components$ref)]
  rel <- x$relationships
  out <- do.call(paste, c(list(name_of(rel$from), "->", name_of(rel$to)), unname(as.list(rel[cols]))))
  sort(unique(out), method = "radix")
}

# `x` with each relationship's field as CycloneDX carries it: contains, or
# depends_on for every other.
as_kinds <- function(x) {
  x$relationships$field <- ifelse(x$relationships$field == "contains", "contains", "depends_on")
  x
}

test_that("an SBOM written in every format at every version reads back", {
  skip_if_not_installed("yaml")
  x <- round_trip_sbom()
  ext <- stats::setNames(sbom_formats()$extension, sbom_formats()$format)
  cdx <- c("cyclonedx-json", "cyclonedx-xml")
  spdx2 <- c("spdx-json", "spdx-yaml", "spdx-xml", "spdx-tv")
  cols_of <- function(format) {
    c(
      "name", "version", "purl",
      if (format != "swid") {
        c("license_spdx", "supplier_name", "homepage", "download_location", "vcs_url", "hashes")
      },
      if (format %in% cdx) c("ref", "evidence", "version_is", "published", "maintainer")
    )
  }
  for (format in read_formats) {
    for (version in format_registry()[[format]]$versions) {
      label <- paste(format, version)
      path <- withr::local_tempfile(fileext = ext[[format]])
      write_sbom(x, path, format = format, version = version)
      y <- read_sbom(path)
      expect_s3_class(y, "sbom")
      cols <- cols_of(format)
      expected <- x$components
      if (format == "swid") {
        # A SWID tag lists the root and links to the components it needs;
        # code compiled into a package and app files (type "file") get no link.
        linked <- !is_embedded_ref(expected$ref) & expected$type != "file"
        expected <- expected[expected$is_root | linked, , drop = FALSE]
      }
      if (format %in% c(spdx2, "spdx3-jsonld")) {
        # The SPDX writers give R and its base packages no supplier, by design.
        expected$supplier_name[expected$ecosystem %in% c("r", "base-r")] <- NA_character_
      }
      expect_identical(comparable(y$components, cols), comparable(expected, cols), label = label)

      # Edges with the field, contains included, as far as the format carries
      # it, so that losing one of two edges between the same names fails.
      root <- x$components$name[x$components$is_root]
      if (format == "swid") {
        links <- expected$name[!expected$is_root]
        expect_identical(
          name_edges(y, "field"), sort(paste(root, "->", links, "depends_on"), method = "radix"),
          label = label
        )
      } else if (format %in% cdx) {
        expect_identical(name_edges(y, "field"), name_edges(as_kinds(x), "field"), label = label)
      } else {
        expect_identical(name_edges(y, c("field", "spec")), name_edges(x, c("field", "spec")), label = label)
      }
      expect_identical(y$components$name[y$components$is_root], root, label = label)
      expect_identical(y$metadata$root, y$components$ref[y$components$is_root], label = label)
    }
  }
})

test_that("every third-party SBOM reads, and the examples write valid documents in every format", {
  skip_if_not_installed("yaml")
  files <- list.files(tp(), recursive = TRUE, full.names = TRUE)
  files <- files[!basename(files) %in% c("SOURCES.md", "invalid-component-type-1.6.json")]
  expect_gt(length(files), 25L)
  reads <- list()
  for (path in files) {
    x <- read_sbom(path)
    expect_s3_class(x, "sbom")
    expect_gte(nrow(x$components), 1L)
    expect_identical(sum(x$components$is_root), 1L, label = basename(path))
    reads[[basename(path)]] <- x
  }
  for (file in c("SPDXJSONExample-v2.3.spdx.json", "valid-bom-1.6.json", "package_sbom.json")) {
    expect_valid_in_every_format(reads[[file]], file)
  }
})

test_that("the SPDX 2.3 example maps its packages, licences, relationships and creators", {
  x <- read_sbom(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  comps <- x$components
  expect_identical(
    comps$ref, c("SPDXRef-Package", "SPDXRef-Saxon", "SPDXRef-fromDoap-0", "SPDXRef-fromDoap-1")
  )
  glibc <- comps[comps$name == "glibc", ]
  expect_true(glibc$is_root)
  expect_identical(x$metadata$root, "SPDXRef-Package")
  expect_identical(glibc$type, "library")
  expect_identical(glibc$supplier_name, "Jane Doe (jane.doe@example.com)")
  # The originator is an organization, not a person.
  expect_identical(glibc$maintainer, NA_character_)
  expect_identical(glibc$license_spdx, "(LGPL-2.0-only AND LicenseRef-3)")
  expect_identical(glibc$homepage, "http://ftp.gnu.org/gnu/glibc")
  expect_identical(glibc$download_location, "http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz")
  expect_identical(glibc$published, "2012-01-29")
  expect_identical(glibc$package_file_name, "glibc-2.11.1.tar.gz")
  expect_match(glibc$license_comment, "^The license for this project changed")
  # SHA256 and SHA1 take sbom's names; BLAKE2b-384 is not one every format takes.
  expect_identical(glibc$hashes[[1]]$alg, c("MD5", "SHA-1", "SHA-256"))
  jena <- comps[comps$name == "Jena", ]
  expect_identical(jena$purl, "pkg:maven/org.apache.jena/apache-jena@3.12.0")
  expect_identical(jena$ecosystem, "maven")
  expect_identical(jena$version_is, "exact")
  lang <- comps[comps$name == "Apache Commons Lang", ]
  expect_identical(lang$license_spdx, NA_character_)
  expect_identical(lang$download_location, NA_character_)
  expect_identical(lang$version_is, NA_character_)
  expect_identical(lang$ecosystem, "unknown")
  expect_identical(unique(comps$evidence), "declared")
  expect_identical(unique(comps$source_input), "SPDXJSONExample-v2.3.spdx.json")
  # Only the dynamic link joins two packages; the other relationships name
  # the document, files or elements of another document.
  expect_identical(x$relationships, data.frame(
    from = "SPDXRef-Package", to = "SPDXRef-Saxon", field = "dynamic_link",
    spec = NA_character_, evidence = "declared", stringsAsFactors = FALSE
  ))
  expect_identical(comps$deps_known, c(TRUE, FALSE, FALSE, FALSE))
  expect_identical(nrow(issues_with(x, "read-dangling-relationships")), 0L)
  expect_identical(nrow(issues_with(x, "read-relationships-skipped")), 0L)

  meta <- x$metadata
  expect_identical(meta$timestamp, as.POSIXct("2010-01-29 18:30:22", tz = "UTC"))
  expect_identical(meta$author, "Jane Doe")
  expect_identical(meta$organization, "ExampleCodeInspect")
  expect_identical(meta$tool_version, NA_character_)
  expect_identical(meta$notes, c(
    "Read from SPDXJSONExample-v2.3.spdx.json (SPDX JSON 2.3).",
    "This document was created using SPDX 2.0 using licenses from the web site."
  ))
  expect_identical(meta$regid, NA_character_)
})

test_that("our own CycloneDX file gives the tool version, and inputs name the file read", {
  x <- fixture_sbom()
  path <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, path)
  y <- read_sbom(path)
  expect_identical(y$metadata$tool_version, as.character(utils::packageVersion("sbom")))
  expect_identical(y$metadata$inputs, data.frame(kind = "sbom", path = path))
  expect_identical(y$metadata$author, "Test Author")
  expect_identical(y$metadata$organization, "Test Org")
  expect_identical(y$metadata$timestamp, x$metadata$timestamp)
  expect_identical(y$metadata$notes, c(
    paste0("Read from ", basename(path), " (CycloneDX JSON 1.6)."),
    document_notes(x)
  ))
  expect_identical(nrow(y$issues), 0L)
  # The dependencies entries say whose dependencies are known.
  known <- y$components$ref[y$components$deps_known]
  expect_setequal(known, c("local/srcpkg", "local/localpkg", "pkg:cran/cranpkg@1.2.0"))
  expect_identical(
    y$components$parent_ref[match(c("R/utils", "local/srcpkg#embedded/cranpkg"), y$components$ref)],
    c("R", "local/srcpkg")
  )
  expect_identical(y$components$scope[y$components$name == "suggestpkg"], "optional")
  # CycloneDX 1.4 and 1.5 keep the organization in a property.
  write_sbom(x, path, version = "1.5")
  expect_identical(read_sbom(path)$metadata$organization, "Test Org")
})

test_that("no written document from a read SBOM holds the reading machine's temporary folder", {
  skip_if_not_installed("yaml")
  path <- withr::local_tempfile(fileext = ".spdx.json")
  write_sbom(fixture_sbom(), path)
  y <- read_sbom(path)
  expect_identical(y$metadata$inputs$path, path)
  temp <- unique(c(tempdir(), normalizePath(tempdir(), winslash = "/")))
  for (format in sbom_formats()$format) {
    out <- withr::local_tempfile(fileext = sbom_formats()$extension[sbom_formats()$format == format])
    write_sbom(y, out, format = format)
    text <- rawToChar(readBin(out, "raw", file.size(out)))
    for (dir in temp) {
      expect_false(grepl(dir, text, fixed = TRUE), label = paste(format, dir))
    }
  }
})

test_that("an SBOM from another ecosystem reads and writes valid documents", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"timestamp":"2026-11-06T10:11:12+02:00","component":{"type":"container",',
    '"bom-ref":"image","name":"app-image","version":"3.1"}},',
    '"components":[',
    '{"type":"library","bom-ref":"guava","name":"guava","version":"33.0.0",',
    '"purl":"pkg:maven/com.google.guava/guava@33.0.0","licenses":[{"license":{"id":"Apache-2.0"}}]},',
    '{"type":"firmware","bom-ref":"requests","name":"requests","version":"2.31.0",',
    '"purl":"pkg:pypi/requests@2.31.0","scope":"excluded",',
    '"licenses":[{"license":{"name":"Apache License 2.0"}}]},',
    '{"type":"framework","name":"loose-part"}],',
    '"dependencies":[{"ref":"image","dependsOn":["guava","requests"]},{"ref":"guava","dependsOn":[]}]}\n'
  ), ".cdx.json")
  comps <- x$components
  expect_identical(comps$ref, c("component-4", "guava", "image", "requests"))
  expect_identical(comps$name, c("loose-part", "guava", "app-image", "requests"))
  expect_identical(comps$type, rep("library", 4))
  expect_identical(comps$ecosystem, c("unknown", "maven", "unknown", "pypi"))
  expect_identical(comps$version_is, c(NA, "exact", "exact", "exact"))
  expect_identical(comps$scope, c("required", "required", "required", "optional"))
  expect_identical(comps$license_spdx, c(NA, "Apache-2.0", NA, NA))
  # One valid licence is also the licence as written, as the writer leaves it.
  expect_identical(comps$license_as_written, c(NA, "Apache-2.0", NA, "Apache License 2.0"))
  expect_identical(comps$deps_known, c(FALSE, TRUE, TRUE, FALSE))
  expect_identical(x$metadata$timestamp, as.POSIXct("2026-11-06 08:11:12", tz = "UTC"))
  expect_identical(x$metadata$author, NA_character_)
  expect_valid_in_every_format(x, "another ecosystem")
})

test_that("CycloneDX licences, references and properties map to their columns", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"timestamp":"2026-01-02T03:04:05Z","manufacture":{"name":"Maker Ltd"},',
    '"supplier":{"name":"Sup Inc","url":["https://sup.example"]},',
    '"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[',
    '{"type":"library","bom-ref":"a","name":"a","version":"1","publisher":"Pat",',
    '"supplier":{"name":"S","url":["https://s.example","https://t.example"]},',
    '"licenses":[{"license":{"id":"MIT"}},{"license":{"name":"Custom"}}],',
    '"externalReferences":[{"type":"website","url":"https://a.example"},',
    '{"type":"vcs","url":"not a url"},{"type":"vcs","url":"https://git.example/a"},',
    '{"type":"distribution","url":"https://dl.example/a.tgz"}],',
    '"hashes":[{"alg":"SHA-256","content":"', strrep("0", 64), '"},',
    '{"alg":"SHA3-256","content":"', strrep("1", 64), '"},{"alg":"MD5","content":"short"}],',
    '"properties":[{"name":"sbom:version-is","value":"minimum"},{"name":"sbom:evidence","value":"observed"},',
    '{"name":"sbom:doi","value":"10.1/x"},{"name":"sbom:published","value":"2025-05-05"},',
    '{"name":"sbom:system-requirements","value":"libxml2"},{"name":"sbom:bioconductor-release","value":"3.20"}]},',
    '{"type":"library","bom-ref":"b","name":"b","version":"2","licenses":[{"expression":"MIT OR (GPL-2.0-only"}],',
    '"properties":[{"name":"sbom:maintainer","value":"Kim"},{"name":"sbom:evidence","value":"guessed"}]},',
    '{"type":"library","bom-ref":"c","name":"c","licenses":[{"expression":"MIT"}],',
    '"purl":"pkg:cran/c@1?repository_url=https://bioconductor.org/packages/3.20/bioc",',
    '"properties":[{"name":"sbom:license-as-written","value":"MIT + file LICENSE"}]}]}\n'
  ), ".cdx.json")
  comps <- x$components
  a <- comps[comps$ref == "a", ]
  expect_identical(a$supplier_name, "S")
  expect_identical(a$supplier_url, "https://s.example")
  expect_identical(a$maintainer, "Pat")
  expect_identical(a$license_spdx, NA_character_)
  expect_identical(a$license_as_written, "MIT, Custom")
  expect_identical(a$homepage, "https://a.example")
  expect_identical(a$vcs_url, "https://git.example/a")
  expect_identical(a$download_location, "https://dl.example/a.tgz")
  expect_identical(
    a$hashes[[1]],
    data.frame(alg = c("SHA-256", "SHA3-256"), content = c(strrep("0", 64), strrep("1", 64)), of = NA_character_)
  )
  expect_identical(a$version_is, "minimum")
  expect_identical(a$evidence, "observed")
  expect_identical(a$doi, "10.1/x")
  expect_identical(a$published, "2025-05-05")
  expect_identical(a$system_requirements, "libxml2")
  expect_identical(a$bioc_release, "3.20")
  b <- comps[comps$ref == "b", ]
  expect_identical(b$maintainer, "Kim")
  expect_identical(b$evidence, "declared")
  # An expression that does not parse is kept as written.
  expect_identical(b$license_spdx, NA_character_)
  expect_identical(b$license_as_written, "MIT OR (GPL-2.0-only")
  c <- comps[comps$ref == "c", ]
  expect_identical(c$license_spdx, "MIT")
  expect_identical(c$license_as_written, "MIT + file LICENSE")
  expect_identical(c$ecosystem, "bioconductor")
  expect_identical(c$version_is, NA_character_)
  # The root takes the metadata's supplier and manufacturer.
  app <- comps[comps$is_root, ]
  expect_identical(app$type, "application")
  expect_identical(app$supplier_name, "Sup Inc")
  expect_identical(app$supplier_url, "https://sup.example")
  expect_identical(app$maintainer, "Maker Ltd")
  # The URL that is not one and the checksum that is too short are counted.
  expect_identical(issues_with(x, "read-values-dropped")$message, paste0(
    "2 values were not kept because sbom's formats cannot carry them (URLs that are not valid IRI ",
    "references and checksums of algorithms or lengths sbom does not write)."
  ))
  expect_identical(issues_with(x, "read-values-dropped")$severity, "info")
  expect_valid_in_every_format(x, "CycloneDX columns")
})

test_that("URLs lose their credentials, query and fragment, and local paths are dropped", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"component":{"type":"application","bom-ref":"app","name":"app",',
    '"supplier":{"name":"S","url":["https://user:pw@s.example/x?token=1"]},',
    '"externalReferences":[{"type":"vcs","url":"https://user:ghp_SECRET@github.com/o/r.git?ref=main#readme"},',
    '{"type":"distribution","url":"file:///home/alice/build/root.tgz"},',
    '{"type":"website","url":"/home/alice/site/index.html"}]}}}\n'
  ), ".cdx.json")
  app <- x$components
  expect_identical(app$vcs_url, "https://github.com/o/r.git")
  expect_identical(app$supplier_url, "https://s.example/x")
  expect_identical(app$download_location, NA_character_)
  expect_identical(app$homepage, NA_character_)
  expect_identical(issues_with(x, "read-values-dropped")$message, paste0(
    "2 values were not kept because sbom's formats cannot carry them (local paths)."
  ))
  out <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, out)
  expect_false(any(grepl("SECRET|token|alice", readLines(out))))
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"one",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},"documentDescribes":["SPDXRef-a"],',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","downloadLocation":"C:\\\\build\\\\a.zip",',
    '"externalRefs":[{"referenceCategory":"OTHER","referenceType":"doi","referenceLocator":"10.1/a b"}]}]}\n'
  ), ".spdx.json")
  expect_identical(x$components$download_location, NA_character_)
  expect_identical(x$components$doi, NA_character_)
  expect_identical(issues_with(x, "read-values-dropped")$message, paste0(
    "2 values were not kept because sbom's formats cannot carry them (DOIs that cannot form a valid URL ",
    "and local paths)."
  ))
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"one",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},"documentDescribes":["SPDXRef-a"],',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","homepage":"./docs"}]}\n'
  ), ".spdx.json")
  expect_identical(issues_with(x, "read-values-dropped")$message, paste0(
    "1 value was not kept because sbom's formats cannot carry it (local paths)."
  ))
})

test_that("SPDX relationship types map to fields, and swapped ones point from the dependent", {
  pkg <- function(id, name) {
    sprintf(
      '{"SPDXID":"%s","name":"%s","versionInfo":"1","downloadLocation":"NOASSERTION","filesAnalyzed":false}',
      id, name
    )
  }
  rel <- function(from, type, to, comment = NULL) {
    sprintf(
      '{"spdxElementId":"%s","relationshipType":"%s","relatedSpdxElement":"%s"%s}',
      from, type, to, if (is.null(comment)) "" else sprintf(',"comment":"%s"', comment)
    )
  }
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"rels",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: other-2.0"]},',
    '"externalDocumentRefs":[{"externalDocumentId":"DocumentRef-ext","spdxDocument":"https://x.example/d",',
    '"checksum":{"algorithm":"SHA1","checksumValue":"', strrep("0", 40), '"}}],',
    '"packages":[', paste(
      pkg("SPDXRef-root", "root"), pkg("SPDXRef-a", "a"), pkg("SPDXRef-b", "b"), pkg("SPDXRef-c", "c"),
      pkg("SPDXRef-d", "d"), pkg("SPDXRef-e", "e"), pkg("SPDXRef-f", "f"), pkg("SPDXRef-g", "g"),
      pkg("SPDXRef-h", "h"),
      sep = ","
    ), "],",
    '"relationships":[', paste(
      rel("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-root"),
      rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-a", "Imports: a (>= 1.0)"),
      rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-b", "Not a field comment"),
      rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-f", "SystemRequirements: f"),
      rel("SPDXRef-c", "OPTIONAL_DEPENDENCY_OF", "SPDXRef-root", "Suggests: c"),
      rel("SPDXRef-d", "OPTIONAL_DEPENDENCY_OF", "SPDXRef-root"),
      rel("SPDXRef-e", "BUILD_DEPENDENCY_OF", "SPDXRef-a"),
      rel("SPDXRef-a", "DEPENDENCY_OF", "SPDXRef-b"),
      rel("SPDXRef-root", "DYNAMIC_LINK", "SPDXRef-e"),
      rel("SPDXRef-root", "CONTAINS", "SPDXRef-f"),
      rel("SPDXRef-a", "OTHER", "SPDXRef-b"),
      rel("SPDXRef-a", "VARIANT_OF", "SPDXRef-c"),
      rel("SPDXRef-a", "DEPENDS_ON", "NONE"),
      rel("SPDXRef-b", "DEPENDS_ON", "NOASSERTION"),
      rel("SPDXRef-b", "DEPENDS_ON", "DocumentRef-ext:SPDXRef-x"),
      rel("SPDXRef-b", "DEPENDS_ON", "SPDXRef-missing"),
      # c is suggested by the root and imported by a, so it is required.
      rel("SPDXRef-a", "DEPENDS_ON", "SPDXRef-c", "Imports: c"),
      # Only the fields the writers put in a comment are read from one.
      rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-g", "Note: pinned by ops"),
      rel("SPDXRef-root", "DEPENDS_ON", "SPDXRef-h", "contains: h"),
      rel("SPDXRef-a", "DEPENDS_ON", "SPDXRef-h", "Suggests: h"),
      # g states that it depends on nothing.
      rel("SPDXRef-g", "DEPENDS_ON", "NONE"),
      sep = ","
    ), "]}\n"
  ), ".spdx.json")
  comps <- x$components
  name_of <- function(ref) comps$name[match(ref, comps$ref)]
  rel <- x$relationships
  expect_identical(
    paste(name_of(rel$from), name_of(rel$to), rel$field, rel$spec),
    c(
      "a c Imports c", "a e build_dependency_of NA", "a h depends_on NA", "b a dependency_of NA",
      "root a Imports a (>= 1.0)", "root b depends_on NA", "root c Suggests c", "root d optional NA",
      "root e dynamic_link NA", "root f contains NA", "root f system_requirement f", "root g depends_on NA",
      "root h depends_on NA"
    )
  )
  expect_identical(unique(rel$evidence), "declared")
  expect_identical(
    comps$scope[match(c("c", "d", "a", "h"), comps$name)], c("required", "optional", "required", "required")
  )
  expect_identical(comps$parent_ref[match(c("f", "h"), comps$name)], c("SPDXRef-root", NA))
  # a, b and the root depend on something, and g states that it depends on nothing.
  expect_identical(
    comps$deps_known[match(c("a", "b", "c", "d", "e", "f", "g", "h", "root"), comps$name)],
    c(TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, TRUE)
  )
  expect_identical(issues_with(x, "read-relationships-skipped")$message, paste0(
    "2 relationships of types sbom does not model (OTHER and VARIANT_OF) were not read."
  ))
  expect_identical(issues_with(x, "read-relationships-skipped")$severity, "info")
  # NONE, NOASSERTION and another document's elements are not dangling.
  expect_identical(issues_with(x, "read-dangling-relationships")$message, paste0(
    "1 relationship names an element that is not a component of the document, so it was not read."
  ))
  expect_identical(issues_with(x, "read-dangling-relationships")$severity, "warning")
  expect_valid_in_every_format(x, "SPDX relationships")
})

test_that("lists taken from the document name at most 20 items, and one type is singular", {
  read_types <- function(types) {
    rels <- sprintf(
      '{"spdxElementId":"SPDXRef-a","relationshipType":"%s","relatedSpdxElement":"SPDXRef-b"}', types
    )
    x <- read_text(paste0(
      '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"types",',
      '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},"documentDescribes":["SPDXRef-a"],',
      '"packages":[{"SPDXID":"SPDXRef-a","name":"a"},{"SPDXID":"SPDXRef-b","name":"b"}],',
      '"relationships":[', paste(rels, collapse = ","), "]}\n"
    ), ".spdx.json")
    issues_with(x, "read-relationships-skipped")$message
  }
  types <- sprintf("T%02d", 1:22)
  expect_identical(read_types(types), paste0(
    "22 relationships of types sbom does not model (", paste(types[1:20], collapse = ", "),
    ", and 2 more) were not read."
  ))
  expect_identical(
    read_types(c("OTHER", "OTHER")), "2 relationships of a type sbom does not model (OTHER) were not read."
  )
})

test_that("SPDX 3 packages map their values, agents and relationships", {
  x <- read_text(paste0(
    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[',
    '{"type":"CreationInfo","@id":"_:ci","specVersion":"3.0.1","created":"2026-03-04T05:06:07Z",',
    '"createdBy":["urn:pat","urn:org"],"createdUsing":["urn:tool"]},',
    '{"type":"Person","spdxId":"urn:pat","name":"Pat Doe (pat@example.org)","creationInfo":"_:ci"},',
    '{"type":"Organization","spdxId":"urn:org","name":"Org","creationInfo":"_:ci"},',
    '{"type":"Tool","spdxId":"urn:tool","name":"sbom 0.1.0","creationInfo":"_:ci"},',
    '{"type":"software_Package","spdxId":"urn:root","name":"root","software_packageVersion":"1.0",',
    '"creationInfo":"_:ci","software_primaryPurpose":"application","originatedBy":["urn:org","urn:pat"],',
    '"suppliedBy":"urn:org","software_homePage":"https://root.example","releaseTime":"2025-01-02T00:00:00Z",',
    '"software_downloadLocation":"https://dl.example/root.tgz","description":"The root.",',
    '"externalRef":[{"type":"ExternalRef","externalRefType":"vcs","locator":["https://git.example/root"]}],',
    '"externalIdentifier":[{"type":"ExternalIdentifier","externalIdentifierType":"other","identifier":"10.5/r",',
    '"comment":"DOI"}],"verifiedUsing":[{"type":"Hash","algorithm":"sha256","hashValue":"', strrep("e", 64), '"},',
    '{"type":"Hash","algorithm":"sha3_384","hashValue":"', strrep("f", 96), '"}]},',
    '{"type":"software_Package","spdxId":"urn:lib","name":"lib","creationInfo":"_:ci",',
    '"software_packageUrl":"pkg:npm/lib@2.0","software_packageVersion":"2.0","software_primaryPurpose":"platform"},',
    '{"type":"software_Package","spdxId":"urn:opt","name":"opt","creationInfo":"_:ci"},',
    '{"type":"simplelicensing_LicenseExpression","spdxId":"urn:lic","creationInfo":"_:ci",',
    '"simplelicensing_licenseExpression":"Apache-2.0"},',
    '{"type":"Relationship","spdxId":"urn:r1","creationInfo":"_:ci","from":"urn:root",',
    '"relationshipType":"hasDeclaredLicense","to":["urn:lic"]},',
    '{"type":"LifecycleScopedRelationship","spdxId":"urn:r2","creationInfo":"_:ci","from":"urn:root",',
    '"relationshipType":"dependsOn","to":["urn:lib"],"scope":"build","comment":"LinkingTo: lib"},',
    '{"type":"Relationship","spdxId":"urn:r3","creationInfo":"_:ci","from":"urn:root",',
    '"relationshipType":"hasOptionalDependency","to":["urn:opt"]},',
    '{"type":"Relationship","spdxId":"urn:r4","creationInfo":"_:ci","from":"urn:root",',
    '"relationshipType":"describes","to":["urn:lib"]},',
    '{"type":"software_Sbom","spdxId":"urn:sbom","creationInfo":"_:ci","rootElement":["urn:root"]},',
    '{"type":"SpdxDocument","spdxId":"urn:doc","creationInfo":"_:ci","name":"three","comment":"A note.",',
    '"rootElement":["urn:sbom"]}]}\n'
  ), ".spdx3.json")
  comps <- x$components
  root <- comps[comps$ref == "urn:root", ]
  expect_true(root$is_root)
  expect_identical(root$type, "application")
  expect_identical(root$supplier_name, "Org")
  expect_identical(root$maintainer, "Pat Doe (pat@example.org)")
  expect_identical(root$license_spdx, "Apache-2.0")
  expect_identical(root$homepage, "https://root.example")
  expect_identical(root$download_location, "https://dl.example/root.tgz")
  expect_identical(root$vcs_url, "https://git.example/root")
  expect_identical(root$doi, "10.5/r")
  expect_identical(root$description, "The root.")
  expect_identical(root$published, "2025-01-02")
  expect_identical(root$hashes[[1]]$alg, c("SHA-256", "SHA3-384"))
  expect_identical(comps$type[comps$ref == "urn:lib"], "platform")
  expect_identical(comps$ecosystem[comps$ref == "urn:lib"], "npm")
  expect_identical(comps$scope[comps$ref == "urn:opt"], "optional")
  expect_identical(
    x$relationships[c("from", "to", "field", "spec")],
    data.frame(
      from = "urn:root", to = c("urn:lib", "urn:opt"), field = c("LinkingTo", "optional"),
      spec = c("lib", NA), stringsAsFactors = FALSE
    )
  )
  expect_identical(issues_with(x, "read-relationships-skipped")$message, paste0(
    "1 relationship of a type sbom does not model (describes) was not read."
  ))
  meta <- x$metadata
  expect_identical(meta$author, "Pat Doe")
  expect_identical(meta$organization, "Org")
  expect_identical(meta$tool_version, "0.1.0")
  expect_identical(meta$notes, c("Read from doc.spdx3.json (SPDX 3 JSON-LD 3.0.1).", "A note."))
  expect_valid_in_every_format(x, "SPDX 3 columns")
  # SHA3 is written in SPDX 3's spelling, and reads back.
  out <- withr::local_tempfile(fileext = ".spdx3.jsonld")
  write_sbom(x, out)
  expect_true(any(grepl('"sha3_384"', readLines(out), fixed = TRUE)))
  expect_identical(read_sbom(out)$components$hashes[[match("root", comps$name)]], root$hashes[[1]])
})

test_that("a SWID tag maps its entities, links and Meta", {
  x <- read_text(paste0(
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ',
    'xmlns:sbom="https://cran.r-project.org/package=sbom" name="tool" version="1.2" tagId="example.org/tool">',
    '<Entity name="Org" regid="https://example.org" role="tagCreator"/>',
    '<Entity name="Dist" regid="https://dist.example" role="distributor"/>',
    '<Entity name="Max" role="maintainer"/>',
    '<Meta generator="sbom 0.2.0" description="A tag note." sbom:purl="pkg:cran/tool@1.2" ',
    'sbom:license="MIT + file LICENSE" sbom:systemRequirements="pandoc"/>',
    '<Link rel="describedby" href="https://tool.example"/>',
    '<Link rel="installationmedia" href="https://dl.example/tool_1.2.tar.gz" artifact="tool_1.2.tar.gz"/>',
    '<Link rel="related" href="https://git.example/tool"/>',
    '<Link rel="requires" href="swid:example.org/R" use="required" sbom:name="R" sbom:version="4.1" ',
    'sbom:versionIs="minimum"/>',
    '<Link rel="requires" href="swid:example.org/opt" use="optional" sbom:name="opt"/>',
    "</SoftwareIdentity>\n"
  ), ".swidtag")
  comps <- x$components
  root <- comps[comps$is_root, ]
  # The regid's authority, which the writer puts before each ref, is not part of it.
  expect_identical(root$ref, "tool")
  expect_identical(root$type, "application")
  expect_identical(root$purl, "pkg:cran/tool@1.2")
  expect_identical(root$ecosystem, "cran")
  expect_identical(root$supplier_name, "Dist")
  expect_identical(root$supplier_url, "https://dist.example")
  expect_identical(root$maintainer, "Max")
  expect_identical(root$license_as_written, "MIT + file LICENSE")
  expect_identical(root$license_spdx, NA_character_)
  expect_identical(root$homepage, "https://tool.example")
  expect_identical(root$download_location, "https://dl.example/tool_1.2.tar.gz")
  expect_identical(root$package_file_name, "tool_1.2.tar.gz")
  expect_identical(root$vcs_url, "https://git.example/tool")
  expect_identical(root$system_requirements, "pandoc")
  expect_identical(root$deps_known, TRUE)
  links <- comps[!comps$is_root, ]
  expect_identical(links$ref, c("R", "opt"))
  expect_identical(links$type, c("library", "library"))
  expect_identical(links$version_is, c("minimum", NA))
  expect_identical(links$scope, c("required", "optional"))
  expect_identical(links$deps_known, c(FALSE, FALSE))
  expect_identical(x$relationships$field, c("depends_on", "depends_on"))
  meta <- x$metadata
  expect_identical(meta$regid, "https://example.org")
  expect_identical(meta$organization, "Org")
  expect_identical(meta$tool_version, "0.2.0")
  expect_identical(meta$notes, c(
    "Read from doc.swidtag (SWID tag 2015).", "A tag note.",
    "The document has no timestamp, so the time it was read is used."
  ))
  expect_valid_in_every_format(x, "SWID columns")
})

test_that("a SWID tag written from a read tag reads back with the same refs", {
  for (regid in list(NULL, "https://example.org")) {
    x <- fixture_sbom()
    x$metadata$regid <- if (is.null(regid)) NA_character_ else regid
    path <- withr::local_tempfile(fileext = ".swidtag")
    write_sbom(x, path)
    y <- read_sbom(path)
    expect_identical(y$metadata$root, x$metadata$root)
    linked <- x$components$ref[!is_embedded_ref(x$components$ref)]
    expect_setequal(y$components$ref, linked)
    write_sbom(y, path)
    expect_identical(read_sbom(path)$components$ref, y$components$ref)
  }
})

test_that("a SWID tag creator is the organization only with a real regid", {
  read_swid <- function(author = NA_character_, organization = NA_character_, regid = NA_character_) {
    x <- minimal_sbom()
    x$metadata[c("author", "organization", "regid")] <- list(author, organization, regid)
    path <- withr::local_tempfile(fileext = ".swidtag", .local_envir = parent.frame())
    write_sbom(x, path)
    read_sbom(path)$metadata[c("author", "organization", "regid")]
  }
  expect_identical(
    read_swid(author = "Pat"),
    list(author = "Pat", organization = NA_character_, regid = NA_character_)
  )
  expect_identical(
    read_swid(organization = "Org", regid = "https://example.org"),
    list(author = NA_character_, organization = "Org", regid = "https://example.org")
  )
  # Without either, the tag creator is sbom itself, the tool.
  expect_identical(read_swid(), list(author = NA_character_, organization = NA_character_, regid = NA_character_))
})

test_that("a read SBOM without a tool version writes the SWID generator sbom", {
  x <- read_sbom(tp("spdx-3", "package_sbom.json"))
  expect_identical(x$metadata$tool_version, NA_character_)
  path <- withr::local_tempfile(fileext = ".swidtag")
  write_sbom(x, path)
  meta <- xml2::xml_find_first(xml2::read_xml(path), "//*[local-name() = 'Meta']")
  expect_identical(xml2::xml_attr(meta, "generator"), "sbom")
})

test_that("a package both suggested and imported is required", {
  x <- fixture_sbom()
  x$relationships <- rbind(x$relationships, data.frame(
    from = "pkg:cran/cranpkg@1.2.0", to = "pkg:cran/suggestpkg@2.0.0", field = "Imports",
    spec = "suggestpkg", evidence = "declared"
  ))
  x$components$scope[x$components$name == "suggestpkg"] <- "required"
  for (format in c("spdx-json", "spdx3-jsonld", "cyclonedx-json")) {
    path <- withr::local_tempfile(fileext = ".json")
    write_sbom(x, path, format = format)
    comps <- read_sbom(path)$components
    expect_identical(comps$scope[comps$name == "suggestpkg"], "required", label = format)
  }
})

test_that("an optional dependency stays optional through SPDX 2 and SPDX 3", {
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"opt",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},"documentDescribes":["SPDXRef-a"],',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a"},{"SPDXID":"SPDXRef-b","name":"b"}],',
    '"relationships":[{"spdxElementId":"SPDXRef-b","relationshipType":"OPTIONAL_DEPENDENCY_OF",',
    '"relatedSpdxElement":"SPDXRef-a"}]}\n'
  ), ".spdx.json")
  expect_identical(x$relationships$field, "optional")
  for (format in c("spdx-json", "spdx-tv", "spdx3-jsonld")) {
    path <- withr::local_tempfile(fileext = ".spdx")
    write_sbom(x, path, format = format)
    y <- read_sbom(path)
    expect_identical(y$relationships[c("field", "spec")], data.frame(field = "optional", spec = NA_character_), label = format)
    expect_identical(y$components$scope[y$components$name == "b"], "optional", label = format)
  }
})

test_that("a read SBOM keeps every dependency when written as CycloneDX", {
  # The library root contains every package, so each has it as its parent.
  x <- sbom_installed(c("cranpkg", "localpkg", "suggestpkg"), lib = fixture_lib(), author = "A")
  edges <- function(x) name_edges(as_kinds(x), "field")
  for (format in c("spdx-json", "spdx3-jsonld")) {
    path <- withr::local_tempfile(fileext = ".json")
    write_sbom(x, path, format = format)
    y <- read_sbom(path)
    out <- withr::local_tempfile(fileext = ".cdx.json")
    write_sbom(y, out)
    z <- read_sbom(out)
    if (format == "spdx-json") {
      packages <- y$components$name %in% c("cranpkg", "localpkg", "suggestpkg")
      expect_identical(unique(y$components$parent_ref[packages]), y$metadata$root)
      expect_identical(edges(z), edges(y))
    } else {
      # SPDX 3 sets no parents, so CycloneDX keeps only its dependencies.
      depends <- function(e) e[!grepl(" contains$", e)]
      expect_identical(depends(edges(z)), depends(edges(y)))
    }
    expect_true("cranpkg -> methods depends_on" %in% edges(z), label = format)
  }
  # A nested component with dependencies of its own keeps them.
  y <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[{"type":"library","bom-ref":"a","name":"a","components":[',
    '{"type":"library","bom-ref":"b","name":"b"}]},{"type":"library","bom-ref":"c","name":"c"}],',
    '"dependencies":[{"ref":"app","dependsOn":["a"]},{"ref":"b","dependsOn":["c"]}]}\n'
  ), ".cdx.json")
  out <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(y, out)
  expect_identical(edges(read_sbom(out)), edges(y))
  expect_true("b -> c depends_on" %in% edges(y))
})

test_that("duplicate ids are renamed, and refs fall back to the purl and name@version", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"component":{"type":"application","bom-ref":"a","name":"root"}},',
    '"components":[{"type":"library","bom-ref":"a","name":"x"},{"type":"library","bom-ref":"a-2","name":"y"},',
    '{"type":"library","bom-ref":"a","name":"z"},{"type":"library","name":"p","version":"1","purl":"pkg:npm/p@1"},',
    '{"type":"library","name":"q","version":"2"},{"type":"library","bom-ref":"","name":"r"}],',
    '"dependencies":[{"ref":"a","dependsOn":["a-2"]}]}\n'
  ), ".cdx.json")
  comps <- x$components
  expect_identical(comps$ref, c("a", "a-2", "a-3", "a-4", "component-7", "pkg:npm/p@1", "q@2"))
  expect_identical(comps$name[match(c("a", "a-3", "a-4"), comps$ref)], c("root", "x", "z"))
  expect_identical(x$metadata$root, "a")
  issue <- issues_with(x, "read-duplicate-id")
  expect_identical(issue$message, "3 elements share the id a, so sbom renamed the later ones a-3 and a-4.")
  expect_identical(issue$severity, "warning")
  # Relationships name the first element with an id.
  expect_identical(x$relationships$from, "a")
  expect_identical(comps$deps_known[match(c("a", "a-3"), comps$ref)], c(TRUE, FALSE))
})

test_that("renaming duplicates takes linear time, and its message names at most 20 refs", {
  skip_on_cran()
  n <- 3000L
  ids <- c(rep("a", n), paste0("a-", seq(2L, n + 1L)))
  path <- withr::local_tempfile(fileext = ".cdx.json")
  write_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[',
    paste0('{"type":"library","bom-ref":"', ids, '","name":"c"}', collapse = ","), "]}\n"
  ), path)
  d <- read_document(path)
  t <- document_tables(d)
  x <- NULL
  expect_lt(system.time(x <- read_sbom_build(d, t))[["elapsed"]], 1)
  # The renamed ones start after the highest suffix taken, a-3001.
  renamed <- paste0("a-", seq(n + 2L, 2L * n))
  expect_setequal(x$components$ref, c("a", ids[-(1:n)], renamed, "document"))
  expect_identical(issues_with(x, "read-duplicate-id")$message, paste0(
    "3000 elements share the id a, so sbom renamed the later ones ", paste(renamed[1:20], collapse = ", "),
    ", and 2979 more."
  ))
})

test_that("two elements that share an id give one renamed ref", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[{"type":"library","bom-ref":"b","name":"b"},{"type":"library","bom-ref":"b","name":"c"}]}\n'
  ), ".cdx.json")
  expect_identical(
    issues_with(x, "read-duplicate-id")$message, "2 elements share the id b, so sbom renamed the later one b-2."
  )
})

test_that("a document without a root gets a placeholder root", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"components":[{"type":"library","bom-ref":"a","name":"a","version":"1"}]}\n'
  ), ".cdx.json", name = "rootless")
  root <- x$components[x$components$is_root, ]
  expect_identical(root$ref, "document")
  expect_identical(x$metadata$root, "document")
  expect_identical(root$name, "rootless.cdx.json")
  expect_identical(root$type, "application")
  expect_identical(root$evidence, "unknown")
  expect_identical(root$ecosystem, "unknown")
  issue <- issues_with(x, "read-no-root")
  expect_identical(
    issue$message,
    "The document names no root component, so sbom added a placeholder root with the ref document."
  )
  expect_identical(issue$severity, "warning")
  expect_identical(x$metadata$notes[2], "The document has no timestamp, so the time it was read is used.")
  expect_valid_in_every_format(x, "placeholder root")
  # CycloneDX does not claim that the placeholder depends on nothing.
  out <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, out)
  deps <- jsonlite::fromJSON(out, simplifyVector = FALSE)$dependencies
  expect_false("document" %in% vapply(deps, function(d) d$ref, character(1)))

  # An SPDX document names it after itself.
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"named-doc",',
    '"creationInfo":{"created":"not a time","creators":["Tool: x"]},',
    '"packages":[{"SPDXID":"SPDXRef-a","name":"a","downloadLocation":"NONE"}]}\n'
  ), ".spdx.json")
  expect_identical(x$components$name[x$components$is_root], "named-doc")
  expect_identical(x$metadata$notes[2], "The document has no timestamp, so the time it was read is used.")
})

test_that("several roots keep the first in id order, and files and snippets are counted", {
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"two",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},',
    '"documentDescribes":["SPDXRef-z","SPDXRef-b","SPDXRef-file"],',
    '"packages":[{"SPDXID":"SPDXRef-z","name":"z"},{"SPDXID":"SPDXRef-b","name":"b"}],',
    '"files":[{"SPDXID":"SPDXRef-file","fileName":"./f.c"}]}\n'
  ), ".spdx.json")
  expect_identical(x$metadata$root, "SPDXRef-b")
  expect_identical(x$components$is_root, c(TRUE, FALSE))
  issue <- issues_with(x, "read-several-roots")
  expect_identical(
    issue$message,
    "The document has 2 root components, so sbom took SPDXRef-b, the first in id order, as the root."
  )
  expect_identical(issue$severity, "info")
  issue <- issues_with(x, "read-files-skipped")
  expect_identical(issue$message, "1 file or snippet in the document is not a component, so it is not listed.")
  expect_identical(issue$severity, "info")

  x <- read_sbom(tp("spdx-2.3", "SPDXJSONExample-v2.3.spdx.json"))
  expect_identical(
    issues_with(x, "read-files-skipped")$message,
    "6 files and snippets in the document are not components, so they are not listed."
  )
  # Its file root is not a component, so the package is the only root.
  expect_identical(nrow(issues_with(x, "read-several-roots")), 0L)
})

test_that("a component in a cycle of parents is not nested", {
  pkg <- function(id) sprintf('{"SPDXID":"%s","name":"%s"}', id, id)
  rel <- function(from, to) {
    sprintf('{"spdxElementId":"%s","relationshipType":"CONTAINS","relatedSpdxElement":"%s"}', from, to)
  }
  x <- read_text(paste0(
    '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"cycle",',
    '"creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: x"]},',
    '"documentDescribes":["SPDXRef-r"],"packages":[',
    paste(pkg("SPDXRef-r"), pkg("SPDXRef-a"), pkg("SPDXRef-b"), pkg("SPDXRef-c"), sep = ","), "],",
    '"relationships":[', paste(
      rel("SPDXRef-r", "SPDXRef-a"), rel("SPDXRef-a", "SPDXRef-r"), rel("SPDXRef-b", "SPDXRef-c"),
      rel("SPDXRef-c", "SPDXRef-b"), sep = ","
    ), "]}\n"
  ), ".spdx.json")
  comps <- x$components
  expect_identical(comps$parent_ref[match(c("SPDXRef-r", "SPDXRef-a"), comps$ref)], c(NA, "SPDXRef-r"))
  expect_identical(comps$parent_ref[match(c("SPDXRef-b", "SPDXRef-c"), comps$ref)], c(NA_character_, NA_character_))
  expect_valid_in_every_format(x, "cycle")
})

test_that("values of the wrong type are absent, and a component without a name is unknown", {
  x <- read_text(paste0(
    '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,',
    '"metadata":{"timestamp":5,"component":{"type":"application","bom-ref":"app","name":"app"}},',
    '"components":[{"type":7,"bom-ref":"a","name":["x"],"version":"","purl":3,"publisher":{"a":1},',
    '"supplier":{"name":"S","url":"https://not-an-array.example"},"description":[1],',
    '"externalReferences":[{"type":"website","url":["https://x.example"]},"junk"],',
    '"hashes":"junk","properties":[{"name":"sbom:evidence","value":5},"junk"]}]}\n'
  ), ".cdx.json")
  a <- x$components[x$components$ref == "a", ]
  expect_identical(a$name, "unknown")
  expect_identical(a$type, "library")
  expect_identical(a$version, NA_character_)
  expect_identical(a$version_is, NA_character_)
  expect_identical(a$purl, NA_character_)
  expect_identical(a$ecosystem, "unknown")
  expect_identical(a$supplier_url, NA_character_)
  expect_identical(a$maintainer, NA_character_)
  expect_identical(a$description, NA_character_)
  expect_identical(a$homepage, NA_character_)
  expect_identical(nrow(a$hashes[[1]]), 0L)
  expect_identical(a$evidence, "declared")
  expect_identical(x$metadata$notes[2], "The document has no timestamp, so the time it was read is used.")
})

test_that("a file that is not an SBOM is a read error", {
  expect_error(read_sbom(test_path("fixtures", "renv", "modern", "renv.lock")), class = "sbom_read_error")
  path <- withr::local_tempfile(fileext = ".json")
  write_text('{"name": "not-an-sbom"}\n', path)
  cnd <- expect_error(read_sbom(path), class = "sbom_read_error")
  expect_identical(cnd$sentence, paste0(basename(path), " is not an SBOM in a format sbom reads."))
  expect_error(read_sbom(path, format = "csv"), "CSV inventory")
})

test_that("without a timestamp, the time in SOURCE_DATE_EPOCH is used when it is set", {
  withr::local_envvar(SOURCE_DATE_EPOCH = "86400")
  x <- read_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}\n', ".cdx.json")
  expect_identical(x$metadata$timestamp, as.POSIXct("1970-01-02", tz = "UTC"))
  expect_identical(
    x$metadata$notes[2], "The document has no timestamp, so the time in SOURCE_DATE_EPOCH is used."
  )
})

test_that("timestamps are read as ISO 8601 in UTC", {
  utc <- function(x) as.POSIXct(x, tz = "UTC")
  expect_identical(read_timestamp("2026-01-01T00:30:00-05:30"), utc("2026-01-01 06:00:00"))
  expect_identical(read_timestamp("2026-01-01T10:00:00.123+01"), utc("2026-01-01 09:00:00"))
  expect_identical(read_timestamp("2026-01-01T10:00:00Z"), utc("2026-01-01 10:00:00"))
  expect_null(read_timestamp("2026-01-01"))
  expect_null(read_timestamp("2026-13-01T00:00:00Z"))
  expect_null(read_timestamp(NA_character_))
})
