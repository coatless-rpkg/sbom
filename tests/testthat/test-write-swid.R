swid_ns <- c(s = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd")

test_that("the SWID tag follows R Observatory's layout", {
  x <- fixture_sbom()
  doc <- xml2::read_xml(swid_tag(x)); root <- xml2::xml_root(doc)
  expect_equal(xml2::xml_attr(root, "tagId"), "local/srcpkg")
  expect_equal(xml2::xml_attr(root, "tagVersion"), "20261104")
  expect_equal(xml2::xml_attr(root, "versionScheme"), "multipartnumeric")
  ent <- xml2::xml_find_all(doc, "//s:Entity", swid_ns)
  expect_equal(xml2::xml_attr(ent, "role"), c("tagCreator", "maintainer"))
  expect_equal(xml2::xml_attr(ent[[1]], "name"), "Test Org")
  expect_equal(xml2::xml_attr(ent[[1]], "regid"), "http://invalid.unavailable")
  req <- xml2::xml_find_all(doc, "//s:Link[@rel='requires']", swid_ns)
  hrefs <- xml2::xml_attr(req, "href")
  expect_true("swid:pkg:cran/cranpkg@1.2.0" %in% hrefs)
  expect_equal(xml2::xml_attr(req[hrefs == "swid:pkg:cran/suggestpkg@2.0.0"], "use"), "optional")
  expect_equal(xml2::xml_attr(req[hrefs == "swid:pkg:cran/cranpkg@1.2.0"], "use"), "required")
  expect_true("regid-missing" %in% sbom_issues(x)$code)
})

test_that("the tag starts with the XML declaration and ends with one newline", {
  txt <- swid_tag(fixture_sbom())
  expect_match(txt, "^<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>\n<SoftwareIdentity ")
  expect_match(txt, "\n  <Entity ")
  expect_match(txt, "</SoftwareIdentity>\n$")
  expect_false(grepl("\n\n", txt))
  expect_false(grepl("\r", txt, fixed = TRUE))
})

test_that("a regid given as an option reaches the tag and clears the issue", {
  withr::local_options(sbom.regid = "https://example.org")
  x <- fixture_sbom()
  ent <- xml2::xml_find_first(xml2::read_xml(swid_tag(x)), "//s:Entity[@role='tagCreator']", swid_ns)
  expect_equal(xml2::xml_attr(ent, "regid"), "https://example.org")
  expect_equal(x$metadata$regid, "https://example.org")
  expect_false("regid-missing" %in% sbom_issues(x)$code)
})

test_that("regid-missing is an info issue on the root, and only with an organization", {
  x <- fixture_sbom()
  iss <- sbom_issues(x)
  i <- iss[iss$code == "regid-missing", ]
  expect_equal(i$severity, "info")
  expect_equal(i$ref, x$metadata$root)
  expect_equal(i$field, "regid")
  expect_equal(i$message, "No regid was given for Test Org, so a SWID tag names it with the placeholder http://invalid.unavailable.")
  expect_true(i$message %in% document_notes(x))
  y <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib())
  expect_false("regid-missing" %in% sbom_issues(y)$code)
  z <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), regid = "https://example.org")
  expect_false("regid-missing" %in% sbom_issues(z)$code)
  expect_equal(z$metadata$regid, "https://example.org")
  expect_true(is.na(y$metadata$regid))
  lib <- sbom_installed(lib = fixture_lib(), organization = "Org", regid = "https://org.example")
  expect_equal(lib$metadata$regid, "https://org.example")
  expect_false("regid-missing" %in% sbom_issues(lib)$code)
})

test_that("with a regid, tagId and requires targets start with its authority", {
  for (regid in c("https://example.org", "https://example.org/", "example.org")) {
    x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(),
                      organization = "Org", regid = regid)
    doc <- xml2::read_xml(swid_tag(x))
    expect_equal(xml2::xml_attr(xml2::xml_root(doc), "tagId"), "example.org/local/srcpkg", label = regid)
    hrefs <- xml2::xml_attr(xml2::xml_find_all(doc, "//s:Link[@rel='requires']", swid_ns), "href")
    expect_true("swid:example.org/pkg:cran/cranpkg@1.2.0" %in% hrefs, label = regid)
    expect_true(all(startsWith(hrefs, "swid:example.org/")), label = regid)
  }
  lib <- sbom_installed(lib = fixture_lib(), organization = "Org", regid = "https://example.org/sw/")
  expect_equal(xml2::xml_attr(xml2::xml_root(xml2::read_xml(swid_tag(lib))), "tagId"), "example.org/sw/r-library")
  for (y in list(x, lib)) {
    tf <- withr::local_tempfile(fileext = ".swidtag"); write_text(swid_tag(y), tf)
    expect_equal(schema_validate(tf, "swid", "2015")$status, "partial")
  }
})

test_that("tagVersion is the timestamp's UTC date as YYYYMMDD", {
  x <- fixture_sbom()
  root <- xml2::xml_root(xml2::read_xml(swid_tag(x)))
  expect_equal(xml2::xml_attr(root, "tagVersion"), format(x$metadata$timestamp, "%Y%m%d", tz = "UTC"))
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  y <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib())
  expect_equal(xml2::xml_attr(xml2::xml_root(xml2::read_xml(swid_tag(y))), "tagVersion"), "20231114")
})

test_that("regid must be a single string, and a blank one means none", {
  build <- function(regid) {
    sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(),
                 organization = "Org", regid = regid)
  }
  expect_error(build(c("https://a.example", "https://b.example")), "single string")
  expect_error(build(character()), "single string")
  expect_error(build(1), "single string")
  expect_error(sbom_installed(lib = fixture_lib(), regid = c("a", "b")), "single string")
  for (none in list(NULL, NA, NA_character_, "", "   ")) {
    x <- build(none)
    expect_true(is.na(x$metadata$regid))
    expect_true("regid-missing" %in% sbom_issues(x)$code)
    ent <- xml2::xml_find_first(xml2::read_xml(swid_tag(x)), "//s:Entity[@role='tagCreator']", swid_ns)
    expect_equal(xml2::xml_attr(ent, "regid"), "http://invalid.unavailable")
  }
})

test_that("the tag creator falls back to the first author, then to sbom", {
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), author = c("Ann", "Bob"))
  ent <- xml2::xml_find_first(xml2::read_xml(swid_tag(x)), "//s:Entity[@role='tagCreator']", swid_ns)
  expect_equal(xml2::xml_attr(ent, "name"), "Ann")
  y <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib())
  ent <- xml2::xml_find_first(xml2::read_xml(swid_tag(y)), "//s:Entity[@role='tagCreator']", swid_ns)
  expect_equal(xml2::xml_attr(ent, "name"), "sbom")
  expect_equal(xml2::xml_attr(ent, "regid"), "http://invalid.unavailable")
})

test_that("SWID escapes &, < and quotes in names", {
  x <- fixture_sbom()
  x$components$maintainer[x$components$is_root] <- 'A & B <c> "d"'
  ent <- xml2::xml_find_first(xml2::read_xml(swid_tag(x)), "//s:Entity[@role='maintainer']", swid_ns)
  expect_equal(xml2::xml_attr(ent, "name"), 'A & B <c> "d"')
})

test_that("Meta carries the generator, product, notes, purl and licence", {
  x <- fixture_sbom()
  doc <- xml2::read_xml(swid_tag(x))
  meta <- xml2::xml_find_first(doc, "//s:Meta", swid_ns)
  expect_equal(xml2::xml_attr(meta, "generator"), paste("sbom", x$metadata$tool_version))
  expect_equal(xml2::xml_attr(meta, "product"), "srcpkg")
  expect_equal(xml2::xml_attr(meta, "description"), paste(document_notes(x), collapse = " "))
  expect_equal(xml2::xml_ns(doc)[["sbom"]], "https://cran.r-project.org/package=sbom")
  attrs <- xml2::xml_attrs(meta)
  expect_equal(attrs[["license"]], "MIT + file LICENSE")
  # The fixture root has no purl, so none is written.
  expect_false("purl" %in% sub("^.*:", "", names(attrs)))
  p <- xml2::xml_attrs(xml2::xml_find_first(xml2::read_xml(swid_tag(parity_sbom())), "//s:Meta", swid_ns))
  expect_equal(p[["purl"]], "pkg:cran/dplyr@1.2.1")
})

test_that("Meta describes the root's asserted overrides", {
  ov <- data.frame(component = c("srcpkg", "cranpkg"), field = "supplier_name",
                   value = c("Acme", "Other"), asserted_by = "Legal", reason = c("Contract", "Checked"))
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
  meta <- xml2::xml_find_first(xml2::read_xml(swid_tag(x)), "//s:Meta", swid_ns)
  desc <- xml2::xml_attr(meta, "description")
  expect_match(desc, "Asserted by Legal: supplier_name is Acme (Contract).", fixed = TRUE)
  expect_false(grepl("supplier_name is Other (Checked).", desc, fixed = TRUE))
  expect_true(startsWith(desc, paste(document_notes(x), collapse = " ")))
})

test_that("a root without a version has no version attributes; others get scheme unknown", {
  x <- sbom_installed(lib = fixture_lib())
  root <- xml2::xml_root(xml2::read_xml(swid_tag(x)))
  expect_true(is.na(xml2::xml_attr(root, "version")))
  expect_true(is.na(xml2::xml_attr(root, "versionScheme")))
  y <- fixture_sbom()
  y$components$version[y$components$is_root] <- "1.0-2"
  root <- xml2::xml_root(xml2::read_xml(swid_tag(y)))
  expect_equal(xml2::xml_attr(root, "version"), "1.0-2")
  expect_equal(xml2::xml_attr(root, "versionScheme"), "unknown")
})

test_that("requires links carry minimum versions and base-package membership", {
  doc <- xml2::read_xml(swid_tag(fixture_sbom()))
  req <- xml2::xml_find_all(doc, "//s:Link[@rel='requires']", swid_ns)
  attrs <- function(href) xml2::xml_attrs(req[xml2::xml_attr(req, "href") == href][[1]])
  expect_equal(attrs("swid:R")[["versionIs"]], "minimum")
  expect_equal(attrs("swid:R/utils")[["partOf"]], "R")
  expect_false("partOf" %in% sub("^.*:", "", names(attrs("swid:R"))))
})

test_that("SWID is deterministic and ends up as UTF-8 under a C locale", {
  x <- sbom_package(local_latin1_pkg(), lib = local_fake_lib(list()))
  local_c_ctype()
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_text(swid_tag(x), tf)
  expect_length(grepRaw(charToRaw("Gábor Csárdi"), readBin(tf, "raw", 1e6), fixed = TRUE), 1L)
  expect_identical(swid_tag(x), swid_tag(x))
})

test_that("package and library tags break no SWID structural rule", {
  for (x in list(fixture_sbom(), sbom_installed(lib = fixture_lib()))) {
    tf <- withr::local_tempfile(fileext = ".swidtag"); write_text(swid_tag(x), tf)
    res <- expect_no_warning(schema_validate(tf, "swid", "2015"))
    expect_equal(res$status, "partial")
  }
})

test_that("a tag that breaks a SWID structural rule fails", {
  tf <- withr::local_tempfile(fileext = ".swidtag")
  write_text(sub("tagVersion=\"[0-9]+\"", "tagVersion=\"x\"", swid_tag(fixture_sbom())), tf)
  res <- schema_validate(tf, "swid", "2015")
  expect_equal(res$status, "fail")
  expect_gt(nrow(res$findings), 0L)
})

test_that("SWID is in the registry", {
  f <- sbom_formats()
  r <- f[f$format == "swid", ]
  expect_equal(r$name, "SWID tag")
  expect_equal(r$extension, ".swidtag")
  expect_equal(r$versions, "2015")
  expect_equal(r$media_type, "application/swid+xml")
  dir <- withr::local_tempdir()
  write_sbom(fixture_sbom(), dir, format = "all")
  expect_true("srcpkg-0.1.0.swidtag" %in% list.files(dir))
  tf <- file.path(dir, "one.swidtag")
  write_sbom(fixture_sbom(), tf)
  expect_equal(readLines(tf, n = 1), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
})

test_that("SWID matches R Observatory's dplyr 1.2.1 sample", {
  ours <- xml2::read_xml(swid_tag(parity_sbom()))
  theirs <- xml2::read_xml(test_path("fixtures/r-observatory/dplyr-1.2.1.swidtag"))
  expect_equal(normalize_swid(ours), normalize_swid(theirs))
})

test_that("R Observatory's own sample breaks no SWID structural rule", {
  res <- schema_validate(test_path("fixtures/r-observatory/dplyr-1.2.1.swidtag"), "swid", "2015")
  expect_equal(res$status, "partial")
})
