# The columns of sbom_advisories() beyond id, ref, name, version and url
# that each format carries.
advisory_columns <- c("summary", "published", "fixed", "cves", "source_url")
carried <- list(
  `cyclonedx-json` = c("summary", "published", "cves", "source_url"),
  `cyclonedx-xml` = c("summary", "published", "cves", "source_url"),
  `spdx-json` = "fixed",
  `spdx-tv` = "fixed",
  `spdx3-jsonld` = c("summary", "published", "cves", "source_url")
)

# `x` written in format `f`, at version `v` or the default, and read back.
reread <- function(x, f, v = NULL) {
  tf <- withr::local_tempfile(fileext = format_registry()[[f]]$extension)
  write_sbom(x, tf, format = f, version = v)
  read_sbom(tf)
}

# The SBOM read from the text `txt`, a file with extension `ext`.
read_text <- function(txt, ext) {
  tf <- withr::local_tempfile(fileext = ext)
  write_text(txt, tf)
  read_sbom(tf)
}

# The findings of validate_sbom() on the text `txt`, with check `check`.
findings_of <- function(txt, ext, check) {
  tf <- withr::local_tempfile(fileext = ext)
  write_text(txt, tf)
  f <- validate_sbom(tf, checks = "content")$findings
  f[f$check == check, c("location", "message"), drop = FALSE]
}

# The text of every format at its default version, but CSV.
every_format <- function(x) {
  reg <- format_registry()
  keys <- setdiff(names(reg), "csv")
  stats::setNames(lapply(keys, function(f) reg[[f]]$writer(x, reg[[f]]$default_version)), keys)
}

# How often `s` occurs in `txt`.
times <- function(txt, s) {
  at <- gregexpr(s, txt, fixed = TRUE)[[1]]
  sum(at > 0L)
}

# The messages sbom_advisories() gives for `x`.
advisory_messages <- function(x) {
  seen <- new.env()
  seen$text <- character()
  withCallingHandlers(
    sbom_advisories(x),
    message = function(m) {
      seen$text <- c(seen$text, cli::ansi_strip(conditionMessage(m)))
      invokeRestart("muffleMessage")
    }
  )
  seen$text
}

# The CycloneDX vulnerabilities `vulns`, JSON objects, each given OSV as its
# source, as sbom and R Observatory write it.
osv_listing <- function(vulns) {
  sub("^\\{", '{"source": {"name": "OSV"}, ', vulns)
}

# A CycloneDX 1.6 document with a root, a CRAN package a 1.0, a component
# without a version, and the vulnerabilities `vulns`, JSON text.
cdx_with_vulnerabilities <- function(vulns) {
  paste0(
    '{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,',
    '"metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"type": "application", "bom-ref": "root", ',
    '"name": "root", "version": "1.0"}},',
    '"components": [',
    '{"type": "library", "bom-ref": "pkg:cran/a@1.0", "name": "a", "version": "1.0", "purl": "pkg:cran/a@1.0"},',
    '{"type": "library", "bom-ref": "nover", "name": "nover"}],',
    '"dependencies": [{"ref": "root", "dependsOn": ["pkg:cran/a@1.0", "nover"]}],',
    '"vulnerabilities": [', paste(vulns, collapse = ", "), "]}"
  )
}

test_that("read_sbom() brings advisories back from CycloneDX, SPDX 2 and SPDX 3", {
  skip_on_cran()
  x <- two_advisory_sbom()
  want <- sbom_advisories(x)
  expect_identical(want$id, c("RSEC-9000-1", "RSEC-9000-2"))
  for (f in names(carried)) {
    back <- reread(x, f)
    got <- expect_no_message(sbom_advisories(back))
    expect_identical(back$metadata$advisories$status, "listed", label = f)
    expect_identical(got[c("id", "name", "version", "url")], want[c("id", "name", "version", "url")], label = f)
    for (col in advisory_columns) {
      expected <- if (col %in% carried[[f]]) want[[col]] else rep(NA_character_, 2L)
      expect_identical(got[[col]], expected, label = paste(f, col))
    }
    # Each advisory names the component the document holds.
    expect_true(all(got$ref %in% back$components$ref), label = f)
  }
  # The values the comparison relies on are there.
  expect_identical(want$fixed, c("1.1.0", NA))
  expect_identical(want$cves, c("CVE-2099-0001", NA))
  expect_false(anyNA(want$summary))
})

test_that("CycloneDX gives back the ratings, without their upstream records", {
  skip_on_cran()
  x <- two_advisory_sbom()
  rating <- data.frame(
    upstream = NA_character_, method = "CVSSv3", vector = cvss_vector, score = 8.8, severity = "high",
    stringsAsFactors = FALSE
  )
  for (f in c("cyclonedx-json", "cyclonedx-xml")) {
    back <- reread(x, f)
    expect_identical(back$advisories$ratings, list(rating, empty_ratings()), label = f)
    expect_identical(back$advisories$upstream, list("CVE-2099-0001", character()), label = f)
    # Written again, the vulnerabilities are those of the SBOM it was read from.
    expect_identical(cdx_document(back)$vulnerabilities, cdx_document(x)$vulnerabilities, label = f)
  }
  # SPDX 2 and SPDX 3 carry no ratings.
  expect_identical(reread(x, "spdx3-jsonld")$advisories$ratings, list(empty_ratings(), empty_ratings()))
})

test_that("every version and serialization gives the advisories back", {
  skip_on_cran()
  x <- two_advisory_sbom()
  want <- sbom_advisories(x)[c("id", "name", "version")]
  reg <- format_registry()
  formats <- c("cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-xml", "spdx-tv", "spdx3-jsonld")
  if (requireNamespace("yaml", quietly = TRUE)) formats <- c(formats, "spdx-yaml")
  for (f in formats) {
    for (v in reg[[f]]$versions) {
      got <- sbom_advisories(reread(x, f, v))
      expect_identical(got[c("id", "name", "version")], want, label = paste(f, v))
      if (startsWith(f, "spdx-")) expect_identical(got$fixed, c("1.1.0", NA), label = paste(f, v))
    }
  }
})

test_that("SPDX 2 references give the fix, or that there is none, in both forms of the comment", {
  skip_on_cran()
  x <- two_advisory_sbom()
  back <- reread(x, "spdx-json")
  affects <- back$advisories$affects
  expect_identical(affects[[1]]$fixed, "1.1.0")
  expect_false(affects[[1]]$no_fix)
  expect_identical(affects[[2]]$fixed, NA_character_)
  expect_true(affects[[2]]$no_fix)
  expect_identical(back$advisories$summary, c(NA_character_, NA_character_))

  # Without the summary.
  x$advisories$summary <- NA_character_
  txt <- spdx_json(x)
  for (comment in c(
    "RSEC-9000-1. OSV lists fakepkg 1.0.0 among the versions it affects, fixed in 1.1.0.",
    "RSEC-9000-2. OSV lists openpkg 2.0 among the versions it affects, with no fix."
  )) {
    expect_true(grepl(comment, txt, fixed = TRUE), label = comment)
  }
  back <- read_text(txt, ".spdx.json")
  expect_identical(back$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"))
  expect_identical(back$advisories$affects[[1]]$fixed, "1.1.0")
  expect_true(back$advisories$affects[[2]]$no_fix)

  # The fix is the one the comment ends with, whatever the summary says.
  doc <- jsonlite::parse_json(spdx_json(two_advisory_sbom()))
  crafted <- paste(
    "RSEC-9000-1, x among the versions it affects, fixed in 1.",
    "OSV lists fakepkg 1.0.0 among the versions it affects, with no fix."
  )
  doc$packages <- lapply(doc$packages, function(p) {
    p$externalRefs <- lapply(p$externalRefs, function(r) {
      if (identical(r$referenceLocator, "https://osv.dev/vulnerability/RSEC-9000-1")) r$comment <- crafted
      r
    })
    p
  })
  back <- read_text(jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx.json")
  expect_identical(back$advisories$affects[[1]]$fixed, NA_character_)
  expect_true(back$advisories$affects[[1]]$no_fix)
})

test_that("sbom's SPDX 2.2 and 2.3 references round-trip in every serialization", {
  skip_on_cran()
  x <- two_advisory_sbom()
  # A summary that holds a line break and a sentence in sbom's words about
  # another package: the comment's last sentence is the one read.
  x$advisories$summary[[1]] <- "First line\nsecond. OSV lists openpkg 2.0 among the versions it affects"
  want <- sbom_advisories(x)[c("id", "name", "version", "fixed", "no_fix")]
  formats <- c("spdx-json", "spdx-xml", "spdx-tv", if (requireNamespace("yaml", quietly = TRUE)) "spdx-yaml")
  for (f in formats) {
    for (v in c("2.2", "2.3")) {
      back <- reread(x, f, v)
      expect_identical(sbom_advisories(back)[names(want)], want, label = paste(f, v))
      expect_false("read-advisories-dropped" %in% back$issues$code, label = paste(f, v))
    }
  }
})

test_that("an SPDX 2 osv.dev reference is read only when its comment names its package at its version", {
  skip_on_cran()
  dropped <- function(back) back$issues$message[back$issues$code == "read-advisories-dropped"]
  not_listing <- "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  doc <- jsonlite::parse_json(spdx_json(two_advisory_sbom()))
  at <- vapply(doc$packages, function(p) p$name, "")
  fake <- which(at == "fakepkg")
  open <- which(at == "openpkg")
  is_ref <- function(r, id) identical(r$referenceLocator, paste0("https://osv.dev/vulnerability/", id))
  read_doc <- function(d) read_text(jsonlite::toJSON(d, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx.json")
  # openpkg 2.0's RSEC-9000-2 reference, with `comment`, or without one.
  with_comment <- function(comment, category = "SECURITY", locator = NULL) {
    d <- doc
    d$packages[[open]]$externalRefs <- lapply(d$packages[[open]]$externalRefs, function(r) {
      if (is_ref(r, "RSEC-9000-2")) {
        r$comment <- comment
        r$referenceCategory <- category
        if (!is.null(locator)) r$referenceLocator <- locator
      }
      r
    })
    d
  }

  # The reviewer's probe: fakepkg's RSEC-9000-1 reference moved onto openpkg.
  moved <- doc
  ref <- Filter(function(r) is_ref(r, "RSEC-9000-1"), moved$packages[[fake]]$externalRefs)
  moved$packages[[fake]]$externalRefs <- Filter(function(r) !is_ref(r, "RSEC-9000-1"), moved$packages[[fake]]$externalRefs)
  moved$packages[[open]]$externalRefs <- c(moved$packages[[open]]$externalRefs, ref)
  back <- read_doc(moved)
  expect_identical(back$advisories$id, "RSEC-9000-2")
  expect_identical(sbom_advisories(back)$name, "openpkg")
  expect_identical(dropped(back), not_listing)
  expect_false(grepl("OSV lists openpkg 2.0 among the versions it affects, fixed in", spdx_tv(back), fixed = TRUE))
  expect_false(grepl("RSEC-9000-1", spdx_tv(back), fixed = TRUE))

  # A comment that names another package or version, another id, or says
  # something else, and a reference without a comment.
  for (comment in list(
    "RSEC-9000-2. OSV lists fakepkg 2.0 among the versions it affects, with no fix.",
    "RSEC-9000-2. OSV lists openpkg 2.0.1 among the versions it affects, with no fix.",
    "RSEC-9000-2. OSV lists openpkg 2 among the versions it affects.",
    "RSEC-9000-2. OSV lists OPENPKG 2.0 among the versions it affects.",
    "RSEC-9000-3. OSV lists openpkg 2.0 among the versions it affects, with no fix.",
    "RSEC-9000-2, Prototype pollution. OSV lists openpkg 2.0 among the versions it affects, with no fix. More.",
    "Prototype pollution in a bundled library",
    "OSV lists openpkg 2.0 among the versions it affects, with no fix",
    NULL
  )) {
    back <- read_doc(with_comment(comment))
    label <- if (is.null(comment)) "no comment" else comment
    expect_identical(back$advisories$id, "RSEC-9000-1", label = label)
    expect_identical(dropped(back), not_listing, label = label)
    expect_false(grepl("OSV lists openpkg", spdx_tv(back), fixed = TRUE), label = label)
  }
  # Another tool's reference to an osv.dev page, as SECURITY or OTHER.
  for (category in c("SECURITY", "OTHER")) {
    back <- read_doc(with_comment(
      "Prototype pollution in a bundled library", category, "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
    ))
    expect_identical(back$advisories$id, "RSEC-9000-1", label = category)
    expect_identical(dropped(back), not_listing, label = category)
  }

  # sbom's words, with or without the id and the summary, are read.
  for (comment in c(
    "RSEC-9000-2, Prototype pollution. OSV lists openpkg 2.0 among the versions it affects, with no fix.",
    "RSEC-9000-2. OSV lists openpkg 2.0 among the versions it affects.",
    "OSV lists openpkg 2.0 among the versions it affects, fixed in 2.1."
  )) {
    back <- read_doc(with_comment(comment))
    expect_identical(back$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"), label = comment)
    expect_identical(dropped(back), character(), label = comment)
  }
})

test_that("an SPDX 2 comment names a package with dots at a version with dashes exactly", {
  x <- widgetframe_sbom()
  ref <- "pkg:cran/my.pkg@1.0-2"
  row <- x$components$name == "widgetframe"
  x$components$ref[row] <- ref
  x$components$purl[row] <- ref
  x$components$name[row] <- "my.pkg"
  x$components$version[row] <- "1.0-2"
  x$advisories$affects[[1]]$ref <- ref
  x$advisories$affects[[1]]$version <- "1.0-2"
  txt <- spdx_json(x)
  expect_true(grepl("OSV lists my.pkg 1.0-2 among the versions it affects, with no fix.", txt, fixed = TRUE))
  back <- read_text(txt, ".spdx.json")
  expect_identical(back$advisories$id, "RSEC-2026-0")
  expect_identical(unlist(sbom_advisories(back)[c("name", "version")]), c(name = "my.pkg", version = "1.0-2"))
  # A dot is not any character, and 1.0.2 is not 1.0-2 as written.
  for (other in c("myXpkg 1.0-2", "my.pkg 1.0.2", "my.pkg 1x0-2")) {
    back <- read_text(sub("OSV lists my.pkg 1.0-2", paste("OSV lists", other), txt, fixed = TRUE), ".spdx.json")
    expect_identical(nrow(back$advisories), 0L, label = other)
    expect_identical(
      back$issues$message[back$issues$code == "read-advisories-dropped"],
      "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read.",
      label = other
    )
  }
})

test_that("an SPDX 2 advisory reference is read only with an osv.dev locator", {
  x <- two_advisory_sbom()
  # Locators that are not osv.dev's: the comments do not stand in for them.
  elsewhere <- function(txt) {
    gsub("https://osv.dev/vulnerability/RSEC-9000-", "https://example.org/advisory/x", txt, fixed = TRUE)
  }
  for (txt in list(list(spdx_json(x), ".spdx.json"), list(spdx_tv(x), ".spdx"))) {
    back <- read_text(elsewhere(txt[[1]]), txt[[2]])
    expect_identical(nrow(back$advisories), 0L, label = txt[[2]])
    expect_identical(
      back$issues$message[back$issues$code == "read-advisories-dropped"],
      "2 vulnerability entries in the document are not OSV advisory listings, so they were not read.",
      label = txt[[2]]
    )
  }
  # Another tool's reference, as for Log4Shell from NVD.
  doc <- jsonlite::parse_json(spdx_json(minimal_sbom()))
  doc$packages[[1]]$externalRefs <- c(doc$packages[[1]]$externalRefs, list(
    list(
      referenceCategory = "SECURITY", referenceType = "advisory",
      referenceLocator = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      comment = "Log4Shell, remote code execution"
    ),
    list(
      referenceCategory = "SECURITY", referenceType = "advisory",
      referenceLocator = "https://example.org/fallback", comment = "fallback, s"
    )
  ))
  back <- read_text(jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx.json")
  expect_identical(back$advisories, empty_advisories())
  expect_identical(back$metadata$advisories$status, "not-requested")
  expect_identical(
    back$issues$message[back$issues$code == "read-advisories-dropped"],
    "2 vulnerability entries in the document are not OSV advisory listings, so they were not read."
  )
})

test_that("SPDX 2.2 OTHER and SPDX 2.3 SECURITY advisory references are both read", {
  skip_on_cran()
  x <- two_advisory_sbom()
  # The SPDX 2 JSON `txt` with each advisory reference given `category` and
  # `type`.
  recategorised <- function(txt, category, type = "advisory") {
    doc <- jsonlite::parse_json(txt)
    doc$packages <- lapply(doc$packages, function(p) {
      p$externalRefs <- lapply(p$externalRefs, function(r) {
        if (identical(r$referenceType, "advisory")) {
          r$referenceCategory <- category
          r$referenceType <- type
        }
        r
      })
      p
    })
    jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null")
  }
  for (v in c("2.2", "2.3")) {
    for (category in c("OTHER", "SECURITY")) {
      back <- read_text(recategorised(spdx_json(x, v), category), ".spdx.json")
      expect_identical(back$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"), label = paste(v, category))
    }
  }
  # Another type, or another category, is not an advisory.
  for (other in list(c("SECURITY", "url"), c("PERSISTENT-ID", "advisory"))) {
    back <- read_text(recategorised(spdx_json(x), other[[1]], other[[2]]), ".spdx.json")
    expect_identical(nrow(back$advisories), 0L, label = paste(other, collapse = " "))
  }
})

test_that("an osv.dev locator gives the id percent-decoded", {
  x <- widgetframe_sbom()
  x$advisories$id <- "RSEC:2026-0"
  txt <- spdx_json(x)
  expect_true(grepl("https://osv.dev/vulnerability/RSEC%3A2026-0", txt, fixed = TRUE))
  # The comment's id is the locator's, decoded.
  back <- read_text(txt, ".spdx.json")
  expect_identical(back$advisories$id, "RSEC:2026-0")
  for (f in c("cyclonedx-json", "cyclonedx-xml", "spdx3-jsonld")) {
    expect_identical(reread(x, f)$advisories$id, "RSEC:2026-0", label = f)
  }
  # A comment that names another id is not a listing.
  other <- sub('"comment": "RSEC:2026-0, ', '"comment": "other, ', txt, fixed = TRUE)
  expect_false(grepl("RSEC:2026-0,", other, fixed = TRUE))
  back <- read_text(other, ".spdx.json")
  expect_identical(nrow(back$advisories), 0L)
  expect_identical(
    back$issues$message[back$issues$code == "read-advisories-dropped"],
    "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  )
  # An escape of a character no OSV id holds is not decoded, so the id is not
  # an OSV id, even when the comment gives the same id.
  txt <- gsub("RSEC%3A2026-0|RSEC:2026-0", "RSEC%2F2026-0", spdx_json(x))
  back <- read_text(txt, ".spdx.json")
  expect_identical(nrow(back$advisories), 0L)
  expect_identical(
    back$issues$message[back$issues$code == "read-advisories-dropped"],
    "1 vulnerability entry in the document has no OSV id, so it was not read."
  )
})

test_that("a SWID tag reads back with no advisories", {
  x <- two_advisory_sbom()
  back <- reread(x, "swid")
  expect_identical(back$advisories, empty_advisories())
  expect_identical(back$metadata$advisories$status, "not-requested")
  expect_identical(advisory_messages(back), "This SBOM was read from a file, and sbom read no advisories from it.")
})

test_that("a read SBOM is listed when its document lists advisories or says they are listed", {
  skip_on_cran()
  x <- two_advisory_sbom()
  back <- reread(x, "cyclonedx-json")
  expect_identical(advisory_messages(back), character())
  expect_true("Advisories: 2 listed by OSV for these exact versions." %in% utils::capture.output(print(back)))
  expect_identical(summary(back)$advisories, list(status = "listed", n = 2L))

  # Listed, but none matched: the document says they are listed.
  y <- minimal_sbom()
  y$metadata$advisories$status <- "listed"
  y$metadata$notes <- listed_note
  for (f in c("cyclonedx-json", "spdx-json", "spdx3-jsonld")) {
    back <- reread(y, f)
    expect_identical(back$metadata$advisories$status, "listed", label = f)
    expect_identical(nrow(back$advisories), 0L, label = f)
    expect_identical(advisory_messages(back), character(), label = f)
  }

  # Built without advisories, or by another tool: none.
  for (back in list(reread(fixture_sbom(), "cyclonedx-json"),
                    read_sbom(test_path("fixtures", "third-party", "cyclonedx", "valid-bom-1.6.json")))) {
    expect_identical(back$metadata$advisories$status, "not-requested")
    expect_identical(back$advisories, empty_advisories())
    expect_identical(advisory_messages(back), "This SBOM was read from a file, and sbom read no advisories from it.")
  }
  # A built SBOM keeps its own message.
  expect_identical(
    advisory_messages(fixture_sbom()),
    "This SBOM was built without advisories; build it with `advisories = TRUE` to list them."
  )
})

test_that("a read SBOM written again keeps its advisories, and each note once", {
  skip_on_cran()
  x <- two_advisory_sbom()
  # With the Bioconductor note too, after the note that they are listed.
  x$metadata$notes <- append(x$metadata$notes, advisory_notes$bioc, after = match(listed_note, x$metadata$notes))
  ids <- x$advisories$id
  sources <- setdiff(names(format_registry()), c("csv", "swid", if (!requireNamespace("yaml", quietly = TRUE)) "spdx-yaml"))
  for (f in sources) {
    back <- reread(x, f)
    texts <- every_format(back)
    for (g in names(texts)) {
      label <- paste(f, "to", g)
      txt <- texts[[g]]
      expect_identical(times(txt, no_data_note), 0L, label = label)
      if (g == "swid") {
        # A tag says it has no place for them instead, whatever the notes
        # were joined into.
        expect_identical(times(txt, listed_note), 0L, label = label)
        expect_identical(times(txt, swid_note), 1L, label = label)
        expect_identical(times(txt, advisory_notes$bioc), 0L, label = label)
        expect_identical(times(txt, "Advisory data is OSV's CRAN export"), 0L, label = label)
        next
      }
      expect_identical(times(txt, listed_note), 1L, label = label)
      expect_identical(times(txt, swid_note), 0L, label = label)
      for (id in ids) expect_true(grepl(id, txt, fixed = TRUE), label = paste(label, id))
    }
    # And read again, they are the same advisories.
    expect_identical(sbom_advisories(reread(back, "cyclonedx-json"))$id, ids, label = f)
  }

  # The note on a local file, joined into one SPDX comment, goes too.
  local <- two_package_sbom(advisories = test_path("fixtures", "osv", "all.zip"))
  provenance <- "Advisory data is OSV's CRAN export, read from all.zip, with records modified up to"
  expect_true(any(startsWith(local$metadata$notes, provenance)))
  swid <- every_format(reread(local, "spdx-json"))$swid
  expect_identical(times(swid, "Advisory data is OSV's CRAN export"), 0L)
  expect_identical(times(swid, swid_note), 1L)
  # And the sentences around it stay.
  expect_true(grepl("Read from ", swid, fixed = TRUE))
  expect_true(grepl("rootpkg 0.1.0 names no maintainer.", swid, fixed = TRUE))

  # A SWID tag read back: the tag says so once, and no other format does.
  # Every other format says instead, once, that no advisory data was on hand
  # for it, which is true of a file written from a SWID tag.
  from_swid <- reread(x, "swid")
  texts <- every_format(from_swid)
  for (g in names(texts)) {
    label <- paste("swid to", g)
    expect_identical(times(texts[[g]], swid_note), if (g == "swid") 1L else 0L, label = label)
    expect_identical(times(texts[[g]], listed_note), 0L, label = label)
    expect_identical(times(texts[[g]], no_data_note), if (g == "swid") 0L else 1L, label = label)
  }
  # Once, even when the notes say it already.
  from_swid$metadata$notes <- c(from_swid$metadata$notes, no_data_note)
  texts <- every_format(from_swid)
  for (g in setdiff(names(texts), "swid")) {
    expect_identical(times(texts[[g]], no_data_note), 1L, label = paste("swid with the note to", g))
    expect_identical(times(texts[[g]], swid_note), 0L, label = paste("swid with the note to", g))
  }

  # Without advisories, the note that no advisory data was on hand, once.
  y <- fixture_sbom()
  expect_true(no_data_note %in% y$metadata$notes)
  for (f in c("cyclonedx-json", "spdx-json")) {
    texts <- every_format(reread(y, f))
    for (g in names(texts)) {
      expect_identical(times(texts[[g]], no_data_note), 1L, label = paste(f, "to", g))
      expect_identical(times(texts[[g]], listed_note), 0L, label = paste(f, "to", g))
    }
  }
})

test_that("CycloneDX vulnerabilities are ids, and their affects relationships", {
  x <- two_advisory_sbom()
  for (f in c("cyclonedx-json", "cyclonedx-xml")) {
    tf <- withr::local_tempfile(fileext = format_registry()[[f]]$extension)
    write_sbom(x, tf, format = f)
    t <- document_tables(read_document(tf))
    expect_true(all(c("advisory/RSEC-9000-1", "advisory/RSEC-9000-2") %in% t$document$ids), label = f)
    rel <- t$relationships[t$relationships$type == "affects", , drop = FALSE]
    expect_identical(rel, tables_relationships(
      location = c("/vulnerabilities/0/affects/0", "/vulnerabilities/1/affects/0"),
      from = c("advisory/RSEC-9000-1", "advisory/RSEC-9000-2"),
      to = c("pkg:cran/fakepkg@1.0.0", "pkg:cran/openpkg@2.0"),
      type = c("affects", "affects")
    ), ignore_attr = "row.names", label = f)
    # They are not relationships of the <sbom>.
    expect_false(any(read_sbom(tf)$issues$code %in% c("read-relationships-skipped", "read-dangling-relationships")))
  }
})

test_that("an affects naming an element the document lacks is a dangling relationship", {
  skip_on_cran()
  x <- two_advisory_sbom()
  dangling <- function(location) {
    data.frame(
      location = location,
      message = "The relationship refers to pkg:cran/gone@1.0, which is not an element of this document.",
      stringsAsFactors = FALSE
    )
  }
  doc <- jsonlite::parse_json(cdx_json(x))
  doc$vulnerabilities[[1]]$affects[[1]]$ref <- "pkg:cran/gone@1.0"
  txt <- jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null")
  expect_identical(
    findings_of(txt, ".cdx.json", "dangling-relationship"), dangling("/vulnerabilities/0/affects/0"),
    ignore_attr = "row.names"
  )
  xml <- xml2::read_xml(cdx_xml(x))
  ref <- xml2::xml_find_first(xml, "//*[local-name()='affects']/*[local-name()='target']/*[local-name()='ref']")
  xml2::xml_text(ref) <- "pkg:cran/gone@1.0"
  expect_identical(
    findings_of(as.character(xml), ".cdx.xml", "dangling-relationship"), dangling("/vulnerabilities/0/affects/0"),
    ignore_attr = "row.names"
  )

  # The files sbom writes have none.
  for (f in c(names(carried), "spdx-xml")) {
    tf <- withr::local_tempfile(fileext = format_registry()[[f]]$extension)
    write_sbom(x, tf, format = f)
    expect_false("dangling-relationship" %in% validate_sbom(tf, checks = "content")$findings$check, label = f)
  }
})

test_that("CycloneDX XML vulnerabilities read to the model of their JSON twin", {
  skip_on_cran()
  x <- two_advisory_sbom()
  x$advisories$ratings[[2]] <- data.frame(
    upstream = "CVE-2099-0002", method = "CVSSv3", vector = NA_character_, score = 5, severity = "medium",
    stringsAsFactors = FALSE
  )
  for (v in format_registry()[["cyclonedx-xml"]]$versions) {
    json <- withr::local_tempfile(fileext = ".cdx.json")
    xml <- withr::local_tempfile(fileext = ".cdx.xml")
    write_sbom(x, json, version = v)
    write_sbom(x, xml, version = v)
    want <- read_document(json)$doc$vulnerabilities
    expect_identical(read_document(xml)$doc$vulnerabilities, want, label = v)
    expect_length(want, 2L)
    # A score without a fraction is an integer, as jsonlite parses it.
    expect_identical(want[[2]]$ratings[[1]]$score, 5L, label = v)
  }

  # Only elements of the CycloneDX namespace, with the attributes the XSDs
  # declare, are read; the arrays hold their items.
  tf <- withr::local_tempfile(fileext = ".cdx.xml")
  write_text(paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:x="urn:example:x" version="1">',
    '<components><component type="library" bom-ref="a"><name>a</name><version>1.0</version></component></components>',
    "<vulnerabilities>",
    '<vulnerability bom-ref="v1" x:bom-ref="spoof" id="SPOOF-1">',
    "<id>RSEC-1</id><x:id>SPOOF-2</x:id>",
    "<references><reference><id>CVE-2099-1</id><source><name>CVE</name></source></reference></references>",
    "<ratings><rating><score> 7.5 </score><severity>high</severity></rating>",
    "<x:rating><score>1</score></x:rating></ratings>",
    "<cwes><cwe>79</cwe></cwes>",
    "<advisories><advisory><url>https://example.org/a</url></advisory></advisories>",
    "<affects><target><ref>a</ref><versions><version><version>1.0</version><status>affected</status></version>",
    "</versions></target><x:target><ref>spoof</ref></x:target></affects>",
    "</vulnerability>",
    '<x:vulnerability bom-ref="v2"><id>SPOOF-3</id></x:vulnerability>',
    "</vulnerabilities></bom>"
  ), tf)
  expect_identical(read_document(tf)$doc$vulnerabilities, list(list(
    `bom-ref` = "v1", id = "RSEC-1",
    references = list(list(id = "CVE-2099-1", source = list(name = "CVE"))),
    ratings = list(list(score = 7.5, severity = "high")),
    cwes = list(79L),
    advisories = list(list(url = "https://example.org/a")),
    affects = list(list(ref = "a", versions = list(list(version = "1.0", status = "affected"))))
  )))
})

test_that("advisory values from a document are checked before they are kept", {
  txt <- cdx_with_vulnerabilities(c(osv_listing(c(
    paste0(
      '{"bom-ref": "v1", "id": "RSEC-2026-1", "description": "Line one\\u0001two",',
      '"published": "2026-02-30T00:00:00Z",',
      '"advisories": [{"url": "https://user:pw@example.org/a.yaml?x=1#y"}],',
      '"references": [{"id": "CVE-2026-0001"}, {"id": "GHSA-aaaa-bbbb-cccc"}, {"id": 5}],',
      '"ratings": [{"score": "9.1", "severity": "critical", "method": "CVSSv31"},',
      '{"score": 7.5, "severity": "high", "method": "CVSSv3", "vector": "CVSS:3.1/AV:N\\u0007"}, 3],',
      '"affects": [{"ref": "pkg:cran/a@1.0"}, {"ref": "missing"}, {"ref": "nover"}, {"ref": 7}]}'
    ),
    '{"id": "not an id", "affects": [{"ref": "pkg:cran/a@1.0"}]}',
    '{"id": 42, "affects": [{"ref": "pkg:cran/a@1.0"}]}',
    '{"id": "RSEC-2026-4", "affects": [{"ref": "missing"}]}',
    '{"id": "RSEC-2026-5", "affects": [{"ref": "nover"}]}',
    paste0(
      '{"id": "RSEC-2026-6", "published": "2026-03-01T10:00:00Z", "advisories": [{"url": "/home/me/a.yaml"}],',
      '"affects": [{"ref": "pkg:cran/a@1.0"}]}'
    ),
    '{"id": "RSEC-2026-1", "description": "Another", "affects": [{"ref": "root"}, {"ref": "pkg:cran/a@1.0"}]}'
  )), '"not an object"'))
  back <- read_text(txt, ".cdx.json")
  adv <- back$advisories
  expect_identical(adv$id, c("RSEC-2026-1", "RSEC-2026-6"))
  expect_identical(adv$summary, c("Line one two", NA))
  expect_identical(adv$published, c(NA, "2026-03-01"))
  expect_identical(adv$source_url, c("https://example.org/a.yaml", NA))
  expect_identical(adv$upstream, list("CVE-2026-0001", character()))
  expect_identical(adv$ratings[[1]], data.frame(
    upstream = c(NA_character_, NA_character_), method = c("CVSSv31", "CVSSv3"),
    vector = c(NA, "CVSS:3.1/AV:N"), score = c(NA, 7.5), severity = c("critical", "high"),
    stringsAsFactors = FALSE
  ))
  # One advisory per id, with the components of both, each once.
  expect_identical(adv$affects[[1]], data.frame(
    ref = c("pkg:cran/a@1.0", "root"), version = c("1.0", "1.0"), fixed = c(NA_character_, NA_character_),
    no_fix = c(NA, NA), stringsAsFactors = FALSE
  ))
  issue <- function(code) back$issues$message[back$issues$code == code]
  expect_identical(issue("read-advisories-dropped"), c(
    "2 vulnerability entries in the document have no OSV id, so they were not read.",
    "2 vulnerability entries name no component of the document that has a version, so they were not read."
  ))
  expect_identical(
    issue("read-values-dropped"),
    "1 value was not kept because sbom's formats cannot carry it (local paths)."
  )
  expect_identical(
    issue("read-control-characters"),
    "2 values in the document held control characters, which sbom replaced with spaces."
  )
  expect_identical(back$issues$severity[back$issues$code == "read-advisories-dropped"], c("info", "info"))

  # One of each, in the singular.
  back <- read_text(cdx_with_vulnerabilities(c(
    '{"id": "RSEC-2026-3", "affects": [{"ref": "pkg:cran/a@1.0"}]}',
    osv_listing(c(
      '{"id": "bad id", "affects": [{"ref": "pkg:cran/a@1.0"}]}',
      '{"id": "RSEC-2026-4", "affects": [{"ref": "nover"}]}'
    ))
  )), ".cdx.json")
  expect_identical(back$issues$message[back$issues$code == "read-advisories-dropped"], c(
    "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read.",
    "1 vulnerability entry in the document has no OSV id, so it was not read.",
    "1 vulnerability entry names no component of the document that has a version, so it was not read."
  ))
  expect_identical(back$metadata$advisories$status, "not-requested")
  expect_identical(grep(safety_words, back$issues$message, perl = TRUE, value = TRUE), character())

  # Every count is of entries: two that share an id count as two.
  back <- read_text(cdx_with_vulnerabilities(osv_listing(c(
    '{"id": "RSEC-2026-4", "affects": [{"ref": "missing"}]}',
    '{"id": "RSEC-2026-4", "affects": [{"ref": "nover"}]}',
    '{"id": "bad id", "affects": [{"ref": "pkg:cran/a@1.0"}]}',
    '{"id": "bad id", "affects": [{"ref": "pkg:cran/a@1.0"}]}'
  ))), ".cdx.json")
  expect_identical(back$issues$message[back$issues$code == "read-advisories-dropped"], c(
    "2 vulnerability entries in the document have no OSV id, so they were not read.",
    "2 vulnerability entries name no component of the document that has a version, so they were not read."
  ))
})

test_that("only OSV's advisory listings are read from CycloneDX, never VEX or another source", {
  dropped <- function(back) back$issues$message[back$issues$code == "read-advisories-dropped"]
  # A VEX statement from another source that a 1.0 is not affected.
  vex <- paste0(
    '{"bom-ref": "v1", "id": "CVE-2021-44228", "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},',
    '"analysis": {"state": "not_affected", "justification": "code_not_reachable"},',
    '"affects": [{"ref": "pkg:cran/a@1.0", "versions": [{"version": "1.0", "status": "unaffected"}]}]}'
  )
  # The same statement giving OSV as its source, and a listing from NVD.
  osv_vex <- sub('"source": {"name": "NVD", "url": "https://nvd.nist.gov/"}', '"source": {"name": "OSV"}', vex,
                 fixed = TRUE)
  nvd <- '{"id": "CVE-2021-44228", "source": {"name": "NVD"}, "affects": [{"ref": "pkg:cran/a@1.0"}]}'
  not_listing <- "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  for (v in c(vex, osv_vex, nvd)) {
    back <- read_text(cdx_with_vulnerabilities(v), ".cdx.json")
    expect_identical(back$advisories, empty_advisories(), label = v)
    expect_identical(back$metadata$advisories$status, "not-requested", label = v)
    expect_identical(dropped(back), not_listing, label = v)
    # So nothing written from it says that OSV lists the version.
    expect_false(grepl("OSV lists", spdx_tv(back), fixed = TRUE), label = v)
    expect_null(cdx_document(back)$vulnerabilities, label = v)
  }
  # In XML too.
  xml <- paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">',
    '<metadata><component type="application" bom-ref="root"><name>root</name><version>1.0</version></component>',
    "</metadata>",
    '<components><component type="library" bom-ref="pkg:cran/a@1.0"><name>a</name><version>1.0</version>',
    "<purl>pkg:cran/a@1.0</purl></component></components>",
    "<vulnerabilities>",
    '<vulnerability bom-ref="v1"><id>RSEC-2026-1</id><source><name>OSV</name></source>',
    "<analysis><state>not_affected</state></analysis>",
    "<affects><target><ref>pkg:cran/a@1.0</ref></target></affects></vulnerability>",
    '<vulnerability bom-ref="v2"><id>RSEC-2026-2</id><source><name>OSV</name></source>',
    "<affects><target><ref>pkg:cran/a@1.0</ref></target></affects></vulnerability>",
    "</vulnerabilities></bom>"
  )
  back <- read_text(xml, ".cdx.xml")
  expect_identical(back$advisories$id, "RSEC-2026-2")
  expect_identical(dropped(back), not_listing)
})

test_that("only OSV's listings are read from SPDX 3, linked by hasAssociatedVulnerability", {
  x <- two_advisory_sbom()
  doc <- jsonlite::parse_json(spdx3_jsonld(x))
  graph <- doc[["@graph"]]
  is_vuln <- vapply(graph, function(e) identical(e$type, "security_Vulnerability"), logical(1))
  first <- which(is_vuln)[[1]]
  second <- which(is_vuln)[[2]]
  # RSEC-9000-1's identifier points elsewhere than osv.dev.
  graph[[first]]$externalIdentifier[[1]]$identifierLocator <- list("https://nvd.nist.gov/vuln/detail/RSEC-9000-1")
  # RSEC-9000-2 is linked only by a VEX relationship, from it to openpkg.
  rel <- which(vapply(graph, function(e) {
    identical(e$relationshipType, "hasAssociatedVulnerability") && identical(e$to[[1]], graph[[second]]$spdxId)
  }, logical(1)))
  package <- graph[[rel]]$from
  graph[[rel]]$type <- "security_VexNotAffectedVulnAssessmentRelationship"
  graph[[rel]]$relationshipType <- "doesNotAffect"
  graph[[rel]]$from <- graph[[second]]$spdxId
  graph[[rel]]$to <- list(package)
  doc[["@graph"]] <- graph
  back <- read_text(jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx3.jsonld")
  expect_identical(back$advisories, empty_advisories())
  expect_identical(back$issues$message[back$issues$code == "read-advisories-dropped"], c(
    "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read.",
    "1 vulnerability entry names no component of the document that has a version, so it was not read."
  ))
})

test_that("a CycloneDX affects target is a listing only when it says the component's version is affected", {
  skip_on_cran()
  dropped <- function(back) back$issues$message[back$issues$code == "read-advisories-dropped"]
  not_listing <- "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  target <- function(ref, versions) paste0('{"ref": "', ref, '", "versions": [', versions, "]}")
  vuln <- function(...) osv_listing(paste0('{"id": "RSEC-2026-1", "affects": [', paste(c(...), collapse = ", "), "]}"))
  a <- "pkg:cran/a@1.0"

  # The version unaffected, and a range of other versions affected, as in a
  # vulnerability disclosure report: OSV does not list 1.0.
  vdr <- target(a, '{"version": "1.0", "status": "unaffected"}, {"range": "vers:cran/<0.9", "status": "affected"}')
  back <- read_text(cdx_with_vulnerabilities(vuln(vdr)), ".cdx.json")
  expect_identical(back$advisories, empty_advisories())
  expect_identical(back$metadata$advisories$status, "not-requested")
  expect_identical(dropped(back), not_listing)
  expect_false(grepl("OSV lists", spdx_tv(back), fixed = TRUE))
  expect_null(cdx_document(back)$vulnerabilities)

  # Each of these says something other than that the version is affected.
  for (versions in c(
    '{"version": "0.9", "status": "affected"}', '{"version": "1.0", "status": "unknown"}',
    '{"version": "1.0"}', '{"range": "vers:cran/<2.0", "status": "affected"}', ""
  )) {
    back <- read_text(cdx_with_vulnerabilities(vuln(target(a, versions))), ".cdx.json")
    expect_identical(back$advisories, empty_advisories(), label = versions)
    expect_identical(dropped(back), not_listing, label = versions)
  }

  # These list it: the version affected, "affected" with neither a version
  # nor a range, and no versions at all, as sbom and R Observatory write it.
  for (t in c(
    target(a, '{"version": "0.9", "status": "affected"}, {"version": "1.0", "status": "affected"}'),
    target(a, '{"status": "affected"}'), paste0('{"ref": "', a, '"}')
  )) {
    back <- read_text(cdx_with_vulnerabilities(vuln(t)), ".cdx.json")
    expect_identical(back$advisories$id, "RSEC-2026-1", label = t)
    expect_identical(back$advisories$affects[[1]]$ref, a, label = t)
    expect_identical(dropped(back), character(), label = t)
  }

  # A vulnerability that lists one component and not another is read for the
  # first, and the second is counted.
  two <- sub(
    '{"type": "library", "bom-ref": "nover", "name": "nover"}',
    paste0(
      '{"type": "library", "bom-ref": "pkg:cran/b@2.0", "name": "b", "version": "2.0", "purl": "pkg:cran/b@2.0"}, ',
      '{"type": "library", "bom-ref": "nover", "name": "nover"}'
    ),
    cdx_with_vulnerabilities(vuln(paste0('{"ref": "', a, '"}'), target("pkg:cran/b@2.0", '{"version": "2.0", "status": "unaffected"}'))),
    fixed = TRUE
  )
  back <- read_text(two, ".cdx.json")
  expect_identical(back$advisories$affects[[1]]$ref, a)
  expect_identical(dropped(back), paste0(
    "1 component of a vulnerability entry in the document is given a version status or VEX statement ",
    "that is not an OSV advisory listing, so the entry was not read for it."
  ))
  expect_false(grepl("OSV lists b", spdx_tv(back), fixed = TRUE))

  # In XML too.
  xml <- paste0(
    '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">',
    '<metadata><component type="application" bom-ref="root"><name>root</name><version>1.0</version></component>',
    "</metadata>",
    '<components><component type="library" bom-ref="pkg:cran/a@1.0"><name>a</name><version>1.0</version>',
    "<purl>pkg:cran/a@1.0</purl></component></components>",
    "<vulnerabilities>",
    '<vulnerability bom-ref="v1"><id>RSEC-2026-1</id><source><name>OSV</name></source>',
    "<affects><target><ref>pkg:cran/a@1.0</ref><versions><version><version>1.0</version>",
    "<status>unaffected</status></version><version><range>vers:cran/&lt;0.9</range><status>affected</status>",
    "</version></versions></target></affects></vulnerability>",
    '<vulnerability bom-ref="v2"><id>RSEC-2026-2</id><source><name>OSV</name></source>',
    "<affects><target><ref>pkg:cran/a@1.0</ref><versions><version><version>1.0</version>",
    "<status>affected</status></version></versions></target></affects></vulnerability>",
    "</vulnerabilities></bom>"
  )
  back <- read_text(xml, ".cdx.xml")
  expect_identical(back$advisories$id, "RSEC-2026-2")
  expect_identical(dropped(back), not_listing)
})

test_that("an SPDX 3 association beside a VEX relationship for the same component is not read", {
  x <- two_advisory_sbom()
  doc <- jsonlite::parse_json(spdx3_jsonld(x))
  graph <- doc[["@graph"]]
  is_vuln <- vapply(graph, function(e) identical(e$type, "security_Vulnerability"), logical(1))
  vulns <- graph[is_vuln]
  rels <- Filter(function(e) identical(e$relationshipType, "hasAssociatedVulnerability"), graph)
  # RSEC-9000-1 is associated with fakepkg; a VEX statement from it says
  # that fakepkg is not affected.
  first <- vulns[[1]]
  assoc <- Filter(function(r) identical(r$to[[1]], first$spdxId), rels)[[1]]
  vex <- function(type, relationship, to, n) {
    list(
      type = type, spdxId = paste0(sub("#.*", "", first$spdxId), "#vex-", n), creationInfo = assoc$creationInfo,
      from = first$spdxId, relationshipType = relationship, to = list(to)
    )
  }
  with_vex <- function(...) {
    d <- doc
    d[["@graph"]] <- c(graph, list(...))
    read_text(jsonlite::toJSON(d, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx3.jsonld")
  }
  not_listing <- "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  dropped <- function(back) back$issues$message[back$issues$code == "read-advisories-dropped"]

  back <- with_vex(vex("security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect", assoc$from, 1))
  expect_identical(back$advisories$id, "RSEC-9000-2")
  expect_identical(dropped(back), not_listing)
  # Any VEX relationship counts, as any CycloneDX analysis does.
  back <- with_vex(vex("security_VexAffectedVulnAssessmentRelationship", "affects", assoc$from, 2))
  expect_identical(back$advisories$id, "RSEC-9000-2")
  expect_identical(dropped(back), not_listing)
  # One about another component leaves the association as it is.
  other <- Filter(function(r) !identical(r$to[[1]], first$spdxId), rels)[[1]]$from
  back <- with_vex(vex("security_VexNotAffectedVulnAssessmentRelationship", "doesNotAffect", other, 3))
  expect_identical(back$advisories$id, c("RSEC-9000-1", "RSEC-9000-2"))
  expect_identical(dropped(back), character())
})

test_that("a BOM-Link to another BOM is not a dangling relationship", {
  skip_on_cran()
  link <- "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:cran/a@1.0"
  txt <- paste0(
    '{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,',
    '"serialNumber": "urn:uuid:5e671687-395b-41f5-a30f-a58921a69b79",',
    '"metadata": {"timestamp": "2026-01-01T00:00:00Z"},',
    '"dependencies": [{"ref": "v1", "dependsOn": ["', link, '"]}],',
    '"vulnerabilities": [{"bom-ref": "v1", "id": "CVE-2021-44228", "source": {"name": "NVD"},',
    '"analysis": {"state": "not_affected", "justification": "code_not_reachable"},',
    '"affects": [{"ref": "', link, '"}]}]}'
  )
  expect_identical(nrow(findings_of(txt, ".cdx.json", "dangling-relationship")), 0L)
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_text(txt, tf)
  expect_identical(schema_validate(tf, "cyclonedx-json", "1.6")$status, "pass")
  # Any other end that the document does not define still dangles.
  missing <- sub(link, "pkg:cran/gone@1.0", txt, fixed = TRUE)
  expect_identical(findings_of(missing, ".cdx.json", "dangling-relationship")$location, "/dependencies/0/dependsOn/0")
})

test_that("SPDX 3 advisory values are checked too", {
  x <- two_advisory_sbom()
  doc <- jsonlite::parse_json(spdx3_jsonld(x))
  is_vuln <- vapply(doc[["@graph"]], function(e) identical(e$type, "security_Vulnerability"), logical(1))
  first <- which(is_vuln)[[1]]
  second <- which(is_vuln)[[2]]
  v <- doc[["@graph"]][[first]]
  v$name <- "A title, not an id"
  v$summary <- 5
  v$security_publishedTime <- "2099-13-01T00:00:00Z"
  v$externalRef[[1]]$locator <- list("https://example.org/a b")
  doc[["@graph"]][[first]] <- v
  # No securityOther identifier on osv.dev: not one of OSV's listings.
  doc[["@graph"]][[second]]$name <- NULL
  doc[["@graph"]][[second]]$externalIdentifier <- NULL
  back <- read_text(jsonlite::toJSON(doc, auto_unbox = TRUE, pretty = TRUE, null = "null"), ".spdx3.jsonld")
  adv <- back$advisories
  # The id is the securityOther identifier.
  expect_identical(adv$id, "RSEC-9000-1")
  expect_identical(adv$summary, NA_character_)
  expect_identical(adv$published, NA_character_)
  expect_identical(adv$source_url, NA_character_)
  expect_identical(adv$upstream, list("CVE-2099-0001"))
  expect_identical(adv$affects[[1]]$version, "1.0.0")
  expect_identical(
    back$issues$message[back$issues$code == "read-advisories-dropped"],
    "1 vulnerability entry in the document is not an OSV advisory listing, so it was not read."
  )
  dropped <- back$issues$message[back$issues$code == "read-values-dropped"]
  expect_true(grepl("URLs that are not valid IRI references", dropped, fixed = TRUE))
})

test_that("the docs say what is matched, where and what is sent", {
  topics <- c("sbom_package", "sbom_renv", "sbom_rsconnect", "sbom_nix", "sbom_advisories")
  docs <- gsub("[[:space:]]+", " ", rd_text(topics))
  for (phrase in c("exact versions", "Matching is local", "only their public ids")) {
    expect_true(all(grepl(phrase, docs, fixed = TRUE)), label = phrase)
  }
  builders <- docs[c("sbom_package", "sbom_renv", "sbom_rsconnect", "sbom_nix")]
  for (phrase in c(
    "Bioconductor", "all.zip", "sbom_advisories_error", "upstream flaw", "pkg:cran", "advisories-no-exact-version",
    "advisories-not-cran", "not installed", "local source", "GitHub"
  )) {
    expect_true(all(grepl(phrase, builders, fixed = TRUE)), label = phrase)
  }
  read_doc <- gsub("[[:space:]]+", " ", rd_text("read_sbom"))
  for (phrase in c("read-advisories-dropped", "not OSV advisory listings", "VEX")) {
    expect_true(grepl(phrase, read_doc, fixed = TRUE), label = phrase)
  }
  expect_identical(names(docs)[grepl(safety_words, docs, perl = TRUE)], character())
})
