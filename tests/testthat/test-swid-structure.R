swid_partial_note <- paste(
  "sbom does not bundle the ISO/IEC 19770-2:2015 schema, so the tag was checked against sbom's structural rules;",
  "set the option sbom.swid_xsd to a copy of the ISO schema to check it fully."
)

# A tag with the root attributes `root` and the children `body`, in the ISO
# namespace.
swid_text <- function(root = 'name="t" tagId="example.org-t"',
                      body = '<Entity name="Org" regid="example.org" role="tagCreator"/>') {
  paste0(
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" ', root, ">\n",
    paste0("  ", body, "\n", collapse = ""),
    "</SoftwareIdentity>\n"
  )
}

# The text parsed as schema_validate() parses a file.
swid_parse <- function(text) {
  xml2::read_xml(charToRaw(enc2utf8(text)), options = c("NOBLANKS", "NONET"))
}

swid_tag_file <- function(text, env = parent.frame()) {
  tf <- withr::local_tempfile(fileext = ".swidtag", .local_envir = env)
  write_text(text, tf)
  tf
}

findings_of <- function(location, message) {
  data.frame(location = location, message = message, stringsAsFactors = FALSE)
}

test_that("sbom's own tags break no structural rule, and are partial", {
  skip_on_cran()
  withr::local_options(sbom.swid_xsd = NULL)
  lib <- local_fake_lib(list())
  tags <- list(
    default = fixture_sbom(),
    minimal = minimal_sbom(),
    installed = sbom_installed(lib = fixture_lib()),
    regid = sbom_package(
      test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), organization = "Org", regid = "https://example.org"
    ),
    renv = sbom_renv(test_path("fixtures/renv/modern/renv.lock"), library = lib),
    rsconnect = sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json")),
    project = sbom(test_path("fixtures/project"), lib = lib),
    shiny = sbom_shiny(test_path("fixtures/shiny/app-r"), system = FALSE),
    nix = sbom_nix(test_path("fixtures/nix/rix-date.nix"), nix = FALSE, author = "A", timestamp = 0)
  )
  for (nm in names(tags)) {
    text <- swid_tag(tags[[nm]])
    expect_identical(swid_structure_findings(swid_parse(text)), empty_findings(), label = nm)
    expect_identical(
      schema_validate(swid_tag_file(text), "swid"),
      list(status = "partial", findings = findings_of("", swid_partial_note)),
      label = nm
    )
  }
})

test_that("the hand-written tags break no structural rule", {
  for (path in c(
    test_path("fixtures/third-party/swid/hand.swidtag"),
    test_path("fixtures/r-observatory/dplyr-1.2.1.swidtag")
  )) {
    expect_identical(schema_validate(path, "swid")$status, "partial", label = basename(path))
  }
  expect_identical(swid_structure_findings(swid_parse(swid_text())), empty_findings())
})

test_that("each structural rule gives fail, with a finding where it is broken", {
  cases <- list(
    `no tagId` = list(
      swid_text(root = 'name="t"'),
      findings_of("/SoftwareIdentity", "The SoftwareIdentity element has no tagId attribute.")
    ),
    `an Entity without role` = list(
      swid_text(body = c('<Entity name="Org" regid="example.org" role="tagCreator"/>', '<Entity name="Other"/>')),
      findings_of("/SoftwareIdentity/Entity[2]", "The Entity element has no role attribute.")
    ),
    `no tagCreator` = list(
      swid_text(body = '<Entity name="Org" regid="example.org" role="softwareCreator"/>'),
      findings_of("/SoftwareIdentity", "No Entity element has the role tagCreator.")
    ),
    `a Link without href` = list(
      swid_text(body = c('<Entity name="Org" regid="example.org" role="tagCreator"/>', '<Link rel="requires"/>')),
      findings_of("/SoftwareIdentity/Link[1]", "The Link element has no href attribute.")
    ),
    `a versionScheme that is not one token` = list(
      swid_text(root = 'name="t" tagId="t" version="2026.11" versionScheme="calendar based"'),
      findings_of("/SoftwareIdentity", "The versionScheme calendar based is not a single token.")
    ),
    `a non-integer tagVersion` = list(
      swid_text(root = 'name="t" tagId="t" tagVersion="1.5"'),
      findings_of("/SoftwareIdentity", "The tagVersion 1.5 is not an integer.")
    )
  )
  for (nm in names(cases)) {
    expect_identical(swid_structure_findings(swid_parse(cases[[nm]][[1]])), cases[[nm]][[2]], label = nm)
    expect_identical(
      schema_validate(swid_tag_file(cases[[nm]][[1]]), "swid"),
      list(status = "fail", findings = cases[[nm]][[2]]),
      label = nm
    )
  }
})

test_that("an empty token or integer, a missing name, and the root are checked too", {
  # NMTOKEN (rel, versionScheme), NMTOKENS (role) and xs:integer (tagVersion)
  # cannot be empty; a missing required attribute is a finding.
  text <- swid_text(
    root = 'name="" tagId="t" version="" versionScheme="" tagVersion=" "',
    body = c(
      '<Link href="swid:a" rel=" "/>',
      '<Entity role="tagCreator softwareCreator"/>',
      '<Entity name="" role=" "/>'
    )
  )
  expect_identical(swid_structure_findings(swid_parse(text)), findings_of(
    c(rep("/SoftwareIdentity", 2), "/SoftwareIdentity/Link[1]", "/SoftwareIdentity/Entity[1]",
      "/SoftwareIdentity/Entity[2]"),
    c(
      "The SoftwareIdentity element has an empty versionScheme attribute.",
      "The SoftwareIdentity element has an empty tagVersion attribute.",
      "The Link element has an empty rel attribute.",
      "The Entity element has no name attribute.",
      "The Entity element has an empty role attribute."
    )
  ))
  other <- '<SoftwareIdentity xmlns="urn:other" name="t" tagId="t"/>'
  expect_identical(swid_structure_findings(swid_parse(other)), findings_of(
    "", "The root element <SoftwareIdentity> is not in the ISO/IEC 19770-2:2015 namespace."
  ))
  expect_identical(swid_structure_findings(swid_parse("<bom/>")), findings_of(
    "", "The root element is <bom>, not <SoftwareIdentity>."
  ))
})

test_that("the rules are no stricter than the ISO schema", {
  # The schema allows an empty xs:string (name, tagId, version) and an empty
  # xs:anyURI (href), gives regid a default, and lets versionScheme be any
  # NMTOKEN.
  lenient <- swid_text(
    root = 'name="" tagId="" version="" versionScheme="calendar"',
    body = c('<Entity name="" role="tagCreator"/>', '<Link href="" rel="requires"/>')
  )
  expect_identical(swid_structure_findings(swid_parse(lenient)), empty_findings())
  expect_identical(
    schema_validate(swid_tag_file(lenient), "swid"),
    list(status = "partial", findings = findings_of("", swid_partial_note))
  )
})

test_that("the structural rules take linear time", {
  skip_on_cran()
  text <- swid_text(body = c('<Entity name="Org" role="tagCreator"/>', rep('<Link rel="requires"/>', 20000L)))
  doc <- swid_parse(text)
  time <- system.time(found <- swid_structure_findings(doc))[["elapsed"]]
  expect_identical(nrow(found), 20000L)
  expect_identical(found$location[[20000L]], "/SoftwareIdentity/Link[20000]")
  expect_identical(unique(found$message), "The Link element has no href attribute.")
  skip_unless_timing()
  # Under 10 s where it was written; the bound leaves room for a slow machine.
  expect_lt(time, 30)
})

test_that("tokens are read as the schema reads them, and other namespaces are left out", {
  # NMTOKEN and NMTOKENS values, and an xs:integer, may be padded with
  # whitespace; role holds several roles.
  padded <- swid_text(
    root = 'name="t" tagId="t" versionScheme=" semver " tagVersion=" +42 "',
    body = c('<Entity name="Org" regid="example.org" role=" softwareCreator  tagCreator "/>', '<Link href="swid:a" rel=" requires "/>')
  )
  expect_identical(swid_structure_findings(swid_parse(padded)), empty_findings())
  # A tagCreator, an Entity or a Link in another namespace is not one.
  foreign <- swid_text(body = c(
    '<x:Entity xmlns:x="urn:other" name="Org" regid="example.org" role="tagCreator"/>',
    '<x:Link xmlns:x="urn:other"/>',
    '<Entity name="Org" role="softwareCreator"/>'
  ))
  expect_identical(swid_structure_findings(swid_parse(foreign)), findings_of(
    "/SoftwareIdentity", "No Entity element has the role tagCreator."
  ))
  # A prefixed ISO namespace is the ISO namespace; Entity[2] counts Entity
  # elements only.
  prefixed <- paste0(
    '<s:SoftwareIdentity xmlns:s="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="t" tagId="t">',
    '<s:Entity name="Org" regid="example.org" role="tagCreator"/><s:Link href="swid:a" rel="requires"/>',
    '<s:Entity name="Other"/></s:SoftwareIdentity>'
  )
  expect_identical(swid_structure_findings(swid_parse(prefixed)), findings_of(
    "/SoftwareIdentity/Entity[2]", "The Entity element has no role attribute."
  ))
})

test_that("validate_sbom() reports a broken structural rule as a schema error at its location", {
  path <- swid_tag_file(swid_text(root = 'name="t" tagId="t" tagVersion="x"'))
  v <- validate_sbom(path, profile = "none")
  expect_identical(v$status, "fail")
  schema <- v$findings[v$findings$check == "schema", ]
  expect_identical(schema$severity, "error")
  expect_identical(schema$location, "/SoftwareIdentity")
  expect_identical(schema$message, "The tagVersion x is not an integer.")
})
