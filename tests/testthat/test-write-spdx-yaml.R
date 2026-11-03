test_that("SPDX YAML is the SPDX JSON document, in YAML", {
  skip_if_not_installed("yaml")
  x <- fixture_sbom()
  txt <- spdx_yaml(x)
  expect_match(txt, '^spdxVersion: "SPDX-2.3"\n')
  expect_match(txt, "\n$")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(txt, tf)
  expect_equal(spdx_yaml_read(tf), jsonlite::fromJSON(spdx_json(x), simplifyVector = FALSE))
})

test_that("YAML keeps quotes, backslashes, colons, hashes and newlines", {
  skip_if_not_installed("yaml")
  x <- fixture_sbom()
  x$metadata$notes <- c(x$metadata$notes, 'He said "a: b" \\ # c\nnext line.')
  tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(spdx_yaml(x), tf)
  expect_equal(spdx_yaml_read(tf)$comment, spdx_document(x)$comment)
})

test_that("SPDX YAML passes the SPDX schema for 2.2 and 2.3", {
  skip_if_not_installed("yaml"); skip_if_not_installed("jsonvalidate")
  for (v in c("2.2", "2.3")) {
    tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(spdx_yaml(fixture_sbom(), v), tf)
    expect_equal(schema_validate(tf, "spdx-yaml", v)$status, "pass", label = v)
  }
})

test_that("SPDX YAML matches R Observatory's dplyr 1.2.1 sample", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(spdx_yaml(parity_sbom()), tf)
  expect_equal(normalize_spdx(spdx_yaml_read(tf)),
               normalize_spdx(spdx_yaml_read(test_path("fixtures/r-observatory/dplyr-1.2.1.spdx.yaml"))))
})

test_that("yaml_emit() writes the R Observatory layout", {
  txt <- yaml_emit(list(
    a = "x", b = TRUE, c = list(), d = list("p", "q"),
    e = list(list(k = "v", n = list()), list(k = "w")),
    f = list(g = list(h = "i"))
  ))
  expect_equal(txt, paste0(
    'a: "x"\nb: true\nc: []\nd:\n  - "p"\n  - "q"\ne:\n',
    '  - k: "v"\n    n: []\n  - k: "w"\nf:\n  g:\n    h: "i"\n'
  ))
})

test_that("a one-element sequence stays an array", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".yaml")
  writeLines(c("creators:", '  - "Tool: sbom"', "packages:", '  - name: "a"'), tf)
  doc <- spdx_yaml_read(tf)
  expect_equal(doc$creators, list("Tool: sbom"))
  expect_equal(doc$packages, list(list(name = "a")))
  expect_equal(as.character(jsonlite::toJSON(doc, auto_unbox = TRUE)),
               '{"creators":["Tool: sbom"],"packages":[{"name":"a"}]}')
})

test_that("YAML text is UTF-8 and literal in a C locale", {
  skip_if_not_installed("yaml")
  local_c_ctype()
  dir <- local_latin1_pkg()
  x <- sbom_package(dir, lib = dirname(dir))
  txt <- spdx_yaml(x)
  expect_false(grepl("\\u00e1", txt, fixed = TRUE))
  expect_true(grepl("G\u00e1bor Cs\u00e1rdi", txt, fixed = TRUE))
  expect_identical(Encoding(txt), "UTF-8")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(txt, tf)
  doc <- spdx_yaml_read(tf)
  expect_true(any(grepl("G\u00e1bor Cs\u00e1rdi", unlist(doc$packages), fixed = TRUE)))
})

test_that("schema_validate() reports a missing yaml, bad YAML and schema failures", {
  skip_if_not_installed("jsonvalidate")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml"); write_text(spdx_yaml(fixture_sbom()), tf)
  local_mocked_bindings(has_yaml = function() FALSE)
  res <- schema_validate(tf, "spdx-yaml")
  expect_equal(res$status, "skipped")
  expect_equal(res$findings$message, "yaml is not installed, so the YAML document was not checked.")
})

test_that("schema_validate() fails bad YAML and a document that breaks the schema", {
  skip_if_not_installed("yaml"); skip_if_not_installed("jsonvalidate")
  bad <- withr::local_tempfile(fileext = ".spdx.yaml"); writeLines("a: [1, 2\nb: : :", bad)
  res <- schema_validate(bad, "spdx-yaml")
  expect_equal(res$status, "fail")
  expect_match(res$findings$message, "^The file is not valid YAML: .+\\.$")
  odd <- withr::local_tempfile(fileext = ".spdx.yaml"); writeLines('spdxVersion: "SPDX-2.3"', odd)
  expect_equal(schema_validate(odd, "spdx-yaml")$status, "fail")
})

test_that("the registry lists SPDX YAML", {
  r <- format_registry()[["spdx-yaml"]]
  expect_equal(r$extension, ".spdx.yaml")
  expect_equal(r$versions, c("2.2", "2.3"))
  expect_equal(r$media_type, "application/spdx+yaml")
  expect_true(r$all)
})

test_that("yaml_emit() quotes keys that are not plain words", {
  skip_if_not_installed("yaml")
  value <- list(`a: b` = "k", `has space` = "v", plain_1 = "w")
  txt <- yaml_emit(value)
  expect_match(txt, '^"a: b": "k"\n"has space": "v"\nplain_1: "w"\n$')
  expect_equal(yaml::yaml.load(txt), value)
})

test_that("yaml_emit() keeps look-alike strings as strings", {
  skip_if_not_installed("yaml")
  value <- list("yes", "null", "1.0", "- x", ": y", " lead")
  back <- yaml::yaml.load(
    yaml_emit(list(k = value)),
    handlers = list(seq = function(x) unname(as.list(x)))
  )
  expect_equal(back, list(k = value))
})

test_that("a YAML file cannot run R code, even with yaml.eval.expr set", {
  skip_if_not_installed("yaml")
  withr::local_options(yaml.eval.expr = TRUE)
  withr::local_envvar(SBOM_YAML_EXPR_RAN = NA)
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text('spdxVersion: !expr Sys.setenv(SBOM_YAML_EXPR_RAN = "yes")\n', tf)
  doc <- spdx_yaml_read(tf)
  expect_identical(Sys.getenv("SBOM_YAML_EXPR_RAN"), "")
  expect_identical(doc$spdxVersion, 'Sys.setenv(SBOM_YAML_EXPR_RAN = "yes")')
})

test_that("YAML numbers and booleans keep their text, except filesAnalyzed", {
  skip_if_not_installed("yaml")
  tf <- withr::local_tempfile(fileext = ".spdx.yaml")
  write_text(paste0(
    "spdxVersion: SPDX-2.3\n",
    "documentDescribes:\n  - 1.0\n  - true\n",
    "packages:\n",
    "  - name: no\n    versionInfo: 1.10\n    packageFileName: 12\n",
    "    filesAnalyzed: false\n",
    "  - name: b\n    filesAnalyzed: yes\n",
    "  - name: c\n    filesAnalyzed: \"false\"\n"
  ), tf)
  doc <- spdx_yaml_read(tf)
  expect_identical(doc$documentDescribes, list("1.0", "true"))
  p <- doc$packages
  expect_identical(p[[1]]$name, "no")
  expect_identical(p[[1]]$versionInfo, "1.10")
  expect_identical(p[[1]]$packageFileName, "12")
  expect_identical(p[[1]]$filesAnalyzed, FALSE)
  expect_identical(p[[2]]$filesAnalyzed, TRUE)
  # A quoted "false" is a string, which the schema then rejects.
  expect_identical(p[[3]]$filesAnalyzed, "false")
})
