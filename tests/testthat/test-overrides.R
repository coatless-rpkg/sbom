build_with <- function(ov) {
  sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = ov)
}

ov_row <- function(component = "cranpkg", field = "maintainer", value = "Someone Else",
                   asserted_by = "Me", reason = "Test") {
  data.frame(component = component, field = field, value = value,
             asserted_by = asserted_by, reason = reason)
}

test_that("a CSV override fills an unknown license and clears its issue", {
  csv <- withr::local_tempfile(fileext = ".csv")
  writeLines(c("component,field,value,asserted_by,reason",
               "localpkg,license_spdx,Apache-2.0,Legal team,Reviewed LICENSE file 2026-11-01"), csv)
  x <- sbom_package(test_path("fixtures/pkgs/srcpkg"), lib = fixture_lib(), overrides = csv)
  comps <- sbom_components(x)
  row <- comps$name == "localpkg"
  expect_equal(comps$license_spdx[row], "Apache-2.0")
  expect_equal(comps$asserted[row][[1]]$asserted_by, "Legal team")
  expect_false(any(sbom_issues(x)$code == "license-no-spdx" & sbom_issues(x)$ref == "local/localpkg"))
})

test_that("an override that contradicts found data is recorded", {
  x <- build_with(ov_row())
  expect_equal(sbom_issues(x)$message[sbom_issues(x)$code == "override-conflict"],
               "The maintainer of cranpkg was Grace Hopper as found and is Someone Else as asserted by Me.")
  expect_equal(sbom_issues(x)$severity[sbom_issues(x)$code == "override-conflict"], "info")
})

test_that("bad overrides fail loudly", {
  expect_error(build_with(ov_row(component = "nope", field = "version", value = "1")), "nope")
  expect_error(build_with(ov_row(field = "color")), "color")
})

test_that("errors name the data row, and missing columns are reported", {
  ov <- rbind(ov_row(), ov_row(component = "nope"))
  expect_error(build_with(ov), "row 2")
  expect_error(build_with(ov_row(field = "color")), "row 1")
  expect_error(build_with(ov_row()[, c("component", "field")]), "value")
  expect_error(build_with(ov_row(value = NA)), "row 1")
  expect_error(build_with(42), "overrides")
  expect_error(build_with(file.path(tempdir(), "missing.csv")), "does not exist")
})

test_that("a component matches by ref, and an ambiguous name is an error", {
  x <- build_with(ov_row(component = "pkg:cran/cranpkg@1.2.0", field = "supplier_name",
                         value = "Acme"))
  comps <- sbom_components(x)
  expect_equal(comps$supplier_name[comps$ref == "pkg:cran/cranpkg@1.2.0"], "Acme")

  base <- build_with(NULL)
  dup <- base$components[base$components$ref == "pkg:cran/cranpkg@1.2.0", ]
  dup$ref <- "unknown/cranpkg"
  base$components <- rbind(base$components, dup)
  expect_error(apply_overrides(base, ov_row()), "unknown/cranpkg")
  expect_equal(apply_overrides(base, ov_row(component = "unknown/cranpkg"))$components$maintainer[
    base$components$ref == "unknown/cranpkg"], "Someone Else")
})

test_that("rows append in order and a later row wins", {
  ov <- rbind(ov_row(value = "First"), ov_row(value = "Second", asserted_by = "You"))
  x <- build_with(ov)
  comps <- sbom_components(x)
  row <- comps$ref == "pkg:cran/cranpkg@1.2.0"
  expect_equal(comps$maintainer[row], "Second")
  expect_equal(comps$asserted[row][[1]]$value, c("First", "Second"))
  expect_equal(names(comps$asserted[row][[1]]), c("field", "value", "asserted_by", "reason"))
  conflicts <- sbom_issues(x)$message[sbom_issues(x)$code == "override-conflict"]
  expect_match(conflicts[2], "was First as found and is Second", fixed = TRUE)
})

test_that("asserting a license extends the comment and clears both license issues", {
  x <- build_with(ov_row(component = "localpkg", field = "license_spdx", value = "Apache-2.0",
                         asserted_by = "Legal", reason = "Reviewed"))
  comps <- sbom_components(x)
  comment <- comps$license_comment[comps$name == "localpkg"]
  expect_match(comment, " Asserted by Legal: Reviewed.", fixed = TRUE)
  iss <- sbom_issues(x)
  expect_false(any(iss$ref == "local/localpkg" &
                     iss$code %in% c("license-no-spdx", "license-missing")))
})

test_that("asserting a supplier clears supplier-unknown", {
  before <- sbom_issues(build_with(NULL))
  target <- before$ref[before$code == "supplier-unknown"][1]
  skip_if(is.na(target))
  x <- build_with(ov_row(component = target, field = "supplier_name", value = "Acme"))
  iss <- sbom_issues(x)
  expect_false(any(iss$ref == target & iss$code == "supplier-unknown"))
})

test_that("NULL overrides change nothing", {
  x <- build_with(NULL)
  expect_identical(apply_overrides(x, NULL), x)
})

test_that("an override names an R package, not a system library of the same name", {
  lib <- local_fake_lib(list(openssl = c(Version = "2.0", License = "MIT", SystemRequirements = "OpenSSL")))
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    list(data.frame(sysreq = "openssl", packages = I(list(character()))))
  })
  ov <- data.frame(component = "openssl", field = "supplier_name", value = "Acme",
                   asserted_by = "QA", reason = "Checked")
  x <- sbom_installed("openssl", lib = lib, overrides = ov)
  comps <- sbom_components(x)
  expect_true("system/openssl" %in% comps$ref)
  expect_equal(comps$supplier_name[comps$ecosystem == "local" & comps$name == "openssl"], "Acme")
  expect_true(is.na(comps$supplier_name[comps$ref == "system/openssl"]))
})

test_that("an asserted version is exact, and an asserted CRAN package URL sets the ecosystem", {
  base <- build_with(NULL)
  comps <- base$components
  local <- comps$ref[comps$name == "localpkg"]
  expect_identical(comps$ecosystem[comps$ref == local], "local")
  at <- function(x) x$components[x$components$ref == local, , drop = FALSE]

  # A version stated as a minimum becomes exact when a version is asserted.
  minimum <- base
  minimum$components$version_is[minimum$components$ref == local] <- "minimum"
  got <- at(apply_overrides(minimum, ov_row(component = "localpkg", field = "version", value = "0.9.1")))
  expect_identical(got$version, "0.9.1")
  expect_identical(got$version_is, "exact")
  expect_identical(got$ecosystem, "local")

  got <- at(apply_overrides(base, ov_row(component = "localpkg", field = "purl", value = "pkg:cran/localpkg@0.1.0")))
  expect_identical(got$ecosystem, "cran")
  bioc <- "pkg:cran/localpkg@0.1.0?repository_url=https://bioconductor.org/packages/3.20/bioc"
  expect_identical(at(apply_overrides(base, ov_row(component = "localpkg", field = "purl", value = bioc)))$ecosystem,
                   "bioconductor")
  # Any other package URL leaves the ecosystem as it was.
  github <- "pkg:github/someone/localpkg@abc123"
  expect_identical(at(apply_overrides(base, ov_row(component = "localpkg", field = "purl", value = github)))$ecosystem,
                   "local")
  # So do the other fields.
  expect_identical(at(apply_overrides(base, ov_row(component = "localpkg")))$ecosystem, "local")
  expect_identical(at(apply_overrides(base, ov_row(component = "localpkg")))$version_is,
                   comps$version_is[comps$ref == local])
})

# A CRAN package rootpkg 0.1.0 that imports midpkg (>= 2.0), from a library
# where midpkg 1.0 compiles in hdrpkg 3.0: refs that carry versions, a
# component inside another, and issues on midpkg.
identity_sbom <- function(overrides = NULL, env = parent.frame()) {
  dir <- withr::local_tempdir(.local_envir = env)
  pkg <- file.path(dir, "rootpkg")
  dir.create(pkg)
  write_text(
    "Package: rootpkg\nVersion: 0.1.0\nRepository: CRAN\nLicense: MIT\nImports: midpkg (>= 2.0)\n",
    file.path(pkg, "DESCRIPTION")
  )
  lib <- write_fake_lib(file.path(dir, "lib"), list(
    midpkg = c(Version = "1.0", Repository = "CRAN", License = "MIT", LinkingTo = "hdrpkg", Imports = "hdrpkg"),
    hdrpkg = c(Version = "3.0", Repository = "CRAN", License = "MIT", Maintainer = "A B <a@example.org>")
  ))
  sbom_package(pkg, lib = lib, author = "Tester", timestamp = 0, system = FALSE, overrides = overrides)
}

# Every ref an SBOM names, wherever it names one.
all_refs <- function(x) {
  refs <- c(
    x$components$ref, x$components$parent_ref, x$relationships$from, x$relationships$to,
    x$issues$ref, x$metadata$root, unlist(lapply(x$advisories$affects, function(a) a$ref))
  )
  refs[!is.na(refs)]
}

test_that("a version override moves the purl, the ref and every reference to the ref", {
  before <- identity_sbom()
  expect_true("pkg:cran/midpkg@1.0#embedded/hdrpkg" %in% before$components$ref)
  x <- identity_sbom(ov_row(component = "midpkg", field = "version", value = "2.1"))
  comps <- x$components
  mid <- comps[comps$name == "midpkg", , drop = FALSE]
  expect_identical(mid$ref, "pkg:cran/midpkg@2.1")
  expect_identical(mid$purl, "pkg:cran/midpkg@2.1")
  expect_identical(mid$version, "2.1")
  expect_false(any(grepl("midpkg@1.0", all_refs(x), fixed = TRUE)))
  # The component inside it moves with it.
  inside <- comps[comps$parent_ref %in% "pkg:cran/midpkg@2.1", , drop = FALSE]
  expect_identical(inside$ref, "pkg:cran/midpkg@2.1#embedded/hdrpkg")
  rels <- x$relationships
  expect_identical(
    rels[rels$from == "pkg:cran/midpkg@2.1" | rels$to == "pkg:cran/midpkg@2.1", c("from", "to", "field")],
    data.frame(
      from = c(rep("pkg:cran/midpkg@2.1", 3), "pkg:cran/rootpkg@0.1.0"),
      to = c("pkg:cran/hdrpkg@3.0", "pkg:cran/hdrpkg@3.0", "pkg:cran/midpkg@2.1#embedded/hdrpkg", "pkg:cran/midpkg@2.1"),
      field = c("Imports", "LinkingTo", "contains", "Imports"),
      row.names = c(1L, 2L, 3L, 4L), stringsAsFactors = FALSE
    )
  )
  # Its issues move too; the unsatisfied constraint is not answered by the
  # override, so it stays.
  expect_setequal(
    x$issues$code[x$issues$ref == "pkg:cran/midpkg@2.1"],
    c("maintainer-missing", "constraint-unsatisfied", "override-conflict")
  )
  # The tables stay in radix order.
  expect_identical(comps$ref, sort(comps$ref, method = "radix"))
  expect_identical(order(rels$from, rels$to, rels$field, method = "radix"), seq_len(nrow(rels)))
  expect_identical(rownames(comps), as.character(seq_len(nrow(comps))))
  # Every format still validates, with no relationship left dangling.
  expect_valid_in_every_format(x, "moved ref")
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf)
  expect_false("dangling-relationship" %in% validate_sbom(tf)$findings$check)
})

test_that("a version override on the root moves metadata$root", {
  x <- identity_sbom(ov_row(component = "rootpkg", field = "version", value = "0.2.0"))
  expect_identical(x$metadata$root, "pkg:cran/rootpkg@0.2.0")
  expect_false(any(grepl("rootpkg@0.1.0", all_refs(x), fixed = TRUE)))
  expect_identical(x$components$ref[x$components$is_root], "pkg:cran/rootpkg@0.2.0")
  expect_valid_in_every_format(x, "moved root")
})

test_that("later rows name a moved component by the ref it was built with", {
  ov <- rbind(
    ov_row(component = "midpkg", field = "version", value = "2.1"),
    ov_row(component = "pkg:cran/midpkg@1.0", field = "supplier_name", value = "Acme")
  )
  x <- identity_sbom(ov)
  expect_identical(x$components$supplier_name[x$components$ref == "pkg:cran/midpkg@2.1"], "Acme")
})

# minimal_sbom() with extra library components, each given as
# c(ref, name, version, purl).
with_rows <- function(...) {
  x <- minimal_sbom()
  for (r in list(...)) {
    x$components <- rbind(x$components, component_row(
      ref = r[[1]], name = r[[2]], version = if (!is.na(r[[3]])) r[[3]],
      version_is = if (!is.na(r[[3]])) "exact", type = "library", ecosystem = "cran",
      purl = if (!is.na(r[[4]])) r[[4]]
    ))
  }
  x$components <- x$components[order(x$components$ref, method = "radix"), , drop = FALSE]
  rownames(x$components) <- NULL
  x
}

test_that("a purl without a version gains one only for cran, github, gitlab and bitbucket", {
  bioc <- "?repository_url=https://bioconductor.org/packages/3.20/bioc"
  x <- with_rows(
    c("pkg:cran/nover", "nover", NA, "pkg:cran/nover"),
    c("pkg:github/me/ghpkg", "ghpkg", NA, "pkg:github/me/ghpkg"),
    c("pkg:gitlab/me/glpkg", "glpkg", NA, "pkg:gitlab/me/glpkg"),
    c("pkg:bitbucket/me/bbpkg", "bbpkg", NA, "pkg:bitbucket/me/bbpkg"),
    c("pkg:npm/npmpkg", "npmpkg", NA, "pkg:npm/npmpkg"),
    c("pkg:generic/genpkg", "genpkg", NA, "pkg:generic/genpkg"),
    c("pkg:github/me/shapkg@abc123", "shapkg", "0.1", "pkg:github/me/shapkg@abc123"),
    c(paste0("pkg:cran/biocpkg@1.0", bioc), "biocpkg", "1.0", paste0("pkg:cran/biocpkg@1.0", bioc)),
    c("local/locpkg", "locpkg", "1.0", "pkg:cran/locpkg@1.0")
  )
  names <- c("nover", "ghpkg", "glpkg", "bbpkg", "npmpkg", "genpkg", "shapkg", "biocpkg", "locpkg")
  ov <- do.call(rbind, lapply(names, function(n) ov_row(component = n, field = "version", value = "2.0")))
  got <- apply_overrides(x, ov)$components
  purl_of <- function(n) got$purl[got$name == n]
  ref_of <- function(n) got$ref[got$name == n]
  for (n in c("nover", "ghpkg", "glpkg", "bbpkg")) {
    expect_identical(purl_of(n), paste0(x$components$purl[x$components$name == n], "@2.0"), label = n)
    expect_identical(ref_of(n), purl_of(n), label = n)
  }
  # Other types are left as they are, and so is a purl whose version is not
  # the component's, such as a commit.
  for (n in c("npmpkg", "genpkg", "shapkg")) {
    expect_identical(purl_of(n), x$components$purl[x$components$name == n], label = n)
    expect_identical(ref_of(n), x$components$ref[x$components$name == n], label = n)
  }
  expect_identical(purl_of("biocpkg"), paste0("pkg:cran/biocpkg@2.0", bioc))
  expect_identical(ref_of("biocpkg"), purl_of("biocpkg"))
  # A ref that is not the purl stays.
  expect_identical(purl_of("locpkg"), "pkg:cran/locpkg@2.0")
  expect_identical(ref_of("locpkg"), "local/locpkg")
})

test_that("a version override never rewrites a purl that a purl row asserts, and a purl ref follows that purl", {
  rows <- list(
    ov_row(component = "b", field = "version", value = "3.0"),
    ov_row(component = "b", field = "purl", value = "pkg:cran/b@9.9")
  )
  for (ov in list(do.call(rbind, rows), do.call(rbind, rev(rows)))) {
    got <- apply_overrides(minimal_sbom(), ov)
    comps <- got$components
    expect_identical(comps$purl[comps$name == "b"], "pkg:cran/b@9.9")
    expect_identical(comps$version[comps$name == "b"], "3.0")
    expect_identical(comps$ref[comps$name == "b"], "pkg:cran/b@9.9")
    expect_identical(got$relationships$to, "pkg:cran/b@9.9")
  }
})

test_that("a purl ref given a version and an explicit purl moves to that purl, with every reference", {
  rows <- list(
    ov_row(component = "midpkg", field = "version", value = "2.1"),
    ov_row(component = "midpkg", field = "purl", value = "pkg:cran/midpkg@2.1?repository_url=https://cran.example.org")
  )
  want <- "pkg:cran/midpkg@2.1?repository_url=https://cran.example.org"
  for (ov in list(do.call(rbind, rows), do.call(rbind, rev(rows)))) {
    x <- identity_sbom(ov)
    comps <- x$components
    mid <- comps[comps$name == "midpkg", , drop = FALSE]
    expect_identical(mid$ref, want)
    expect_identical(mid$purl, want)
    expect_false(any(grepl("midpkg@1.0", all_refs(x), fixed = TRUE)))
    expect_identical(comps$ref[comps$parent_ref %in% want], paste0(want, "#embedded/hdrpkg"))
    expect_identical(x$relationships$to[x$relationships$from == x$metadata$root], want)
    expect_true(all(c("maintainer-missing", "constraint-unsatisfied") %in% x$issues$code[x$issues$ref == want]))
    expect_identical(comps$ref, sort(comps$ref, method = "radix"))
  }
  # A purl that another component has as its ref is the same error.
  expect_error(
    identity_sbom(ov_row(component = "midpkg", field = "purl", value = "pkg:cran/hdrpkg@3.0")),
    "would change the ref of \"pkg:cran/midpkg@1.0\" to \"pkg:cran/hdrpkg@3.0\""
  )
})

test_that("a version override renames a package file named for the old version and drops any other", {
  x <- identity_sbom(ov_row(component = "midpkg", field = "version", value = "2.1"))
  expect_identical(x$components$package_file_name[x$components$name == "midpkg"], "midpkg_2.1.tar.gz")
  for (ext in c(".tgz", ".zip")) {
    y <- with_rows(c("pkg:cran/binpkg@1.0", "binpkg", "1.0", "pkg:cran/binpkg@1.0"))
    y$components$package_file_name[y$components$name == "binpkg"] <- paste0("binpkg_1.0", ext)
    got <- apply_overrides(y, ov_row(component = "binpkg", field = "version", value = "1.1"))$components
    expect_identical(got$package_file_name[got$name == "binpkg"], paste0("binpkg_1.1", ext), label = ext)
  }
  # A file of another name is not known to be the new version's.
  y <- with_rows(c("pkg:cran/binpkg@1.0", "binpkg", "1.0", "pkg:cran/binpkg@1.0"))
  y$components$package_file_name[y$components$name == "binpkg"] <- "binpkg-latest.tar.gz"
  got <- apply_overrides(y, ov_row(component = "binpkg", field = "version", value = "1.1"))$components
  expect_true(is.na(got$package_file_name[got$name == "binpkg"]))
  # The same version changes nothing.
  got <- apply_overrides(y, ov_row(component = "binpkg", field = "version", value = "1.0"))$components
  expect_identical(got$package_file_name[got$name == "binpkg"], "binpkg-latest.tar.gz")
})

test_that("a version override that would give a component another's ref is an error", {
  x <- with_rows(c("pkg:cran/b@3.0", "b", "3.0", "pkg:cran/b@3.0"))
  expect_error(
    apply_overrides(x, ov_row(component = "pkg:cran/b@2.0", field = "version", value = "3.0")),
    "Override row 1 would change the ref of \"pkg:cran/b@2.0\" to \"pkg:cran/b@3.0\", which is already the ref of another component.",
    fixed = TRUE
  )
})

test_that("an asserted field clears the issues it answers and keeps the rest", {
  # A root without a version, which a library would skip.
  dir <- withr::local_tempdir()
  write_text("Package: nover\nRepository: CRAN\nLicense: MIT\nImports: rspmpkg, gitpkg\n", file.path(dir, "DESCRIPTION"))
  lib <- local_fake_lib(list(
    rspmpkg = c(Version = "1.0", Repository = "RSPM", License = "MIT", Maintainer = "A <a@example.org>"),
    gitpkg = c(Version = "1.0", RemoteType = "git", RemoteUrl = "https://example.org/g.git", License = "MIT",
               Maintainer = "A <a@example.org>")
  ))
  x <- sbom_package(dir, lib = lib, author = "Tester", timestamp = 0, system = FALSE, embedded = FALSE)
  # The codes of a component's issues, but for the conflicts an override records.
  codes <- function(x, name) {
    ref <- x$components$ref[x$components$name == name]
    sort(setdiff(x$issues$code[x$issues$ref == ref], "override-conflict"), method = "radix")
  }
  expect_identical(codes(x, "nover"), c("maintainer-missing", "version-missing"))
  expect_identical(codes(x, "rspmpkg"), "purl-inferred")
  expect_identical(codes(x, "gitpkg"), "source-git")
  ov <- rbind(
    ov_row(component = "nover", field = "version", value = "1.0"),
    ov_row(component = "rspmpkg", field = "purl", value = "pkg:cran/rspmpkg@1.0?repository_url=https://p3m.dev/cran/latest"),
    ov_row(component = "gitpkg", field = "purl", value = "pkg:generic/gitpkg@1.0")
  )
  y <- apply_overrides(x, ov)
  # The versionless purl gains the version, and the version issue goes; the
  # maintainer issue stays.
  expect_identical(y$components$ref[y$components$name == "nover"], "pkg:cran/nover@1.0")
  expect_identical(y$metadata$root, "pkg:cran/nover@1.0")
  expect_identical(codes(y, "nover"), "maintainer-missing")
  expect_identical(codes(y, "rspmpkg"), character())
  # That gitpkg came from a git repository stays true, so the issue is
  # reworded, not removed.
  expect_identical(codes(y, "gitpkg"), "source-git")
  git <- y$issues[y$issues$code == "source-git", , drop = FALSE]
  expect_identical(git$message, "gitpkg was installed from a git repository; its package URL is asserted by an override.")
  expect_identical(git$severity, "info")
  z <- apply_overrides(y, ov_row(component = "nover", field = "maintainer", value = "M <m@example.org>"))
  expect_identical(codes(z, "nover"), character())

  # R's unknown version and a JavaScript library's missing one.
  m <- minimal_sbom()
  m$issues <- add_issue(m$issues, "R", "version", "r-version-unknown", "R is listed without a version.")
  m$issues <- add_issue(m$issues, "R", "license", "license-missing", "R declares no license.")
  got <- apply_overrides(m, ov_row(component = "R", field = "version", value = "4.4.0"))
  expect_identical(got$issues$code, "license-missing")
  js <- with_rows(c("pkg:cran/a@1.0#js/jquery", "jquery", NA, NA))
  js$components$parent_ref[js$components$name == "jquery"] <- "pkg:cran/a@1.0"
  js$issues <- add_issue(js$issues, "pkg:cran/a@1.0#js/jquery", "version", "javascript-version-missing", "a declares jquery without a usable version.")
  got <- apply_overrides(js, ov_row(component = "pkg:cran/a@1.0#js/jquery", field = "version", value = "3.7.1"))
  expect_identical(nrow(got$issues), 0L)
})

test_that("a version override on R gives the base packages its version", {
  x <- sbom_installed(lib = fixture_lib(), r_version = "4.4.0", timestamp = 0, system = FALSE)
  y <- apply_overrides(x, ov_row(component = "R", field = "version", value = "4.5.0",
                                 asserted_by = "Ops", reason = "Upgraded"))
  base <- y$components[y$components$parent_ref %in% "R", , drop = FALSE]
  expect_gt(nrow(base), 0L)
  expect_true(all(base$version == "4.5.0" & base$version_is == "exact"))
  # Their evidence stays as built, and each records the assertion.
  expect_identical(base$evidence, x$components$evidence[x$components$parent_ref %in% "R"])
  for (a in base$asserted) {
    expect_identical(a, data.frame(field = "version", value = "4.5.0", asserted_by = "Ops", reason = "Upgraded"))
  }
  # From a minimum too: the asserted version is exact.
  z <- apply_overrides(fixture_sbom(), ov_row(component = "R", field = "version", value = "4.5.0"))
  base <- z$components[z$components$parent_ref %in% "R", , drop = FALSE]
  expect_true(all(base$version == "4.5.0" & base$version_is == "exact"))
})

test_that("an uninstalled dependency given a version and a CRAN purl matches its advisory, with every ref agreeing", {
  dir <- withr::local_tempdir()
  pkg <- file.path(dir, "rootpkg")
  dir.create(pkg)
  write_text("Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: fakepkg\n", file.path(pkg, "DESCRIPTION"))
  lib <- file.path(dir, "lib")
  dir.create(lib)
  ov <- rbind(
    ov_row(component = "fakepkg", field = "version", value = "1.0.0"),
    ov_row(component = "fakepkg", field = "purl", value = "pkg:cran/fakepkg@1.0.0")
  )
  build <- function(ov) {
    sbom_package(pkg, lib = lib, author = "Tester", timestamp = 0, embedded = FALSE, system = FALSE,
                 overrides = ov, advisories = test_path("fixtures", "osv", "all.zip"))
  }
  x <- build(ov)
  fake <- x$components[x$components$name == "fakepkg", , drop = FALSE]
  expect_identical(fake$purl, "pkg:cran/fakepkg@1.0.0")
  # The controller's ruling on Task 3: only a ref that was the component's
  # purl follows the purl. unknown/fakepkg never was one, so it stays, as
  # Plan 7 documents, and everything that names it agrees with it.
  expect_identical(fake$ref, "unknown/fakepkg")
  expect_identical(fake$version, "1.0.0")
  expect_identical(x$advisories$id, "RSEC-9000-1")
  expect_identical(x$advisories$affects[[1]]$ref, fake$ref)
  expect_identical(x$relationships$to[x$relationships$from == x$metadata$root], fake$ref)
  tf <- withr::local_tempfile(fileext = ".cdx.json")
  write_sbom(x, tf)
  doc <- jsonlite::read_json(tf)
  bom_refs <- vapply(doc$components, function(c) c$`bom-ref`, "")
  affects <- vapply(doc$vulnerabilities[[1]]$affects, function(a) a$ref, "")
  expect_identical(affects, fake$ref)
  expect_true(all(affects %in% bom_refs))
  expect_false("dangling-relationship" %in% validate_sbom(tf)$findings$check)
  # With both the version and the purl asserted, the issue that it is missing
  # says so, as info.
  missing <- x$issues[x$issues$code == "dependency-not-installed", , drop = FALSE]
  expect_identical(
    missing$message,
    "fakepkg is named as a dependency but is not installed; its version and purl are asserted by an override."
  )
  expect_identical(missing$severity, "info")
  expect_identical(missing$ref, "unknown/fakepkg")
  # Either alone leaves it as it is.
  plain <- paste0(
    "fakepkg is named as a dependency of rootpkg but is not installed in the library sbom read, ",
    "so its version and source are unknown."
  )
  for (one in list(ov[1, ], ov[2, ])) {
    missing <- build(one)$issues
    missing <- missing[missing$code == "dependency-not-installed", , drop = FALSE]
    expect_identical(missing$message, plain)
    expect_identical(missing$severity, "warning")
  }
})

test_that("a moved ref moves the advisory targets an SBOM already lists", {
  x <- widgetframe_sbom()
  y <- apply_overrides(x, ov_row(component = "widgetframe", field = "version", value = "0.3.2"))
  expect_identical(y$advisories$affects[[1]]$ref, "pkg:cran/widgetframe@0.3.2")
  expect_true("pkg:cran/widgetframe@0.3.2" %in% y$components$ref)
})

# The messages of the issues of `x` with `code`.
messages_of <- function(x, code) x$issues$message[x$issues$code == code]

test_that("an asserted purl rewords source-git, and a CRAN purl still makes the package a CRAN one", {
  # The reviewer's probe.
  dir <- withr::local_tempdir()
  write_text("Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: gitpkg\n", file.path(dir, "DESCRIPTION"))
  lib <- local_fake_lib(list(gitpkg = c(
    Version = "1.0", RemoteType = "git", RemoteUrl = "https://example.org/g.git", License = "MIT",
    Maintainer = "A <a@example.org>"
  )))
  x <- sbom_package(dir, lib = lib, author = "Tester", timestamp = 0, system = FALSE, embedded = FALSE,
                    overrides = ov_row(component = "gitpkg", field = "purl", value = "pkg:cran/gitpkg@1.0"))
  git <- x$issues[x$issues$code == "source-git", , drop = FALSE]
  expect_identical(git$ref, "git/gitpkg")
  expect_identical(git$message, "gitpkg was installed from a git repository; its package URL is asserted by an override.")
  expect_identical(git$severity, "info")
  expect_identical(x$components$ecosystem[x$components$name == "gitpkg"], "cran")
})

test_that("the issues that a dependency is not locked or not recorded are reworded too", {
  dir <- withr::local_tempdir()
  lock <- list(R = list(Version = "4.5.0"), Packages = list(cli = list(
    Package = "cli", Version = "3.6.6", Source = "Repository", Repository = "CRAN",
    License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>", Requirements = list("zzz")
  )))
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  both <- function(name) {
    rbind(
      ov_row(component = name, field = "version", value = "1.0"),
      ov_row(component = name, field = "purl", value = paste0("pkg:cran/", name, "@1.0"))
    )
  }
  x <- sbom_renv(file.path(dir, "renv.lock"), library = local_fake_lib(list()), timestamp = 0,
                 system = FALSE, embedded = FALSE, overrides = both("zzz"))
  expect_identical(
    messages_of(x, "dependency-not-locked"),
    "zzz is named as a dependency but is not in renv.lock; its version and purl are asserted by an override."
  )
  expect_identical(x$issues$severity[x$issues$code == "dependency-not-locked"], "info")
  y <- sbom_rsconnect(test_path("fixtures/rsconnect/manifest.json"), overrides = both("notrecorded"))
  expect_identical(
    messages_of(y, "dependency-not-recorded"),
    "notrecorded is named as a dependency but is not in manifest.json; its version and purl are asserted by an override."
  )
  expect_identical(y$issues$severity[y$issues$code == "dependency-not-recorded"], "info")
})

test_that("a version override drops the hashes of the version found", {
  tmp <- withr::local_tempdir()
  tarball <- file.path(tmp, "srcpkg_0.1.0.tar.gz")
  withr::with_dir(test_path("fixtures/pkgs"), utils::tar(tarball, "srcpkg", compression = "gzip"))
  build <- function(version) {
    sbom_package(tarball, lib = fixture_lib(), timestamp = 0, system = FALSE,
                 overrides = ov_row(component = "srcpkg", field = "version", value = version))
  }
  root <- function(x) x$components[x$components$is_root, , drop = FALSE]
  x <- build("0.2.0")
  expect_identical(nrow(root(x)$hashes[[1]]), 0L)
  expect_identical(root(x)$package_file_name, "srcpkg_0.2.0.tar.gz")
  expect_valid_in_every_format(x, "no hashes")
  # The version found, asserted again, keeps them.
  same <- build("0.1.0")
  expect_identical(root(same)$hashes[[1]]$content, cli::hash_file_sha256(tarball))
  expect_identical(root(same)$package_file_name, "srcpkg_0.1.0.tar.gz")
})

test_that("two version rows move the purl and ref twice", {
  ov <- rbind(
    ov_row(component = "midpkg", field = "version", value = "2.1"),
    ov_row(component = "midpkg", field = "version", value = "2.2")
  )
  x <- identity_sbom(ov)
  mid <- x$components[x$components$name == "midpkg", , drop = FALSE]
  expect_identical(c(mid$ref, mid$purl, mid$package_file_name), c("pkg:cran/midpkg@2.2", "pkg:cran/midpkg@2.2", "midpkg_2.2.tar.gz"))
  expect_true("pkg:cran/midpkg@2.2#embedded/hdrpkg" %in% x$components$ref)
  expect_false(any(grepl("midpkg@(1.0|2.1)", all_refs(x))))
  expect_identical(sum(x$issues$code == "override-conflict" & x$issues$ref == "pkg:cran/midpkg@2.2"), 2L)
})

test_that("a blank override value is missing, as it is in a CSV file", {
  expect_error(
    apply_overrides(minimal_sbom(), ov_row(component = "b", field = "purl", value = "")),
    "Override row 1 has no value"
  )
  expect_error(
    apply_overrides(minimal_sbom(), ov_row(component = "b", field = "version", value = "  ")),
    "Override row 1 has no value"
  )
})

test_that("the issue on linked system libraries without a version follows the asserted versions", {
  lib <- local_fake_lib(list(a = c(Version = "1.0"), b = c(Version = "1.0")))
  for (p in c("a", "b")) {
    dir.create(file.path(lib, p, "libs"))
    write_text("", file.path(lib, p, "libs", paste0(p, ".so")))
  }
  local_mocked_bindings(sys_linked_libraries = function(so) {
    if (grepl("a.so", so, fixed = TRUE)) c("/usr/lib/libssl.48.dylib", "/usr/lib/libz.1.dylib") else "/usr/lib/libz.1.dylib"
  })
  build <- function(ov) sbom_installed(c("a", "b"), lib = lib, timestamp = 0, overrides = ov)
  expect_identical(
    messages_of(build(NULL), "system-version-unknown"),
    "The versions of the linked system libraries libssl and libz are unknown, because sbom found no package manager that owns them."
  )
  libz <- ov_row(component = "system/libz", field = "version", value = "1.3.1")
  partly <- build(libz)
  expect_identical(
    messages_of(partly, "system-version-unknown"),
    "The version of the linked system library libssl is unknown, because sbom found no package manager that owns it."
  )
  expect_identical(partly$issues$severity[partly$issues$code == "system-version-unknown"], "info")
  all <- build(rbind(libz, ov_row(component = "system/libssl", field = "version", value = "3.0.13")))
  expect_false("system-version-unknown" %in% all$issues$code)
})

test_that("the issue on bundled libraries without a version follows the asserted versions", {
  lib <- local_fake_lib(list(cpkg = c(
    Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE", Maintainer = "A B <a@example.org>",
    `Authors@R` = 'c(person("A", "B", role = c("aut", "cre")), person("The LZ4 authors", role = "cph"))'
  )))
  dir.create(file.path(lib, "cpkg", "libs"))
  write_text("Bundles SQLite and a utf8procish thing.\n", file.path(lib, "cpkg", "COPYRIGHTS"))
  build <- function(ov) sbom_installed("cpkg", lib = lib, timestamp = 0, system = FALSE, overrides = ov)
  expect_identical(
    messages_of(build(NULL), "vendored-version-unknown"),
    "sbom found no version for the bundled lz4 in cpkg 1.0 and sqlite in cpkg 1.0."
  )
  sqlite <- ov_row(component = "pkg:cran/cpkg@1.0#vendored/sqlite", field = "version", value = "3.45.0")
  expect_identical(
    messages_of(build(sqlite), "vendored-version-unknown"),
    "sbom found no version for the bundled lz4 in cpkg 1.0."
  )
  all <- build(rbind(sqlite, ov_row(component = "pkg:cran/cpkg@1.0#vendored/lz4", field = "version", value = "1.9.4")))
  expect_false("vendored-version-unknown" %in% all$issues$code)
})

test_that("the issue on LinkingTo packages that are not installed says which versions are asserted", {
  desc <- withr::local_tempdir()
  write_text("Package: p\nVersion: 1\nLinkingTo: ghostpkg, phantompkg\n", file.path(desc, "DESCRIPTION"))
  build <- function(ov) sbom_package(desc, lib = fixture_lib(), timestamp = 0, system = FALSE, overrides = ov)
  ghost <- ov_row(component = "local/p#embedded/ghostpkg", field = "version", value = "1.0")
  partly <- build(ghost)
  hit <- partly$issues[partly$issues$code == "embedded-not-installed", , drop = FALSE]
  expect_identical(hit$message, c(
    "phantompkg is compiled into p 1 through LinkingTo, but is not installed in the library sbom read, so its version is unknown.",
    "ghostpkg is compiled into p 1 through LinkingTo, but is not installed in the library sbom read; its version is asserted by an override."
  ))
  expect_identical(hit$severity, c("info", "info"))
  expect_identical(hit$ref, c("local/p", "local/p"))
  all <- build(rbind(ghost, ov_row(component = "local/p#embedded/phantompkg", field = "version", value = "2.0")))
  expect_identical(
    messages_of(all, "embedded-not-installed"),
    paste0(
      "ghostpkg and phantompkg are compiled into p 1 through LinkingTo, but are not installed in the library ",
      "sbom read; their versions are asserted by an override."
    )
  )
})

test_that("the issue that a static Nix SBOM has no versions goes once every version is asserted", {
  x <- sbom_nix(test_path("fixtures", "nix", "rix-date.nix"), nix = FALSE, system = FALSE, embedded = FALSE)
  comps <- x$components
  counted <- comps$name[!comps$is_root & comps$source_input %in% "default.nix" &
    comps$ecosystem %in% c("cran", "github", "git") & is.na(comps$version)]
  expect_gt(length(counted), 1L)
  ov <- do.call(rbind, lapply(counted, function(n) ov_row(component = n, field = "version", value = "1.0")))
  message <- messages_of(x, "nix-versions-unknown")
  expect_identical(messages_of(apply_overrides(x, ov[-1, ]), "nix-versions-unknown"), message)
  expect_false("nix-versions-unknown" %in% apply_overrides(x, ov)$issues$code)
})

test_that("fields-from-library goes once the license and maintainer it names are asserted", {
  lock <- list(R = list(Version = "4.5.0"), Packages = list(glue = list(
    Package = "glue", Version = "1.7.0", Source = "Repository", Repository = "CRAN", Requirements = list("methods")
  )))
  dir <- withr::local_tempdir()
  write_text(jsonlite::toJSON(lock, auto_unbox = TRUE), file.path(dir, "renv.lock"))
  lib <- local_fake_lib(list(glue = c(Version = "1.7.0", Maintainer = "J B <j@example.org>", License = "MIT")))
  build <- function(ov) sbom_renv(file.path(dir, "renv.lock"), library = lib, timestamp = 0, system = FALSE,
                                  embedded = FALSE, overrides = ov)
  named <- "The license and maintainer of glue 1.7.0 come from the installed library, because renv.lock does not record them."
  expect_identical(messages_of(build(NULL), "fields-from-library"), named)
  license <- ov_row(component = "glue", field = "license_spdx", value = "MIT")
  maintainer <- ov_row(component = "glue", field = "maintainer", value = "J B")
  # One of the two leaves the sentence true of the other.
  expect_identical(messages_of(build(license), "fields-from-library"), named)
  expect_false("fields-from-library" %in% build(rbind(license, maintainer))$issues$code)

  # Borrowed dependencies stay borrowed.
  deps <- local_fake_lib(list(
    cli = c(Version = "2.2.0", Imports = "glue, utils", License = "MIT + file LICENSE", Maintainer = "G C <g@example.org>"),
    glue = c(Version = "1.4.3", Imports = "methods")
  ))
  ov <- rbind(ov_row(component = "cli", field = "license_spdx", value = "MIT"),
              ov_row(component = "cli", field = "maintainer", value = "G C"))
  y <- sbom_renv(test_path("fixtures/renv/pre-0.15/renv.lock"), library = deps, overrides = ov)
  hit <- y$issues[y$issues$code == "fields-from-library", , drop = FALSE]
  expect_identical(hit$message, "The dependencies of cli 2.2.0 come from the installed library, because renv.lock does not record them.")
  expect_identical(hit$field, "dependencies")
})

test_that("a missing dependency of two packages has one reworded issue", {
  dir <- withr::local_tempdir()
  write_text("Package: rootpkg\nVersion: 0.1.0\nLicense: MIT\nImports: fakepkg, midpkg\n", file.path(dir, "DESCRIPTION"))
  lib <- local_fake_lib(list(midpkg = c(Version = "1.0", Repository = "CRAN", License = "MIT", Imports = "fakepkg")))
  ov <- rbind(
    ov_row(component = "fakepkg", field = "version", value = "1.0.0"),
    ov_row(component = "fakepkg", field = "purl", value = "pkg:cran/fakepkg@1.0.0")
  )
  build <- function(ov) sbom_package(dir, lib = lib, timestamp = 0, system = FALSE, embedded = FALSE, overrides = ov)
  expect_identical(sum(build(NULL)$issues$code == "dependency-not-installed"), 2L)
  expect_identical(
    messages_of(build(ov), "dependency-not-installed"),
    "fakepkg is named as a dependency but is not installed; its version and purl are asserted by an override."
  )
})

test_that("the Nix issues on git and store versions follow the asserted versions", {
  x <- minimal_sbom()
  add <- function(x, ref, name, ...) {
    x$components <- rbind(x$components, component_row(ref = ref, name = name, type = "library", ...))
    x
  }
  x <- add(x, "github/housing", "housing", ecosystem = "github", source_input = "default.nix",
           download_location = "git+https://github.com/o/housing@abc")
  x <- add(x, "github/Alpha", "Alpha", ecosystem = "github", source_input = "default.nix",
           download_location = "git+https://github.com/o/Alpha@def")
  x <- add(x, "local/foo", "foo", ecosystem = "local", source_input = "nix-store")
  x <- add(x, "nix/libbar", "libbar", ecosystem = "nix", source_input = "nix-store")
  root <- x$metadata$root
  x$issues <- add_issue(x$issues, root, "version", "nix-git-versions-unknown",
                        nix_git_versions_sentence("rix-date.nix", c("housing", "Alpha")))
  x$issues <- add_issue(x$issues, root, "version", "nix-store-versions-unknown",
                        nix_store_versions_sentence(c("libbar", "r-foo")), severity = "info")
  expect_identical(
    messages_of(x, "nix-git-versions-unknown"),
    "The versions of the packages that rix-date.nix fetches from git are not recorded (Alpha and housing); each is identified by its revision instead."
  )
  partly <- apply_overrides(x, rbind(
    ov_row(component = "housing", field = "version", value = "1.0"),
    ov_row(component = "foo", field = "version", value = "2.0")
  ))
  expect_identical(
    messages_of(partly, "nix-git-versions-unknown"),
    "The version of the package that rix-date.nix fetches from git is not recorded (Alpha); it is identified by its revision instead."
  )
  expect_identical(
    messages_of(partly, "nix-store-versions-unknown"),
    "1 store path in the environment carries no version (libbar), so its version is unknown."
  )
  all <- apply_overrides(x, rbind(
    ov_row(component = "housing", field = "version", value = "1.0"),
    ov_row(component = "Alpha", field = "version", value = "1.0"),
    ov_row(component = "foo", field = "version", value = "2.0"),
    ov_row(component = "nix/libbar", field = "version", value = "3.0")
  ))
  expect_false(any(c("nix-git-versions-unknown", "nix-store-versions-unknown") %in% all$issues$code))
})
