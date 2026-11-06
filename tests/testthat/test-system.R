local_compiled_pkg <- function(lib, name) {
  dir.create(file.path(lib, name, "libs"))
  write_text("", file.path(lib, name, "libs", paste0(name, ".so")))
}

test_that("linked libraries become observed components, with OS package versions when known", {
  lib <- local_fake_lib(list(curlish = c(Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE",
                                         Maintainer = "A B <a@example.org>", SystemRequirements = "libcurl, libxml2")))
  local_compiled_pkg(lib, "curlish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) c("/usr/lib/x86_64-linux-gnu/libcurl.so.4", "/lib/x86_64-linux-gnu/libc.so.6"),
    sys_os_package = function(path) if (grepl("libcurl", path)) list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64") else NULL,
    sys_os_release = function() list(id = "debian", version_id = "12"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = c("libcurl", "libxml2"), packages = I(list("libcurl4-openssl-dev", "libxml2-dev")))))
  x <- sbom_installed("curlish", lib = lib)
  comps <- sbom_components(x)
  d <- comps[comps$ref == "deb/libcurl4", ]
  expect_equal(d$purl, "pkg:deb/debian/libcurl4@7.88.1-10?arch=amd64&distro=debian-12")
  expect_equal(d$evidence, "observed")
  expect_equal(d$ecosystem, "deb")
  expect_false(any(grepl("libc$|libc\\.so", comps$name)))
  rel <- sbom_dependencies(x)
  expect_equal(rel$to[rel$field == "dynamic_link"], "deb/libcurl4")
  iss <- sbom_issues(x)
  expect_true(any(iss$code == "may-statically-link" & grepl("libxml2", iss$message)))
  expect_false(any(iss$code == "may-statically-link" & grepl("libcurl", iss$message)))
})

test_that("a macOS system library is recorded without inventing a version", {
  lib <- local_fake_lib(list(sslish = c(Version = "1.0")))
  local_compiled_pkg(lib, "sslish")
  local_mocked_bindings(sys_linked_libraries = function(so) structure("/usr/lib/libssl.48.dylib", versions = "49.2.0"),
                        sysreqs_match = function(spec, platform) NULL)
  comps <- sbom_components(sbom_installed("sslish", lib = lib))
  s <- comps[comps$ref == "system/libssl", ]
  expect_true(is.na(s$version))
  expect_equal(s$evidence, "observed")
  expect_match(s$description, "library version 49.2.0", fixed = TRUE)
  expect_false(grepl("/", s$description, fixed = TRUE))
})

test_that("missing tools are noted once", {
  lib <- local_fake_lib(list(a = c(Version = "1"), b = c(Version = "1")))
  for (p in c("a", "b")) local_compiled_pkg(lib, p)
  local_mocked_bindings(sys_linked_libraries = function(so) structure(character(), tool_missing = TRUE),
                        sysreqs_match = function(spec, platform) NULL)
  expect_equal(sum(sbom_issues(sbom_installed(lib = lib))$code == "links-not-checked"), 1L)
})

test_that("no compiled code means nothing to check and no issue", {
  lib <- local_fake_lib(list(a = c(Version = "1")))
  local_mocked_bindings(sys_linked_libraries = function(so) stop("not called"))
  expect_false("links-not-checked" %in% sbom_issues(sbom_installed(lib = lib))$code)
})

test_that("system = FALSE does not look at links", {
  lib <- local_fake_lib(list(a = c(Version = "1")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(sys_linked_libraries = function(so) stop("not called"))
  expect_no_error(sbom_installed("a", lib = lib, system = FALSE))
})

test_that("a declared and observed library is one component, observed", {
  lib <- local_fake_lib(list(sslish = c(Version = "1.0", SystemRequirements = "libssl")))
  local_compiled_pkg(lib, "sslish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure("/usr/lib/libssl.48.dylib", versions = "49.2.0"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libssl", packages = I(list(character())))))
  x <- sbom_installed("sslish", lib = lib)
  comps <- sbom_components(x)
  s <- comps[comps$ref == "system/libssl", ]
  expect_equal(nrow(s), 1L)
  expect_equal(s$evidence, "observed")
  expect_match(s$description, "Needed by sslish")
  expect_match(s$description, "Linked as libssl.48.dylib (library version 49.2.0).", fixed = TRUE)
  expect_setequal(sbom_dependencies(x)$field[grepl("libssl", sbom_dependencies(x)$to)], c("system_requirement", "dynamic_link"))
  expect_false("may-statically-link" %in% sbom_issues(x)$code)
})

test_that("openssl, zlib and a missing lib prefix match their libraries", {
  expect_true(sysreq_is_linked("openssl", "libcrypto"))
  expect_true(sysreq_is_linked("zlib", c("libz", "libfoo")))
  expect_true(sysreq_is_linked("curl", "libcurl"))
  expect_false(sysreq_is_linked("libxml2", "libcurl"))
})

test_that("library names lose their directory, version and extension", {
  expect_equal(
    library_base_name(c("/usr/lib/libssl.48.dylib", "libcurl.so.4", "/lib/libxml2.so.2.9.14", "/usr/lib/libc++.1.dylib", "/usr/lib/libicucore.A.dylib")),
    c("libssl", "libcurl", "libxml2", "libc++", "libicucore")
  )
  expect_equal(
    ignored_library(c("/usr/lib/libSystem.B.dylib", "/lib64/ld-linux-x86-64.so.2", "/lib/libm.so.6",
                      "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", "/usr/lib/libcurl.so.4",
                      "/Library/Frameworks/R.framework/Versions/4.6/Resources/lib/libR.dylib")),
    c(TRUE, TRUE, TRUE, TRUE, FALSE, TRUE)
  )
})

test_that("otool output gives the linked libraries and versions, not the file itself", {
  lines <- c(
    "/lib/curl/libs/curl.so:",
    "\tcurl.so (compatibility version 0.0.0, current version 0.0.0)",
    "\t/usr/lib/libssl.48.dylib (compatibility version 49.0.0, current version 49.2.0)",
    "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)",
    "\t@rpath/libR.dylib (compatibility version 4.6.0, current version 4.6.2)"
  )
  got <- parse_otool(lines, "/lib/curl/libs/curl.so")
  expect_equal(got$paths, c("/usr/lib/libssl.48.dylib", "/usr/lib/libSystem.B.dylib", "@rpath/libR.dylib"))
  expect_equal(got$versions, c("49.2.0", "1351.0.0", "4.6.2"))
})

test_that("ldd output gives paths, and nothing for a missing library or the vdso", {
  lines <- c(
    "\tlinux-vdso.so.1 (0x00007ffc8b5f4000)",
    "\tlibcurl.so.4 => /usr/lib/x86_64-linux-gnu/libcurl.so.4 (0x00007f1c2a000000)",
    "\tlibgone.so.1 => not found",
    "\t/lib64/ld-linux-x86-64.so.2 (0x00007f1c2a400000)"
  )
  expect_equal(
    parse_ldd(lines)$paths,
    c("/usr/lib/x86_64-linux-gnu/libcurl.so.4", "/lib64/ld-linux-x86-64.so.2")
  )
  expect_length(parse_ldd("\tnot a dynamic executable")$paths, 0L)
})

test_that("dpkg and rpm output give the OS package", {
  expect_equal(parse_dpkg_owner("libcurl4:amd64: /usr/lib/x86_64-linux-gnu/libcurl.so.4"), "libcurl4")
  expect_true(is.na(parse_dpkg_owner(character())))
  expect_equal(
    parse_os_package("7.88.1-10 amd64", "deb", "libcurl4"),
    list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64")
  )
  expect_equal(
    parse_os_package("libcurl 7.76.1-23.el9 x86_64", "rpm", NULL),
    list(manager = "rpm", name = "libcurl", version = "7.76.1-23.el9", arch = "x86_64")
  )
  expect_null(parse_os_package(character(), "rpm", NULL))
})

test_that("os-release fields are lowercase and unquoted", {
  expect_equal(
    parse_os_release(c("NAME=\"Debian GNU/Linux\"", "ID=debian", "VERSION_ID=\"12\"", "# c")),
    list(name = "debian gnu/linux", id = "debian", version_id = "12")
  )
  expect_null(sys_os_release_real(withr::local_tempfile()))
})

test_that("every writer accepts dynamic links and deb and rpm components", {
  skip_if_not_installed("jsonvalidate")
  skip_if_not_installed("yaml")
  lib <- local_fake_lib(list(curlish = c(Version = "1.0", License = "MIT")))
  local_compiled_pkg(lib, "curlish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) c("/usr/lib/libcurl.so.4", "/usr/lib/libfoo.so.1"),
    sys_os_package = function(path) if (grepl("libcurl", path)) {
      list(manager = "deb", name = "libcurl4", version = "7.88.1-10+deb12u5", arch = "amd64")
    } else list(manager = "rpm", name = "foo", version = "1-2.el9", arch = "x86_64"),
    sys_os_release = function() list(id = "debian", version_id = "12"))
  x <- sbom_installed("curlish", lib = lib)
  for (fmt in sbom_formats()$format) {
    tf <- withr::local_tempfile()
    write_sbom(x, tf, format = fmt)
    if (fmt != "csv") {
      expect_false(schema_validate(tf, fmt)$status == "fail", info = fmt)
    }
  }
  spdx <- jsonlite::fromJSON(spdx_json(x, "2.3"), simplifyVector = FALSE)
  expect_true("DYNAMIC_LINK" %in% vapply(spdx$relationships, `[[`, "", "relationshipType"))
  expect_true(all(c("SPDXRef-deb-libcurl4", "SPDXRef-rpm-foo") %in% vapply(spdx$packages, `[[`, "", "SPDXID")))
})

test_that("a failed read is not reported as a static copy", {
  lib <- local_fake_lib(list(curlish = c(Version = "1.0", SystemRequirements = "libcurl"), other = c(Version = "1.0")))
  for (p in c("curlish", "other")) local_compiled_pkg(lib, p)
  local_mocked_bindings(
    sys_linked_libraries = function(so) {
      if (grepl("curlish", so, fixed = TRUE)) {
        structure(character(), versions = character(), tool_missing = FALSE, failed = TRUE)
      } else {
        "/usr/lib/libz.so.1"
      }
    },
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libcurl", packages = I(list(character())))))
  iss <- sbom_issues(sbom_installed(c("curlish", "other"), lib = lib))
  expect_false("may-statically-link" %in% iss$code)
  expect_equal(iss$message[iss$code == "links-not-read"],
    "sbom could not read the shared libraries linked by curlish 1.0.")
})

test_that("@loader_path and @executable_path targets that exist outside the package are system libraries", {
  skip_on_os("windows")
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  ext <- withr::local_tempdir()
  write_text("", file.path(ext, "libfoo.1.dylib"))
  write_text("", file.path(ext, "libbaz.3.dylib"))
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure(
      c(paste0("@loader_path/../../../", basename(ext), "/libfoo.1.dylib"), "@executable_path/libbaz.3.dylib"),
      versions = c("2.0.0", "3.0.0")),
    sys_r_bin = function() ext)
  comps <- sbom_components(sbom_installed("a", lib = lib))
  s <- comps[comps$ref == "system/libfoo", ]
  expect_equal(s$description, "Linked as libfoo.1.dylib (library version 2.0.0).")
  expect_true("system/libbaz" %in% comps$ref)
})

test_that("a target that does not exist, or is not absolute, is skipped", {
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure(
      c("@loader_path/../../../nowhere/libfoo.1.dylib", "@executable_path/libbaz.3.dylib", "libplain.dylib"),
      versions = rep("1.0.0", 3)),
    sys_r_bin = function() file.path(tempdir(), "no-such-bin"))
  refs <- sbom_components(sbom_installed("a", lib = lib))$ref
  expect_false(any(grepl("system/", refs)))
  expect_true(is.na(resolve_link("libplain.dylib", "/x/a.so", function() character(), "/bin")))
})

test_that("a library bundled in the package is not a system library and leaves the static-copy hint", {
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libcurl")))
  local_compiled_pkg(lib, "a")
  write_text("", file.path(lib, "a", "libs", "libcurl.4.dylib"))
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure(c("@loader_path/libcurl.4.dylib", file.path(lib, "a", "libs", "libz.1.dylib")), versions = c("9.0.0", "1.0.0")),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libcurl", packages = I(list(character())))))
  x <- sbom_installed("a", lib = lib)
  comps <- sbom_components(x)
  expect_equal(comps$evidence[comps$ref == "system/libcurl"], "declared")
  expect_false("system/libz" %in% comps$ref)
  expect_false("dynamic_link" %in% sbom_dependencies(x)$field)
  expect_true("may-statically-link" %in% sbom_issues(x)$code)
})

test_that("@rpath entries are resolved through the file's rpaths, else skipped", {
  skip_on_os("windows")
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  ext <- withr::local_tempdir()
  write_text("", file.path(ext, "libbar.2.dylib"))
  local_mocked_bindings(sys_linked_libraries = function(so) structure("@rpath/libbar.2.dylib", versions = "1.0.0"))
  local_mocked_bindings(sys_otool_rpaths = function(so) c("/nonexistent", ext))
  expect_true("system/libbar" %in% sbom_components(sbom_installed("a", lib = lib))$ref)
  local_mocked_bindings(sys_otool_rpaths = function(so) character())
  expect_false("system/libbar" %in% sbom_components(sbom_installed("a", lib = lib))$ref)
})

test_that("a Debian version is percent-encoded in the purl", {
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(
    sys_linked_libraries = function(so) "/usr/lib/libcurl.so.4",
    sys_os_package = function(path) list(manager = "deb", name = "libcurl4", version = "1:2.3-1+deb12u1", arch = "amd64"),
    sys_os_release = function() list(id = "debian", version_id = "12"))
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_equal(comps$purl[comps$ref == "deb/libcurl4"], "pkg:deb/debian/libcurl4@1%3A2.3-1%2Bdeb12u1?arch=amd64&distro=debian-12")
})

test_that("ldd lines with no path and a name inside another are not links", {
  expect_length(parse_ldd("\tlinux-vdso.so.1 =>  (0x00007ffc8b5f4000)")$paths, 0L)
  expect_false(sysreq_is_linked("curl", "libcurlpp"))
  expect_false(sysreq_is_linked("libssh2", "libssh"))
})

test_that("@rpath entries anchored at the loader or R's bin resolve when the target exists", {
  skip_on_os("windows")
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  root <- withr::local_tempdir()
  dir.create(file.path(root, "bin"))
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure("@rpath/libbar.2.dylib", versions = "1.0.0"),
    sys_r_bin = function() file.path(root, "bin"))
  has_bar <- function() "system/libbar" %in% sbom_components(sbom_installed("a", lib = lib))$ref
  # From lib/a/libs, ../../.. is the folder that holds both temporary folders.
  outside <- paste0("@loader_path/../../../", basename(root), "/deps")
  for (entry in c(outside, "@executable_path/../deps")) {
    local_mocked_bindings(sys_otool_rpaths = function(so) entry)
    # The target is missing: skipped.
    expect_false(has_bar(), info = entry)
  }
  dir.create(file.path(root, "deps"))
  write_text("", file.path(root, "deps", "libbar.2.dylib"))
  for (entry in c(outside, "@executable_path/../deps")) {
    local_mocked_bindings(sys_otool_rpaths = function(so) entry)
    expect_true(has_bar(), info = entry)
  }
  # A target inside the library folder is a copy that a package ships.
  dir.create(file.path(lib, "deps"))
  write_text("", file.path(lib, "deps", "libbar.2.dylib"))
  local_mocked_bindings(sys_otool_rpaths = function(so) "@loader_path/../../deps")
  expect_false(has_bar())
})

test_that("a library SBOM with embedded and system components validates in every format and is byte-identical", {
  skip_if_not_installed("jsonvalidate"); skip_if_not_installed("yaml")
  withr::local_envvar(SOURCE_DATE_EPOCH = "1700000000")
  lib <- local_fake_lib(list(
    curlish = c(Version = "1.0", Repository = "CRAN", License = "MIT + file LICENSE",
                Maintainer = "A B <a@example.org>", SystemRequirements = "libcurl",
                LinkingTo = "helperpkg", Imports = "helperpkg"),
    helperpkg = c(Version = "2.0", Repository = "CRAN", License = "MIT",
                  Maintainer = "A B <a@example.org>")))
  local_compiled_pkg(lib, "curlish")
  write_text("Bundles SQLite.\n", file.path(lib, "curlish", "COPYRIGHTS"))
  dir.create(file.path(lib, "curlish", "www"))
  write_text("/*! jQuery v3.5.1 | x */\n", file.path(lib, "curlish", "www", "jquery.min.js"))
  local_mocked_bindings(
    sys_linked_libraries = function(so) "/usr/lib/x86_64-linux-gnu/libcurl.so.4",
    sys_os_package = function(path) list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64"),
    sys_os_release = function() list(id = "debian", version_id = "12"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libcurl", packages = I(list("libcurl4-openssl-dev")))))
  build <- function() sbom_installed(c("curlish", "helperpkg"), lib = lib)
  refs <- sbom_components(build())$ref
  for (kind in c("#embedded/helperpkg", "#vendored/sqlite", "#js/jquery@3.5.1", "system/libcurl", "deb/libcurl4")) {
    expect_true(any(grepl(kind, refs, fixed = TRUE)), info = kind)
  }
  expect_true("pkg:cran/helperpkg@2.0" %in% refs)
  expected <- c(`cyclonedx-json` = "pass", `cyclonedx-xml` = "pass", `spdx-json` = "pass", `spdx-yaml` = "pass",
                `spdx-xml` = "partial", `spdx-tv` = "partial", `spdx3-jsonld` = "partial", swid = "partial")
  d1 <- withr::local_tempdir(); d2 <- withr::local_tempdir()
  write_sbom(build(), d1, format = "all"); write_sbom(build(), d2, format = "all")
  files <- list.files(d1, full.names = TRUE)
  expect_identical(basename(files), list.files(d2))
  for (f in files) expect_identical(readBin(f, "raw", 1e7), readBin(file.path(d2, basename(f)), "raw", 1e7), label = basename(f))
  for (f in names(expected)) {
    file <- files[endsWith(files, sbom_formats()$extension[sbom_formats()$format == f])]
    expect_identical(schema_validate(file, f)$status, expected[[f]], label = f)
  }
  spdx <- jsonlite::fromJSON(spdx_json(build()), simplifyVector = FALSE)
  expect_true(any(vapply(spdx$relationships, function(r) r$relationshipType == "DYNAMIC_LINK", TRUE)))
  expect_true(any(vapply(spdx$relationships, function(r) identical(r$comment, "SystemRequirements: libcurl"), TRUE)))
  s3 <- jsonlite::fromJSON(spdx3_jsonld(build()), simplifyVector = FALSE)
  rels <- Filter(function(e) e$type %in% c("Relationship", "LifecycleScopedRelationship") &&
                 !e$relationshipType %in% c("hasDeclaredLicense", "contains"), s3[["@graph"]])
  types <- vapply(rels, function(r) paste(r$type, r$relationshipType, if (is.null(r$scope)) "" else r$scope), "")
  expect_true("LifecycleScopedRelationship dependsOn runtime" %in% types)
  expect_true(any(grepl("hasDynamicLink", types)), info = paste(types, collapse = "; "))
})

test_that("a program system component is an application in every format", {
  local_mocked_bindings(sysreqs_match = function(spec, platform) {
    list(data.frame(sysreq = c("pandoc", "libxml2"), packages = I(list("pandoc", "libxml2-dev"))))
  })
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "Pandoc, libxml2")))
  x <- sbom_installed("a", lib = lib)
  purpose <- function(doc, name) {
    for (p in doc$packages) if (identical(p$name, name)) return(p$primaryPackagePurpose)
  }
  doc <- spdx_document(x, "2.3")
  expect_equal(purpose(doc, "pandoc"), "APPLICATION")
  expect_equal(purpose(doc, "libxml2"), "LIBRARY")
  s3 <- Filter(function(e) identical(e$type, "software_Package"), spdx3_document(x)[["@graph"]])
  purposes <- vapply(s3, function(e) paste(e$name, e$software_primaryPurpose), "")
  expect_true("pandoc application" %in% purposes)
  expect_true("libxml2 library" %in% purposes)
  cdx <- cdx_document(x, "1.6")
  flat <- function(cs) unlist(lapply(cs, function(c) c(paste(c$name, c$type), flat(c$components))))
  expect_true("pandoc application" %in% flat(cdx$components))
  expect_true("libxml2 library" %in% flat(cdx$components))
})

test_that("the Fortran and OpenMP runtimes are ignored like the C and C++ ones", {
  expect_equal(
    ignored_library(c("/opt/gfortran/lib/gcc/aarch64-apple-darwin20.0/14.2.0/libgfortran.5.dylib",
                      "/opt/gfortran/lib/gcc/aarch64-apple-darwin20.0/14.2.0/libquadmath.0.dylib",
                      "/usr/lib/x86_64-linux-gnu/libgomp.so.1", "/opt/homebrew/opt/libomp/lib/libomp.dylib",
                      "/usr/lib/x86_64-linux-gnu/libgfortran.so.5", "/usr/lib/libompx.so.1")),
    c(TRUE, TRUE, TRUE, TRUE, TRUE, FALSE)
  )
})

test_that("R's own libraries and other packages' libraries are not system libraries", {
  lib <- local_fake_lib(list(a = c(Version = "1.0"), other = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  dir.create(file.path(lib, "other", "libs"))
  write_text("", file.path(lib, "other", "libs", "libbar.1.dylib"))
  linked <- c(
    file.path(R.home(), "lib", "libRblas.dylib"),
    file.path(R.home(), "lib", "libgfortran.5.dylib"),
    file.path(lib, "other", "libs", "libbar.1.dylib"),
    "/opt/elsewhere/libRlapack.so"
  )
  local_mocked_bindings(sys_linked_libraries = function(so) structure(linked, versions = rep("1.0.0", 4)))
  x <- sbom_installed("a", lib = lib)
  expect_false(any(sbom_components(x)$ecosystem %in% c("system", "deb", "rpm")))
  expect_false("dynamic_link" %in% sbom_dependencies(x)$field)
})

test_that("suffixed and differently named libraries count as linked", {
  expect_true(sysreq_is_linked("libpng", library_base_name("/usr/lib/x86_64-linux-gnu/libpng16.so.16")))
  expect_true(sysreq_is_linked("postgresql", "libpq"))
  expect_true(sysreq_is_linked("imagemagick", library_base_name("/usr/lib/libMagick++-6.Q16.so.8")))
  expect_true(sysreq_is_linked("libicu", "libicuuc"))
  expect_true(sysreq_is_linked("xz", "liblzma"))
  expect_true(sysreq_is_linked("netcdf4", "libnetcdf"))
  expect_true(sysreq_is_linked("hdf5", "libhdf5_serial"))
  expect_true(sysreq_is_linked("zeromq", "libzmq"))
  expect_true(sysreq_is_linked("pango", library_base_name("/usr/lib/libpango-1.0.so.0")))
  expect_true(sysreq_is_linked("glib", library_base_name("/usr/lib/libglib-2.0.so.0")))
  expect_true(sysreq_is_linked("geos", library_base_name("/usr/lib/libgeos_c.so.1")))
  expect_true(sysreq_is_linked("sqlite3", "libsqlite3"))
  # A package that links nothing links none of them, prefixes included.
  expect_false(sysreq_is_linked("libicu", character()))
  expect_false(sysreq_is_linked("openssl", character()))
  for (case in list(c("libpng", "/usr/lib/x86_64-linux-gnu/libpng16.so.16"),
                    c("postgresql", "/usr/lib/x86_64-linux-gnu/libpq.so.5"))) {
    lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = case[[1]])))
    local_compiled_pkg(lib, "a")
    local_mocked_bindings(
      sys_linked_libraries = function(so) case[[2]],
      sysreqs_match = function(spec, platform) list(data.frame(sysreq = case[[1]], packages = I(list(character())))))
    expect_false("may-statically-link" %in% sbom_issues(sbom_installed("a", lib = lib))$code, info = case[[1]])
  }
})

test_that("a path is inside a folder by its own folder, and no folders hold nothing", {
  lib <- withr::local_tempdir()
  expect_equal(inside_any(c(file.path(lib, "a", "libs", "x.so"), "/usr/lib/libz.so", NA), lib), c(TRUE, FALSE, FALSE))
  expect_equal(inside_any("/usr/lib/libz.so", character()), FALSE)
  expect_equal(inside_any("/usr/lib/libz.so", NULL), FALSE)
})

test_that("absolute paths are Unix or Windows paths", {
  expect_equal(
    is_absolute_path(c("/usr/lib/libz.so", "C:\\R\\bin\\R.dll", "c:/R/lib", "\\\\server\\share\\x.dll",
                       "@rpath/libz.dylib", "libz.dylib", "lib/x.so", NA)),
    c(TRUE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE)
  )
})

test_that("Windows DLLs are not read, and one issue says so", {
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libcurl")))
  dir.create(file.path(lib, "a", "libs", "x64"), recursive = TRUE)
  write_text("", file.path(lib, "a", "libs", "x64", "a.dll"))
  local_mocked_bindings(
    sys_os_name = function() "Windows",
    sys_linked_libraries = function(so) stop("not called"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libcurl", packages = I(list(character())))))
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_equal(sum(iss$code == "links-not-checked"), 1L)
  expect_equal(iss$message[iss$code == "links-not-checked"], paste0(
    "The shared libraries linked by compiled packages were not checked, ",
    "because sbom does not read the libraries that Windows DLLs link."
  ))
  expect_false("may-statically-link" %in% iss$code)
  # On Linux a DLL is still not read, but a .so in a subfolder is.
  write_text("", file.path(lib, "a", "libs", "x64", "a.so"))
  seen <- new.env()
  local_mocked_bindings(
    sys_os_name = function() "Linux",
    sys_linked_libraries = function(so) {
      seen$files <- c(seen$files, basename(so))
      character()
    })
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_equal(seen$files, "a.so")
  expect_equal(iss$message[iss$code == "links-not-checked"],
    "The shared libraries linked by the Windows DLLs of a 1.0 were not checked, because sbom does not read the libraries that Windows DLLs link.")
  expect_false("may-statically-link" %in% iss$code)
})

test_that("system, deb and rpm components have no dependency entry in CycloneDX", {
  lib <- local_fake_lib(list(curlish = c(Version = "1.0", SystemRequirements = "libxml2")))
  local_compiled_pkg(lib, "curlish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) c("/usr/lib/libcurl.so.4", "/usr/lib/libfoo.so.1", "/usr/lib/libxml2.so.2"),
    sys_os_package = function(path) if (grepl("libcurl", path)) {
      list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64")
    } else if (grepl("libfoo", path)) list(manager = "rpm", name = "foo", version = "1-2.el9", arch = "x86_64"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libxml2", packages = I(list(character())))))
  x <- sbom_installed("curlish", lib = lib)
  refs <- vapply(cdx_document(x, "1.6")$dependencies, `[[`, "", "ref")
  sys <- sbom_components(x)$ref[sbom_components(x)$ecosystem %in% c("system", "deb", "rpm")]
  expect_setequal(sys, c("deb/libcurl4", "rpm/foo", "system/libxml2"))
  expect_false(any(sys %in% refs))
  expect_true(all(!sbom_components(x)$deps_known[sbom_components(x)$ref %in% sys]))
})

test_that("linked system libraries without a version are named in one issue", {
  lib <- local_fake_lib(list(a = c(Version = "1.0"), b = c(Version = "1.0")))
  for (p in c("a", "b")) local_compiled_pkg(lib, p)
  local_mocked_bindings(sys_linked_libraries = function(so) {
    if (grepl("a.so", so, fixed = TRUE)) c("/usr/lib/libssl.48.dylib", "/usr/lib/libz.1.dylib") else "/usr/lib/libz.1.dylib"
  })
  iss <- sbom_issues(sbom_installed(c("a", "b"), lib = lib))
  expect_equal(iss$message[iss$code == "system-version-unknown"], paste0(
    "The versions of the linked system libraries libssl and libz are unknown, ",
    "because sbom found no package manager that owns them."
  ))
  local_mocked_bindings(sys_linked_libraries = function(so) "/usr/lib/libz.1.dylib")
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_equal(iss$message[iss$code == "system-version-unknown"], paste0(
    "The version of the linked system library libz is unknown, ",
    "because sbom found no package manager that owns it."
  ))
  expect_equal(iss$severity[iss$code == "system-version-unknown"], "info")
})

# The bytes of a minimal ELF file: the header, then one program header per
# segment type in `types` (3 is PT_INTERP).
elf_bytes <- function(class = 2L, little = TRUE, types = c(1L, 3L)) {
  int <- function(x, size) {
    b <- as.raw((x %/% 256^(seq_len(size) - 1L)) %% 256)
    if (little) b else rev(b)
  }
  ehsize <- if (class == 2L) 64 else 52
  phentsize <- if (class == 2L) 56 else 32
  word <- if (class == 2L) 8 else 4
  head <- c(as.raw(c(0x7f, 0x45, 0x4c, 0x46, class, if (little) 1L else 2L, 1L)), raw(9),
            int(3, 2), int(62, 2), int(1, 4), int(0, word), int(ehsize, word), int(0, word),
            int(0, 4), int(ehsize, 2), int(phentsize, 2), int(length(types), 2), int(0, 6))
  c(head, unlist(lapply(types, function(t) c(int(t, 4), raw(phentsize - 4)))))
}

test_that("an ELF file's program interpreter is found in 32- and 64-bit files of either byte order", {
  elf <- function(...) {
    tf <- withr::local_tempfile(.local_envir = parent.frame())
    writeBin(elf_bytes(...), tf)
    tf
  }
  expect_true(elf_has_interp(elf()))
  expect_false(elf_has_interp(elf(types = 1L)))
  expect_true(elf_has_interp(elf(class = 1L, little = FALSE)))
  expect_false(elf_has_interp(elf(class = 1L, little = FALSE, types = c(1L, 2L))))
  expect_true(elf_has_interp(elf(class = 1L, little = TRUE, types = c(6L, 3L))))
  expect_false(elf_has_interp(elf(class = 2L, little = FALSE, types = integer())))
  text <- withr::local_tempfile()
  write_text("not an ELF file\n", text)
  expect_true(is.na(elf_has_interp(text)))
  short <- withr::local_tempfile()
  writeBin(elf_bytes()[1:70], short)
  expect_true(is.na(elf_has_interp(short)))
  expect_true(is.na(elf_has_interp(file.path(tempdir(), "no-such-file.so"))))
})

test_that("on macOS without the Command Line Tools, otool is not run and one issue says so", {
  lib <- local_fake_lib(list(a = c(Version = "1"), b = c(Version = "1")))
  for (p in c("a", "b")) local_compiled_pkg(lib, p)
  asked <- new.env()
  asked$n <- 0L
  local_mocked_bindings(
    sys_os_name = function() "Darwin",
    sys_xcode_tools = function() {
      asked$n <- asked$n + 1L
      FALSE
    },
    sys_linked_libraries = function(so) stop("not called"))
  iss <- sbom_issues(sbom_installed(lib = lib))
  expect_equal(sum(iss$code == "links-not-checked"), 1L)
  expect_false("links-not-read" %in% iss$code)
  expect_equal(asked$n, 1L)
})

test_that("when every read fails, one issue replaces the notes for each package", {
  lib <- local_fake_lib(list(a = c(Version = "1"), b = c(Version = "1")))
  for (p in c("a", "b")) local_compiled_pkg(lib, p)
  local_mocked_bindings(sys_linked_libraries = function(so) {
    structure(character(), versions = character(), tool_missing = FALSE, failed = TRUE)
  })
  iss <- sbom_issues(sbom_installed(lib = lib))
  expect_false("links-not-read" %in% iss$code)
  expect_equal(iss$message[iss$code == "links-not-checked"], paste0(
    "The shared libraries linked by compiled packages were not checked, ",
    "because sbom could not read them for any package."
  ))
  # When one read succeeds, each failed package keeps its own note.
  local_mocked_bindings(sys_linked_libraries = function(so) {
    if (grepl("a.so", so, fixed = TRUE)) "/usr/lib/libz.so.1" else
      structure(character(), versions = character(), tool_missing = FALSE, failed = TRUE)
  })
  iss <- sbom_issues(sbom_installed(lib = lib))
  expect_equal(iss$message[iss$code == "links-not-read"], "sbom could not read the shared libraries linked by b 1.")
  expect_false("links-not-checked" %in% iss$code)
})

test_that("SPDX 2 and SPDX 3 keep how a deb or rpm package is linked", {
  lib <- local_fake_lib(list(curlish = c(Version = "1.0")))
  local_compiled_pkg(lib, "curlish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) c("/usr/lib/libcurl.so.4", "/usr/lib/libfoo.so.1"),
    sys_os_package = function(path) if (grepl("libcurl", path)) {
      list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64")
    } else list(manager = "rpm", name = "foo", version = "1-2.el9", arch = "x86_64"))
  x <- sbom_installed("curlish", lib = lib)
  comment2 <- function(name) Filter(function(p) identical(p$name, name), spdx_document(x)$packages)[[1]]$comment
  expect_equal(comment2("libcurl4"), "Linked as libcurl.so.4.")
  expect_equal(comment2("foo"), "Linked as libfoo.so.1.")
  s3 <- Filter(function(e) identical(e$type, "software_Package") && identical(e$name, "libcurl4"),
               spdx3_document(x)[["@graph"]])[[1]]
  expect_equal(s3$comment, "Linked as libcurl.so.4.")
})

test_that("deb and rpm purls follow the purl spec's vendor and distro conventions", {
  deb <- list(manager = "deb", name = "libcurl4", version = "7.88.1-10", arch = "amd64")
  rpm <- list(manager = "rpm", name = "libcurl", version = "7.76.1-23.el9", arch = "x86_64")
  expect_equal(
    os_package_purl(rpm, list(id = "rhel", version_id = "9.2")),
    "pkg:rpm/redhat/libcurl@7.76.1-23.el9?arch=x86_64&distro=rhel-9.2"
  )
  expect_equal(
    os_package_purl(rpm, list(id = "fedora", version_id = "25")),
    "pkg:rpm/fedora/libcurl@7.76.1-23.el9?arch=x86_64&distro=fedora-25"
  )
  expect_equal(
    os_package_purl(rpm, list(id = "opensuse-leap", version_id = "15.5")),
    "pkg:rpm/opensuse/libcurl@7.76.1-23.el9?arch=x86_64&distro=opensuse-leap-15.5"
  )
  for (id in c("centos", "rocky", "almalinux")) {
    expect_match(os_package_purl(rpm, list(id = id, version_id = "9")), paste0("^pkg:rpm/", id, "/"))
  }
  expect_equal(
    os_package_purl(deb, list(id = "ubuntu", version_id = "22.04")),
    "pkg:deb/ubuntu/libcurl4@7.88.1-10?arch=amd64&distro=ubuntu-22.04"
  )
  # The spec's deb examples name the release.
  expect_equal(
    os_package_purl(deb, list(id = "debian", version_id = "12", version_codename = "bookworm")),
    "pkg:deb/debian/libcurl4@7.88.1-10?arch=amd64&distro=bookworm"
  )
  # An ID that is not mapped keeps its own name; no version_id, no distro.
  expect_equal(
    os_package_purl(deb, list(id = "pop")),
    "pkg:deb/pop/libcurl4@7.88.1-10?arch=amd64"
  )
  expect_null(os_package_purl(deb, NULL))
})

test_that("a linked library on RHEL gets the redhat namespace and a distro qualifier", {
  lib <- local_fake_lib(list(curlish = c(Version = "1.0")))
  local_compiled_pkg(lib, "curlish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) "/usr/lib64/libcurl.so.4",
    sys_os_package = function(path) list(manager = "rpm", name = "libcurl", version = "7.76.1-23.el9", arch = "x86_64"),
    sys_os_release = function() list(id = "rhel", version_id = "9.2"),
    sysreqs_match = function(spec, platform) NULL)
  comps <- sbom_components(sbom_installed("curlish", lib = lib))
  expect_equal(comps$purl[comps$ref == "rpm/libcurl"], "pkg:rpm/redhat/libcurl@7.76.1-23.el9?arch=x86_64&distro=rhel-9.2")
})

test_that("musl's loader and libc are ignored like glibc's", {
  expect_equal(
    ignored_library(c("/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1", "/usr/lib/libcurl.so.4")),
    c(TRUE, TRUE, FALSE)
  )
  lib <- local_fake_lib(list(a = c(Version = "1.0")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(
    sys_linked_libraries = function(so) c("/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1"),
    sysreqs_match = function(spec, platform) NULL)
  comps <- sbom_components(sbom_installed("a", lib = lib))
  expect_false(any(grepl("musl", comps$name)))
})

test_that("ldd's not found lines are named in links-not-read, with no component", {
  expect_equal(
    parse_ldd(c("\tlibfoo.so.1 => not found", "\tlibz.so.1 => /lib/libz.so.1 (0x1)", "\tlibR.so => not found"))$not_found,
    c("libR.so", "libfoo.so.1")
  )
  lib <- local_fake_lib(list(a = c(Version = "1.0", SystemRequirements = "libfoo")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(
    sys_linked_libraries = function(so) {
      structure("/usr/lib/libz.so.1", versions = NA_character_, not_found = c("libR.so", "libfoo.so.1"))
    },
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libfoo", packages = I(list(character())))))
  x <- sbom_installed("a", lib = lib)
  iss <- sbom_issues(x)
  expect_equal(sum(iss$code == "links-not-read"), 1L)
  expect_equal(
    iss$message[iss$code == "links-not-read"],
    "ldd did not find libfoo.so.1, which a 1.0 links, so it is not listed as a component."
  )
  expect_false("may-statically-link" %in% iss$code)
  comps <- sbom_components(x)
  expect_false(any(grepl("libfoo.so", comps$name) & comps$evidence == "observed"))
  expect_true("system/libz" %in% comps$ref)
  # A failed read and a missing library share one issue.
  local_mocked_bindings(
    sys_linked_libraries = function(so) {
      structure(character(), versions = character(), not_found = "libfoo.so.1", failed = TRUE)
    })
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_equal(sum(iss$code == "links-not-read" | iss$code == "links-not-checked"), 1L)
  # The libraries ldd did not find are still named.
  expect_equal(iss$message[iss$code == "links-not-checked"], paste0(
    "The shared libraries linked by compiled packages were not checked, because sbom could not ",
    "read them for any package, and ldd did not find libfoo.so.1, so it is not listed as a component."
  ))
})

test_that("a declared minimum stays a minimum when the library is observed, and a required package raises the scope", {
  lib <- local_fake_lib(list(
    sslish = c(Version = "1.0", SystemRequirements = "libssl (>= 1.1)", Suggests = "x"),
    caller = c(Version = "1.0", Imports = "sslish")))
  local_compiled_pkg(lib, "sslish")
  local_mocked_bindings(
    sys_linked_libraries = function(so) structure("/usr/lib/libssl.48.dylib", versions = "49.2.0"),
    sysreqs_match = function(spec, platform) list(data.frame(sysreq = "libssl", packages = I(list(character())))))
  x <- sbom_installed("caller", lib = lib)
  s <- sbom_components(x)
  s <- s[s$ref == "system/libssl", ]
  expect_equal(s$version_is, "minimum")
  expect_equal(s$evidence, "declared")
  expect_match(s$description, "the version is the declared minimum, not an observed one", fixed = TRUE)
  expect_match(s$description, "library version 49.2.0", fixed = TRUE)
  expect_equal(s$scope, "required")
})

test_that("a macOS machine without the Command Line Tools says so", {
  lib <- local_fake_lib(list(a = c(Version = "1")))
  local_compiled_pkg(lib, "a")
  local_mocked_bindings(
    sys_os_name = function() "Darwin",
    sys_xcode_tools = function() FALSE,
    sys_linked_libraries = function(so) stop("not called"))
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_equal(iss$message[iss$code == "links-not-checked"], paste0(
    "The shared libraries linked by compiled packages were not checked, because ",
    "otool cannot run without the Xcode Command Line Tools."
  ))
  local_mocked_bindings(
    sys_os_name = function() "Linux",
    sys_linked_libraries = function(so) structure(character(), tool_missing = TRUE))
  iss <- sbom_issues(sbom_installed("a", lib = lib))
  expect_match(iss$message[iss$code == "links-not-checked"], "neither otool nor ldd is available", fixed = TRUE)
})
