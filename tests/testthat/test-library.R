test_that("base_packages() matches this R installation", {
  expect_setequal(base_packages(), rownames(installed.packages(priority = "base")))
})

test_that("resolve_dependencies() follows Depends, Imports and LinkingTo", {
  lib <- local_fake_lib(list(
    a = c(Version = "1.0", Imports = "b (>= 2.0), utils", Depends = "R (>= 4.1.0)"),
    b = c(Version = "2.1", LinkingTo = "c"),
    c = c(Version = "0.1"),
    s = c(Version = "3.0", Imports = "deep")
  ))
  db <- read_library(lib)
  root <- db$desc[[match("a", db$package)]]
  root["Suggests"] <- "s, nothere"
  r <- resolve_dependencies(root, library_lookup(lib), root_suggests = TRUE)
  expect_setequal(r$packages, c("b", "c", "s"))
  expect_equal(r$missing, "nothere")
  expect_true(all(c("R", "utils") %in% r$edges$to))
  expect_false("deep" %in% c(r$packages, r$missing))
  expect_equal(r$edges$field[r$edges$to == "s"], "Suggests")
})

test_that("base packages and R are never missing, even when absent from db", {
  lib <- local_fake_lib(list(a = c(Version = "1", Imports = "utils, stats", Depends = "R")))
  db <- read_library(lib)
  r <- resolve_dependencies(db$desc[[1L]], library_lookup(lib))
  expect_length(r$missing, 0L)
  expect_length(r$packages, 0L)
  expect_setequal(r$edges$to, c("utils", "stats", "R"))
})

test_that("the first library path wins", {
  lib1 <- local_fake_lib(list(b = c(Version = "2.0")))
  lib2 <- local_fake_lib(list(b = c(Version = "9.9")))
  db <- read_library(c(lib1, lib2))
  expect_equal(db$version[db$package == "b"], "2.0")
  expect_equal(sum(db$package == "b"), 1L)
  expect_equal(db$libpath[db$package == "b"], lib1)
})

test_that("cycles terminate and list each edge once", {
  lib <- local_fake_lib(list(a = c(Version = "1", Imports = "b"), b = c(Version = "1", Imports = "a")))
  db <- read_library(lib)
  r <- resolve_dependencies(db$desc[[match("a", db$package)]], library_lookup(lib))
  expect_equal(nrow(r$edges), 2L)
  expect_equal(r$packages, "b")
})

test_that("lock directories and broken entries are skipped", {
  lib <- local_fake_lib(list(a = c(Version = "1")))
  dir.create(file.path(lib, "00LOCK-a"))
  dir.create(file.path(lib, "empty"))
  dir.create(file.path(lib, "broken"))
  writeLines("Title: no package field", file.path(lib, "broken", "DESCRIPTION"))
  dir.create(file.path(lib, "garbled"))
  writeLines("not a dcf: \n\tcontinuation: : :\n", file.path(lib, "garbled", "DESCRIPTION"))
  dir.create(file.path(lib, "00LOCK-b"))
  writeLines(c("Package: lockb", "Version: 1"), file.path(lib, "00LOCK-b", "DESCRIPTION"))
  expect_equal(read_library(lib)$package, "a")
})

test_that("an empty or missing library gives a zero-row table", {
  lib <- withr::local_tempdir()
  for (paths in list(lib, file.path(lib, "nope"), character())) {
    db <- read_library(paths)
    expect_equal(nrow(db), 0L)
    expect_named(db, c("package", "version", "libpath", "desc"))
    expect_type(db$desc, "list")
  }
})

test_that("constraint_satisfied() compares versions", {
  expect_true(constraint_satisfied("1.3.0", ">= 1.3.0"))
  expect_false(constraint_satisfied("1.2.0", ">= 1.3.0"))
  expect_true(is.na(constraint_satisfied("1.2.0", NA)))
  expect_true(is.na(constraint_satisfied(NA, ">= 1")))
  expect_true(is.na(constraint_satisfied("1.0", "~> 1")))
  expect_true(is.na(constraint_satisfied("garbage", ">= 1")))
  expect_equal(
    constraint_satisfied(c("1.0", "2.0", "2.0", "2.0", "2.0", "1.0"),
                         c("> 1.0", "> 1.0", "<= 2.0", "< 2.0", "== 2.0", "!= 1.0")),
    c(FALSE, TRUE, TRUE, FALSE, TRUE, FALSE)
  )
})

test_that("a package both suggested and required keeps its dependencies", {
  lib <- local_fake_lib(list(
    a = c(Version = "1", Imports = "b", Suggests = "s"),
    b = c(Version = "1", Imports = "s"),
    s = c(Version = "1", Imports = "deep"),
    deep = c(Version = "1")
  ))
  db <- read_library(lib)
  r <- resolve_dependencies(db$desc[[match("a", db$package)]], library_lookup(lib), root_suggests = TRUE)
  expect_setequal(r$packages, c("b", "s", "deep"))
  expect_true(any(r$edges$from == "s" & r$edges$to == "deep"))
  expect_true(any(r$edges$from == "a" & r$edges$to == "s" & r$edges$field == "Suggests"))
})

test_that("a build reads only the DESCRIPTION files it reaches", {
  pkgs <- c(list(a = c(Version = "1", Imports = "b"), b = c(Version = "1")),
            stats::setNames(rep(list(c(Version = "1")), 300), sprintf("unused%03d", 1:300)))
  lib <- local_fake_lib(pkgs)
  calls <- new.env(); calls$n <- 0L
  real <- read_description
  local_mocked_bindings(read_description = function(path) { calls$n <- calls$n + 1L; real(path) })
  root <- withr::local_tempdir()
  write_text("Package: top\nVersion: 1.0\nImports: a\n", file.path(root, "DESCRIPTION"))
  x <- sbom_package(root, lib = lib)
  expect_setequal(sbom_components(x)$name[sbom_components(x)$ecosystem != "r"], c("top", "a", "b"))
  expect_lte(calls$n, 5L)
})

test_that("the library index keeps the first path and skips lock directories", {
  lib1 <- local_fake_lib(list(b = c(Version = "2.0")))
  lib2 <- local_fake_lib(list(b = c(Version = "9.9"), c = c(Version = "1")))
  dir.create(file.path(lib2, "00LOCK-c"))
  idx <- library_index(c(lib1, lib2))
  expect_equal(idx$package, c("b", "c"))
  expect_equal(library_lookup(c(lib1, lib2))$get("b")[["Version"]], "2.0")
  expect_null(library_lookup(c(lib1, lib2))$get("nothere"))
})

test_that("the library index skips directories without a DESCRIPTION and missing paths", {
  lib <- local_fake_lib(list(a = c(Version = "1")))
  dir.create(file.path(lib, "empty"))
  expect_equal(library_index(c(file.path(lib, "nope"), lib))$package, "a")
})

test_that("get() skips an unusable first copy as read_library() does", {
  lib1 <- local_fake_lib(list(b = c(Version = "2.0")))
  lib2 <- local_fake_lib(list(b = c(Version = "9.9")))
  write_text("Title: no package field\n", file.path(lib1, "b", "DESCRIPTION"))
  lookup <- library_lookup(c(lib1, lib2))
  expect_equal(lookup$get("b")[["Version"]], "9.9")
  expect_equal(read_library(c(lib1, lib2))$version, "9.9")
  expect_null(library_lookup(lib1)$get("b"))
})

test_that("lookups keep separate caches and all() matches read_library()", {
  lib1 <- local_fake_lib(list(b = c(Version = "1")))
  lib2 <- local_fake_lib(list(b = c(Version = "2")))
  l1 <- library_lookup(lib1)
  l2 <- library_lookup(lib2)
  expect_equal(l1$get("b")[["Version"]], "1")
  expect_equal(l2$get("b")[["Version"]], "2")
  expect_equal(l1$all(), read_library(lib1))
})
