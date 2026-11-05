test_that("purl() builds package URLs the way R Observatory does", {
  expect_equal(purl("dplyr", "1.2.1"), "pkg:cran/dplyr@1.2.1")
  expect_equal(
    purl("DESeq2", "1.50.2", repository_url = "https://bioconductor.org/packages/3.22/bioc"),
    "pkg:cran/DESeq2@1.50.2?repository_url=https://bioconductor.org/packages/3.22/bioc"
  )
  expect_equal(purl("srcpkg", "abc123", source = "github", namespace = "example"),
               "pkg:github/example/srcpkg@abc123")
  expect_equal(
    purl("srcpkg", "abc123", source = "github", namespace = "example",
         repository_url = "https://github.acme.com"),
    "pkg:github/example/srcpkg@abc123?repository_url=https://github.acme.com"
  )
  expect_equal(purl("dplyr", NA), "pkg:cran/dplyr")
  expect_equal(purl(c("a", "b"), c("1", "2")), c("pkg:cran/a@1", "pkg:cran/b@2"))
  expect_error(purl("x", "1", source = "github"), "namespace")
  expect_equal(purl("p", "abc123", source = "gitlab", namespace = "team"), "pkg:gitlab/team/p@abc123")
  expect_equal(purl("p", "abc123", source = "bitbucket", namespace = "team"), "pkg:bitbucket/team/p@abc123")
  expect_error(purl("x", "1", source = "gitlab"), "namespace")
  expect_error(purl("x", "1", source = "bitbucket"), "namespace")
})

test_that("cran_doi() builds CRAN's DataCite DOI", {
  expect_equal(cran_doi("dplyr"), "10.32614/CRAN.package.dplyr")
  expect_equal(cran_doi(c("a", "b")), c("10.32614/CRAN.package.a", "10.32614/CRAN.package.b"))
})

test_that("unknown names and namespaces give NA, not a bogus identifier", {
  expect_identical(purl("srcpkg", "abc", source = "github", namespace = NA_character_),
                   NA_character_)
  expect_identical(purl("srcpkg", "abc", source = "github", namespace = ""),
                   NA_character_)
  expect_identical(purl(NA_character_, "1.0.0"), NA_character_)
  expect_identical(cran_doi(NA_character_), NA_character_)
  expect_identical(cran_doi(c("a", NA)), c("10.32614/CRAN.package.a", NA))
  expect_identical(
    purl(c("a", NA), "1", source = "github", namespace = c("ns", NA)),
    c("pkg:github/ns/a@1", NA)
  )
  expect_error(purl("x", "1", source = "github", namespace = NULL), "namespace")
})

test_that("purl() recycles only length-1 or common-length arguments", {
  expect_error(purl(c("a", "b", "c"), c("1", "2")), "length 1 or")
  expect_error(purl(c("a", "b"), "1", source = "github", namespace = c("x", "y", "z")), "name")
  expect_equal(purl(c("a", "b"), "1"), c("pkg:cran/a@1", "pkg:cran/b@1"))
})

test_that("an empty version is unknown, like NA", {
  expect_equal(purl("x", ""), "pkg:cran/x")
  expect_equal(purl("x", NA), "pkg:cran/x")
  expect_equal(purl(c("a", "b"), c("", "2")), c("pkg:cran/a", "pkg:cran/b@2"))
})
