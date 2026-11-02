# print.sbom() summarises

    Code
      print(minimal_sbom())
    Output
      <sbom> a 1.0
      Components: 3
      Relationships: 1
      Issues: 0

# print.sbom() handles issues and a root without a version

    Code
      print(x)
    Output
      <sbom> a
      Components: 3
      Relationships: 1
      Issues: 1 (see sbom_issues())

