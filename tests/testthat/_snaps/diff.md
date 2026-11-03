# sbom_diff() reports additions, removals and changes

    Code
      print(d)
    Output
      0 added, 1 removed, 2 changed
      ~ cranpkg (version): 1.2.0 -> 1.3.0
      ~ localpkg (license): NOASSERTION -> MIT
      - suggestpkg 2.0.0

---

    Code
      print(sbom_diff(a, a))
    Output
      No differences.

