# summary() counts components, licences, unknowns and drift

    Code
      print(s)
    Output
      srcpkg 0.1.0
      
      -- Components --
      
      ecosystem: base-r (2), cran (2), local (2), r (1)
      type: library (6), platform (1)
      evidence: observed (3), declared (2), inferred (2)
      Unknown version or licence: 3
      
      -- Licences --
      
      NOASSERTION (3), GPL-2.0-only OR GPL-3.0-only (2), MIT (2)
      
      -- Drift --
      
      No drift.

# summary() reports drift issues

    Code
      print(s)
    Output
      a 1.0
      
      -- Components --
      
      ecosystem: cran (2), r (1)
      type: library (2), platform (1)
      Unknown version or licence: 3
      
      -- Licences --
      
      NOASSERTION (3)
      
      -- Drift --
      
      ! b is 2.0 in the lockfile but 2.1 in the library.

# sbom_tree() prints the tree once per node and respects max_depth

    Code
      sbom_tree(x)
    Output
      srcpkg 0.1.0
      +-R 4.1.0
      | +-methods
      | \-utils
      +-cranpkg 1.2.0
      | \-methods (see above)
      +-localpkg 0.0.1
      +-suggestpkg 2.0.0 (suggested)
      \-utils (see above)

---

    Code
      sbom_tree(x, max_depth = 1)
    Output
      srcpkg 0.1.0
      +-R 4.1.0
      +-cranpkg 1.2.0
      +-localpkg 0.0.1
      +-suggestpkg 2.0.0 (suggested)
      \-utils

# sbom_tree() terminates on cycles and rejects a bad max_depth

    Code
      sbom_tree(x)
    Output
      a 1.0
      \-b 2.0
        \-a 1.0 (see above)

