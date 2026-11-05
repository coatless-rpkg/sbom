# print() reports the findings by severity and check, with hints

    Code
      print(v)
    Output
      SPDX JSON 2.3, SPDXJSONExample-v2.3.spdx.json: FAIL
      Profile: ntia-2021.
      
      -- Errors --
      
      x ntia-identifier: 2 findings
        * Apache Commons Lang has no purl, CPE or SWID identifier. (/packages/1)
        * Saxon 8.8 has no purl, CPE or SWID identifier. (/packages/3)
        i Give each component a purl, CPE or SWID tag id; if sbom made this SBOM,
          assert a purl it cannot find with an override of purl.
      x ntia-supplier: 3 findings
        * Apache Commons Lang has no supplier. (/packages/1)
        * Jena 3.12.0 has no supplier. (/packages/2)
        * Saxon 8.8 has no supplier. (/packages/3)
        i State each component's supplier; if sbom made this SBOM, assert the ones it
          cannot find with an override of supplier_name.
      x Apache Commons Lang has no version. (/packages/1)
        i State each component's version; if sbom made this SBOM, assert the ones it
          cannot find with an override of version.

---

    Code
      print(validate_sbom(write_format(described_sbom(), "cyclonedx-json",
      "srcpkg.cdx.json")))
    Output
      CycloneDX JSON 1.6, srcpkg.cdx.json: PASS
      Profile: ntia-2021.
      No findings.

---

    Code
      print(validate_sbom(fixture_sbom()))
    Output
      <sbom> object: FAIL
      Profile: ntia-2021.
      
      -- Errors --
      
      x ntia-identifier: 5 findings
        * R 4.1.0 has no purl, CPE or SWID identifier. (component R)
        * methods has no purl, CPE or SWID identifier. (component R/methods)
        * utils has no purl, CPE or SWID identifier. (component R/utils)
        ... and 2 more.
        i Give each component a purl, CPE or SWID tag id; if sbom made this SBOM,
          assert a purl it cannot find with an override of purl.
      x ntia-supplier: 4 findings
        * R 4.1.0 has no supplier. (component R)
        * methods has no supplier. (component R/methods)
        * utils has no supplier. (component R/utils)
        ... and 1 more.
        i State each component's supplier; if sbom made this SBOM, assert the ones it
          cannot find with an override of supplier_name.
      x ntia-version: 2 findings
        * methods has no version. (component R/methods)
        * utils has no version. (component R/utils)
        i State each component's version; if sbom made this SBOM, assert the ones it
          cannot find with an override of version.
      
      Use as.data.frame() to see every finding.

# print() shows a read failure, and never prints a control character from the file

    Code
      print(validate_sbom(path))
    Output
      notes.json: FAIL
      Profile: ntia-2021.
      
      -- Errors --
      
      x notes.json is not an SBOM in a format sbom reads.
        i Check that the file is an SBOM in a format sbom reads (see sbom_formats()),
          written in UTF-8.

# braces from the file print as they are, in print() and in the error_on message

    Code
      print(v)
    Output
      CycloneDX JSON 1.6, {nope}}{.cdx.json: FAIL
      Profile: ntia-2021.
      
      -- Errors --
      
      x ntia-supplier: 2 findings
        * One {.emph x} {nope} }{ has no supplier. (/a/{nope})
        * Two {.emph x} {nope} }{ has no supplier. (/b/}{)
        i State each component's supplier; if sbom made this SBOM, assert the ones it
          cannot find with an override of supplier_name.
      x {.emph x} {nope} }{ has no version. (/c/{.emph x})
        i State each component's version; if sbom made this SBOM, assert the ones it
          cannot find with an override of version.

