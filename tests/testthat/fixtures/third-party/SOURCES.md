# Third-party SBOM fixtures

SBOM files from the format specifications: the SPDX specification's examples
and the CycloneDX specification's schema test files. The tests read and
validate them as documents sbom did not write. Every file except
`swid/hand.swidtag`, which was written for these tests, is copied byte for
byte from upstream and is unmodified. Each source is pinned to the commit its
branch pointed at when the file was fetched (2026-11-06), and each file's
SHA-256 is listed. Licences and attribution are also recorded in
`inst/COPYRIGHTS`.

## spdx-2.3/

- Source: https://github.com/spdx/spdx-spec, branch `support/2.3`, commit
  `6f2cb47d13db19b12c23885573b22ef32ec1ada5`, directory `examples/`.
  Raw URL: `https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/examples/<file>`.
- Title: the SPDX 2.3 specification's example documents (the four files below).
- Creator: Linux Foundation and its Contributors (the SPDX project). The
  specification on that branch states "Copyright © 2010-2026 Linux Foundation
  and its Contributors."
- Licence: Creative Commons Attribution 3.0 Unported (CC-BY-3.0),
  <https://creativecommons.org/licenses/by/3.0/>, as the repository's
  `LICENSE` on that branch states.
- Changes: none; every file is unmodified.
- The four files describe the same document, with packages, files, snippets,
  extracted licences, annotations and an external document reference.

| File | SHA-256 |
|---|---|
| `SPDXJSONExample-v2.3.spdx.json` | `2de3741a7be1be5f5e54e837524f2ec627fedfb82307dc004ae03b195abc092f` |
| `SPDXTagExample-v2.3.spdx` | `f0e2ab03e332f5b31cdba4a4b6bffe0d612dd54fa4cc8f7cdbe69a26dbfbc50d` |
| `SPDXXMLExample-v2.3.spdx.xml` | `47e0e3e899244ad6c2ca25f1fdae93214c4595e97882794feb3d3c49fe9ceef4` |
| `SPDXYAMLExample-2.3.spdx.yaml` | `5d0f18f653449a45b0b192fe07fadfff408aae725e37113c16b126a3298e15b1` |

## spdx-2.2/

- Source: https://github.com/spdx/spdx-spec, branch `development/v2.2.2`,
  commit `4694d1fe63ecd269262c26bd4370d4e11e6f7f8f`, directory `examples/`.
  Raw URL: `https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.2.2/examples/<file>`.
- Title: the SPDX 2.2 specification's example documents (the four files below).
- Creator: Linux Foundation and its Contributors (the SPDX project). The
  specification on that branch states "Copyright © 2010 - 2022 Linux
  Foundation and its Contributors."
- Licence: Creative Commons Attribution 3.0 Unported (CC-BY-3.0),
  <https://creativecommons.org/licenses/by/3.0/>, as the repository's
  `LICENSE` on that branch states.
- Changes: none; every file is unmodified.

| File | SHA-256 |
|---|---|
| `SPDXJSONExample-v2.2.spdx.json` | `e2a5da0f6d58df3f3608d878e75ee683c0a1430debace64623e19b84f83fd881` |
| `SPDXTagExample-v2.2.spdx` | `ac7d21ef8efd6f78672eef1e667e1aeada0105d1aa950d280da6ac1dd61fe1e7` |
| `SPDXXMLExample-v2.2.spdx.xml` | `78c60b3a857d28ce1011bd4d0066a0d8aedd087ff57552d1568e96911fe891fc` |
| `SPDXYAMLExample-2.2.spdx.yaml` | `56128dd78fd2b6ba32f2e20e00aebf4d7f74004b269ced3ab139ed7ebb15ca7d` |

## spdx-3/

- Source: https://github.com/spdx/spdx-spec, branch `support/3.0`, commit
  `0232660029bc66f6e25b33c49379c03c87fdaaed`, file
  `examples/jsonld/package_sbom.json`.
  Raw URL: `https://raw.githubusercontent.com/spdx/spdx-spec/support/3.0/examples/jsonld/package_sbom.json`.
- Title: `package_sbom.json`, the JSON-LD example of the SPDX 3.0.1
  specification.
- Creator: The Linux Foundation and its Contributors. The specification on
  that branch states "SPDX 3.0 Copyright © 2010-2026, The Linux Foundation
  and its Contributors, including SPDX Model contributions from OMG and its
  Contributors."
- Licence: the repository's `LICENSE` on that branch,
  <https://github.com/spdx/spdx-spec/blob/support/3.0/LICENSE>, says:
  - "The SPDX Specification is provided under the Community Specification
    License 1.0 (Community-Spec-1.0), a copy of which is included below."
    That `LICENSE` file holds the full text; the SPDX License List has it at
    <https://spdx.org/licenses/Community-Spec-1.0.html>.
  - "Pre-existing portions of the SPDX Specification from copyright holders
    who have not subsequently contributed under the Community Specification
    License 1.0 are provided under Creative Commons Attribution 3.0 Unported
    (CC-BY-3.0)", <https://creativecommons.org/licenses/by/3.0/>.

  Both allow redistribution with attribution. Section 1.2 of
  Community-Spec-1.0 asks for the material's name, version and source, which
  this entry gives. These are the same terms as the bundled SPDX 3.0.1 schema.
- Changes: none; the file is unmodified.
- The graph has one package, one file, one relationship and a blank-node
  `creationInfo` (`_:creationinfo`).

| File | SHA-256 |
|---|---|
| `package_sbom.json` | `97f4455b30e1e69918b8ef0a696b40c6826e5c5381ab2ae871ca7424c1933b33` |

## cyclonedx/

- Source: https://github.com/CycloneDX/specification, branch `master`,
  commit `6470e34ef83f915868ece48934cff52e10c9eb49`, directory
  `tools/src/test/resources/<version>/`, the specification's own schema test
  files. Raw URL: `https://raw.githubusercontent.com/CycloneDX/specification/master/tools/src/test/resources/<version>/<file>`.
- Licence: Apache License 2.0 (Apache-2.0),
  <https://www.apache.org/licenses/LICENSE-2.0>, the repository's `LICENSE`.
  The repository has no `NOTICE` file at that commit, so there is no notice
  text to reproduce.
- Copyright: OWASP Foundation, as the `LICENSE` states.
- Changes: none; every file is unmodified.
- Every requested file exists upstream under its requested name, so nothing
  was substituted. `valid-bom-1.3.json` is for version detection only: sbom
  bundles no CycloneDX 1.3 schema.

| File | Upstream folder | SHA-256 |
|---|---|---|
| `invalid-component-type-1.6.json` | `1.6/` | `bd45f056f8667103f0e2294aa7b9b498b9559b1ed0a436145ab1d5fc5a05c1e3` |
| `valid-bom-1.3.json` | `1.3/` | `a91d7054a4019b629250300333c40bdba0411f4577767f9d8bd9ae6f74b08ad4` |
| `valid-bom-1.4.json` | `1.4/` | `21eba6ac11cc6237542177c9d86e6e73be569fb294eabd09da6615ada1232ad5` |
| `valid-bom-1.5.xml` | `1.5/` | `2c233cea3efc27bda76b25ecf9475f6bd75258412ddd1c77e56895d246856486` |
| `valid-bom-1.6.json` | `1.6/` | `c561927ee0d09a88cad7c939c7220746bb978016455ea36f37de39554a9e4ec1` |
| `valid-bom-1.6.xml` | `1.6/` | `b98ed2560e8ba65e851f58c2c37180247dd3581cb31844812bd86bbaafa78b04` |
| `valid-bom-1.7.json` | `1.7/` | `2dcdb3d43647a8802e98124dacec76f2b00091bf567febef6306d58d5b0b04dd` |
| `valid-component-hashes-1.6.json` | `1.6/` | `6c51f4e61503ee0d2b858715d470234f3a3125e5f0a6e49b2758a185bc1ec556` |
| `valid-component-hashes-1.6.xml` | `1.6/` | `003e1c060401455543f392ae179414b19cab53a0f41ee780cab5cafa3a135c7a` |
| `valid-dependency-1.6.json` | `1.6/` | `209b8a93cbc623b41c8da43a72ccce74b17eb2c14db4cece3ba2473bd9087a76` |
| `valid-dependency-1.6.xml` | `1.6/` | `0ef03908ac84b0656518d3d9528317c70232eb78337c1dddf3c953c66e10cd37` |
| `valid-external-reference-1.6.json` | `1.6/` | `3773f727563f00ed8163a66e6643c6e05acff5b7a9d385ec3fb4f4ea777fd90b` |
| `valid-external-reference-1.6.xml` | `1.6/` | `5d060375fa8e2c8d37032ab7cc51279a304b7088458b84d5cdfd0014655a560c` |
| `valid-license-expression-1.6.json` | `1.6/` | `178c0705b30f5f3881d0930ba664f5c6f4630e1a8cfc0619bf75640e65dbd5b2` |
| `valid-license-expression-1.6.xml` | `1.6/` | `97d662f1ce7f0cf86ee946c1d5f278d3fb9eac1bc99569f1a80255a5a1170dc2` |
| `valid-metadata-author-1.6.json` | `1.6/` | `e465d862dc77da1f7e0f505bda995f7aa7599a9209d3cea9a9b7661c8096456e` |
| `valid-metadata-author-1.6.xml` | `1.6/` | `7f44b1532ed771252761216f460bea15a37c4d774f64a50f4e1d393659a3a980` |
| `valid-metadata-tool-1.6.json` | `1.6/` | `2a6fa2cc725711089dfd1918127f56feacd1a10a76a0fb37c6d08c9bcd3adb64` |
| `valid-metadata-tool-1.6.xml` | `1.6/` | `e7f9d1c8183ec05a8e86ce5755da723fa1288e9a2922869157dad887c1bddeeb` |

## swid/

- `hand.swidtag` was written by hand for these tests, as part of the sbom
  package (MIT licence), so no third-party licence applies. It is not copied
  from any published example. It is a minimal ISO/IEC 19770-2:2015 tag with a
  `tagCreator` entity, a `softwareCreator` entity and two `requires` links,
  and it passes the bundled SWID schema.

| File | SHA-256 |
|---|---|
| `hand.swidtag` | `7f2baffe0eb1f340dfa988fb2666ae80dfa15e44392d46e01fe0eb538891f7b3` |
