# OSV advisory fixtures

The records in `records/` and in the zips are synthetic. They follow the shape
of the records in OSV's CRAN export
(`https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip`), but every
package name (`fakepkg`, `openpkg`, `lastpkg`, `listpkg`, `twopkg`, `badpkg`,
`oddpkg`), id (`RSEC-9000-*`, `PYSEC-2099-1`), upstream id (`CVE-2099-*`) and
URL is made up, and no text is copied from a real advisory, so no licence
applies to them. Each record in `records/` exercises one rule of `osv_read_zip()` and `osv_match()`:

| Record | Package | What it holds |
|---|---|---|
| RSEC-9000-1 | fakepkg | An `ECOSYSTEM` range from 0.1.0 to fixed 1.1.0, listed versions 0.1.0, 0.1.1 and 1.0.0, upstream CVE-2099-0001, a `database_specific.source` URL |
| RSEC-9000-2 | openpkg | Introduced 0 with no fix |
| RSEC-9000-3 | lastpkg | A `SEMVER` range from 1.0 to last_affected 1.2-3; the latest `modified`, with a fraction of a second |
| RSEC-9000-4 | listpkg | Listed versions only, 2.0.1 and 2.0-2 |
| RSEC-9000-5 | fakepkg | Withdrawn; every version |
| RSEC-9000-6 | fakepkg | Ecosystem Bioconductor; every version |
| RSEC-9000-7 | twopkg | One range with two intervals, 1.0 to fixed 1.5 and 2.0 to fixed 2.3, and a `GIT` range, which is ignored |
| RSEC-9000-8 | badpkg | Introduced `not-a-version`; an empty summary |

The zips are made by `make-zips.R`, which needs an external zip program and is
run by hand from the package root; the tests only read the committed zips.

| Zip | Entries |
|---|---|
| `all.zip` | The eight records, each as `<id>.json` |
| `evil-names.zip` | `../x.json` and `a/b.json` |
| `not-json.zip` | `README.txt` |
| `bad-json.zip` | `RSEC-9000-90.json`, whose text is not JSON |
| `no-id.zip` | `RSEC-9000-91.json`, a JSON object without an id |
| `bad-id.zip` | `RSEC-9000-94.json`, whose id holds a slash and a space |
| `odd.zip` | `a.json` and `b.json`, two records with one id, and `c.json`, a record whose fields have the wrong JSON types; `make-zips.R` lists what each holds |
| `not-cran.zip` | `PYSEC-2099-1.json`, a record of a PyPI package, and `RSEC-9000-95.json`, a record without affected packages: no CRAN record |
| `affected-object.zip` | `RSEC-9000-96.json`, whose `affected` is an object, not an array |
| `empty-affected.zip` | `RSEC-9000-97.json`, whose affected entry is `{}` |
| `no-package.zip` | `RSEC-9000-98.json`, whose affected entry has no `package` |
