# Nix store fixtures

Nix is not installed where these tests run, and no test can create files under
`/nix/store`. The fixtures were written by hand from the documentation, not
captured from a real Nix, and `local_nix_store()` (in `helper-nix.R`) serves
them in place of the Nix commands.

| File | Stands for |
| --- | --- |
| `instantiate.txt` | `nix-instantiate default.nix`: the shell derivation. |
| `references.txt` | `nix-store --query --references <shell.drv>`: its direct inputs, derivations and sources. |
| `outputs.txt` | `nix-store --query --outputs <input .drv files>`: the output paths of those inputs. |
| `requisites.txt` | `nix-store --query --requisites <outputs>`: the runtime closure. |
| `graph.dot` | `nix-store --query --graph <outputs>`: Graphviz DOT. |
| `descriptions/<pkg>.dcf` | `<out>/library/<pkg>/DESCRIPTION` of an R package output. A package with no file here has an unreadable DESCRIPTION (ggplot2, curl, rlang, cli and scales). |

The closure holds R 4.4.1, the R packages dplyr 1.1.4, data.table 1.15.4,
ggplot2 3.5.1, curl 5.2.1 and their R dependencies, the two packages that
`rix-date.nix` builds with `buildRPackage`: housing from git, whose store path
`r-housing` has no version (nixpkgs names it `"r-" + name`, and rix gives only
the name), so its DESCRIPTION gives 0.1.0, and AER 1.2-8 from the CRAN archive,
and curl 8.9.1 in four
outputs (`-bin`, `-dev`, `-lib` and the default), openssl, zlib, libpng, glibc
glibc-locales, and bash 5.2p26 with a `-man` output (a direct input whose man output a test treats as never fetched). In `graph.dot`, R packages link to a library (r-curl to
`curl-8.9.1-lib`), to non-libraries (r-data.table to zlib and glibc), to each
other (r-housing to r-dplyr) and to R.

Format notes (Nix 2.34 reference manual, `nix-store --query`; the DOT layout
from the source of `printDotGraph`, Nix 2.18):

* `--references`, `--outputs` and `--requisites` print one store path per line.
* `--graph` prints `digraph G { ... }`. Each node is
  `"<hash>-<name>" [label = "<name>", shape = box, style = filled, fillcolor = "#ff0000"];`
  and each edge is `"<dependency>" -> "<dependent>" [color = "#rrggbb"];`: the
  arrow points from the path that is referenced to the path that references it.
* Hashes are 32 characters of Nix's base32 alphabet, `0123456789abcdfghijklmnpqrsvwxyz`.
