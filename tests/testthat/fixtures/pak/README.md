# pak's tool rules

`tool-rules.txt` lists the rules of pak's system requirements database
whose names are programs rather than libraries: the file names, without
`.json`, of the rules under `sysreqs/rules` in the pkgdepends that pak 0.11.1
ships (rules commit 1da4eec6470c8b97c2310bc8d62eb7c04547699c), chosen by the
operating system packages each rule installs. sbom's `sysreq_programs` must
hold every one of them; `test-sysreqs.R` checks that, and checks that each
name is still a rule when pak is installed.
