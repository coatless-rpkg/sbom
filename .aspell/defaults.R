# R CMD check --as-cran spell-checks DESCRIPTION with this file: R's statistics
# dictionary, plus the correct terms in words.rds that it would otherwise flag.
Rd_files <- vignettes <- R_files <- description <-
  list(encoding = "UTF-8", dictionaries = c("en_stats", "words"))
