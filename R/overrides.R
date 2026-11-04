# Overrides: values a person asserts where sbom found nothing (or something
# different). Each applied value is recorded in the component's `asserted`
# table with who asserted it and why.

override_columns <- function() c("component", "field", "value", "asserted_by", "reason")

override_fields <- function() {
  c(
    "version", "license_spdx", "supplier_name", "supplier_url", "maintainer",
    "purl", "download_location"
  )
}

# Row numbers count data rows, so row 1 is line 2 of a CSV file.
read_overrides <- function(overrides, call = parent.frame()) {
  if (is.character(overrides) && length(overrides) == 1 && !is.na(overrides)) {
    if (!file.exists(overrides)) {
      cli::cli_abort("The overrides file {.file {overrides}} does not exist.", call = call)
    }
    overrides <- utils::read.csv(
      overrides, colClasses = "character", na.strings = "",
      stringsAsFactors = FALSE, encoding = "UTF-8", check.names = FALSE
    )
  } else if (!is.data.frame(overrides)) {
    cli::cli_abort(
      "{.arg overrides} must be {.code NULL}, a data frame or a path to a CSV file.",
      call = call
    )
  }
  missing <- setdiff(override_columns(), names(overrides))
  if (length(missing) > 0) {
    cli::cli_abort(
      c(
        "{.arg overrides} must have the columns {.val {override_columns()}}.",
        "x" = "Missing {cli::qty(length(missing))}column{?s}: {.val {missing}}."
      ),
      call = call
    )
  }
  out <- overrides[, override_columns(), drop = FALSE]
  out[] <- lapply(out, as.character)
  rownames(out) <- NULL
  out
}

match_component <- function(comps, value, row, call) {
  # An embedded component shares its name with the package it copies, so only
  # its ref names it.
  hits <- which(comps$ref %in% value |
    (comps$name %in% value & !is_embedded_ref(comps$ref)))
  if (length(hits) == 0) {
    cli::cli_abort(
      c(
        "Override row {row} names an unknown component, {.val {value}}.",
        "i" = "{.field component} must equal the {.field name} or {.field ref} of a component."
      ),
      call = call
    )
  }
  if (length(hits) > 1) {
    refs <- comps$ref[hits]
    cli::cli_abort(
      c(
        "Override row {row} names an ambiguous component, {.val {value}}.",
        "i" = "It matches {length(refs)} components: {.val {refs}}.",
        "i" = "Use the {.field ref} to choose one."
      ),
      call = call
    )
  }
  hits
}

apply_overrides <- function(x, overrides) {
  if (is.null(overrides)) {
    return(x)
  }
  ov <- read_overrides(overrides)
  ov[] <- lapply(ov, enc2utf8_bytes)
  comps <- x$components
  issues <- x$issues
  for (i in seq_len(nrow(ov))) {
    row <- ov[i, ]
    for (col in override_columns()) {
      if (is.na(row[[col]])) {
        cli::cli_abort(
          "Override row {i} has no {.field {col}}, and an override must assert something."
        )
      }
    }
    field <- row$field
    if (!field %in% override_fields()) {
      cli::cli_abort(c(
        "Override row {i} names an unknown field, {.val {field}}.",
        "i" = "{.field field} must be one of {.val {override_fields()}}."
      ))
    }
    at <- match_component(comps, row$component, i, call = NULL)
    ref <- comps$ref[at]
    name <- comps$name[at]
    old <- comps[[field]][at]
    new <- row$value
    if (!is.na(old) && !identical(old, new)) {
      issues <- add_issue(
        issues, ref, field, "override-conflict",
        paste0(
          "The ", field, " of ", name, " was ", old, " as found and is ", new,
          " as asserted by ", row$asserted_by, "."
        ),
        severity = "info"
      )
    }
    comps[[field]][at] <- new
    if (field == "license_spdx") {
      note <- paste0("Asserted by ", row$asserted_by, ": ", row$reason, ".")
      old_comment <- comps$license_comment[at]
      comps$license_comment[at] <- if (is.na(old_comment)) note else paste(old_comment, note)
      issues <- issues[!(issues$ref == ref &
        issues$code %in% c("license-no-spdx", "license-missing")), , drop = FALSE]
    }
    if (field == "supplier_name") {
      issues <- issues[!(issues$ref == ref & issues$code == "supplier-unknown"), , drop = FALSE]
    }
    record <- data.frame(
      field = field, value = new, asserted_by = row$asserted_by,
      reason = row$reason, stringsAsFactors = FALSE
    )
    prior <- comps$asserted[[at]]
    comps$asserted[[at]] <- if (is.data.frame(prior) && all(names(record) %in% names(prior))) {
      rbind(prior[, names(record), drop = FALSE], record)
    } else {
      record
    }
  }
  rownames(issues) <- NULL
  x$components <- comps
  x$issues <- issues
  x
}
