#' @keywords internal
"_PACKAGE"

# Package-level environment for caches: the rules tables that
# vendored_rules() and javascript_rules() read once per session.
the <- new.env(parent = emptyenv())
