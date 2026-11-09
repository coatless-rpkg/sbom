# Reading SPDX YAML with the yaml package, after a scan for deep nesting,
# aliases and extra documents (yaml_problem()), so that hostile YAML cannot
# exhaust R.

# YAML types that the yaml package turns into numbers or NA. Their text is
# kept: `versionInfo: 1.10` is "1.10", not 1.1.
spdx_yaml_text_types <- c(
  "int#hex", "int#oct", "int#base60", "int#na", "float", "float#fix",
  "float#exp", "float#base60", "float#nan", "float#inf", "float#neginf",
  "float#na", "bool#na"
)

# Decimal integers and booleans keep their text too, carrying a mark until
# the enclosing map or sequence is built. There an integer under an integer
# key becomes an integer, and a boolean under a boolean key a logical;
# anywhere else they are plain text, so `name: no` is "no".
spdx_yaml_unmark <- function(x, key) {
  bool <- attr(x, "sbom_bool", exact = TRUE)
  if (!is.null(bool)) {
    return(if (key %in% spdx_json_booleans) bool else as.vector(x))
  }
  if (isTRUE(attr(x, "sbom_int", exact = TRUE))) {
    return(spdx_typed_value(as.vector(x), key))
  }
  x
}

# The handlers that read the YAML tags as text, keeping the marks that
# spdx_yaml_unmark() resolves, and unmark each sequence and map.
spdx_yaml_handlers <- function() {
  text <- rep(list(function(x) x), length(spdx_yaml_text_types))
  names(text) <- spdx_yaml_text_types
  c(text, list(
    int = function(x) structure(x, sbom_int = TRUE),
    `bool#yes` = function(x) structure(x, sbom_bool = TRUE),
    `bool#no` = function(x) structure(x, sbom_bool = FALSE),
    # Keep every sequence a list, so a one-element array stays an array.
    seq = function(x) lapply(unname(as.list(x)), spdx_yaml_unmark, key = ""),
    map = function(x) {
      for (i in seq_along(x)) {
        x[i] <- list(spdx_yaml_unmark(x[[i]], names(x)[i]))
      }
      x
    }
  ))
}

# The names a YAML text uses both as an anchor (&name) and as an alias
# (*name), found in the text before it is parsed. A name is a run of
# libyaml's anchor characters, [A-Za-z0-9_-], which is where libyaml itself
# ends it: `&a:x` anchors ":x" as `a`.
yaml_alias_names <- function(txt) {
  names_after <- function(mark) {
    found <- regmatches(txt, gregexpr(paste0(mark, "[A-Za-z0-9_-]+"), txt, perl = TRUE))[[1]]
    substring(found, 2L)
  }
  aliases <- names_after("\\*")
  aliases[aliases %in% names_after("&")]
}

# Reads an SPDX YAML file into the list `jsonlite::fromJSON(spdx_json(x),
# simplifyVector = FALSE)` gives. Needs the yaml package. The bytes are read
# as UTF-8, whatever the native locale. A `!expr` tag is read as text and
# never evaluated, whatever the yaml.eval.expr option says. A document that
# uses aliases is refused unparsed, with an error of class `sbom_yaml_alias`:
# SPDX never needs them, and a few hundred bytes of aliases can expand to
# gigabytes. So is one that nests more than json_max_depth levels deep, with
# an error of class `sbom_json_limit`, as JSON is, and one that holds more
# than one YAML document, with an error of class `sbom_yaml_documents`
# (yaml_problem()).
spdx_yaml_read <- function(path) {
  spdx_yaml_parse(read_utf8_text(path), read_file_label(path))
}

# The same, for the text of the file named `file`.
spdx_yaml_parse <- function(txt, file) {
  aliases <- yaml_alias_names(txt)
  if (length(aliases) > 0L) {
    name <- quote_value(aliases[1], 40L)
    cli::cli_abort(
      "{file} uses YAML aliases (*{name}), which sbom does not expand.",
      class = "sbom_yaml_alias", call = NULL
    )
  }
  problem <- yaml_problem(txt)
  if (identical(problem, "deep")) {
    cli::cli_abort("it nests more than {json_max_depth} levels deep", class = "sbom_json_limit", call = NULL)
  }
  if (identical(problem, "documents")) {
    cli::cli_abort("it holds more than one YAML document", class = "sbom_yaml_documents", call = NULL)
  }
  doc <- yaml::yaml.load(txt, eval.expr = FALSE, handlers = spdx_yaml_handlers())
  spdx_yaml_unmark(doc, "")
}

# The most columns a line of YAML may be indented, counting the "- " and
# "? " that open nested collections on it.
yaml_max_indent <- 400L

# What would make YAML text unsafe to hand to libyaml, judged from its text
# before it is parsed: "deep" when it nests more than `max` levels, since
# libyaml, through the yaml package, takes time quadratic in the depth, so a
# few hundred kilobytes of brackets would take minutes; "documents" when it
# holds more than one YAML document, of which yaml.load() keeps only the
# first, unchecked; NA otherwise.
#
# * A block collection nests one level for each column of indentation at
#   least, so a line indented more than yaml_max_indent columns is too deep.
# * A `---` or `...` marker at the start of a line after the first document's
#   content, outside a block scalar, starts another document.
# * Flow collections ([ and {) are counted by yaml_scan(), unless the text
#   holds too few brackets to nest that deep, or is JSON (yaml_json_depth()).
#
# Every step takes time linear in the size of the text.
yaml_problem <- function(txt, max = json_max_depth) {
  indent <- sprintf("(^|\n)(?:[ \t]|[-?:](?=[ \t])){%d}", yaml_max_indent + 1L)
  if (grepl(indent, txt, perl = TRUE, useBytes = TRUE)) {
    return("deep")
  }
  bytes <- charToRaw(txt)
  lines <- NULL
  markers <- integer()
  if (grepl("\n(---|\\.\\.\\.)([ \t\r\n]|$)", txt, perl = TRUE, useBytes = TRUE)) {
    lines <- yaml_text_lines(bytes)
    markers <- yaml_later_markers(lines)
  }
  if (length(markers) == 0L) {
    opens <- sum(bytes == as.raw(0x5b) | bytes == as.raw(0x7b))
    # An empty [] or {} can only be the innermost level.
    empty <- length(grepRaw("[]", bytes, fixed = TRUE, all = TRUE)) +
      length(grepRaw("{}", bytes, fixed = TRUE, all = TRUE))
    if (opens <= max || opens - empty < max) {
      return(NA_character_)
    }
    json <- yaml_json_depth(txt)
    if (!is.na(json)) {
      return(if (json > max) "deep" else NA_character_)
    }
  }
  if (is.null(lines)) lines <- yaml_text_lines(bytes)
  scan <- yaml_scan(bytes, lines, max)
  if (scan$deep) {
    return("deep")
  }
  if (any(!scan$in_block_scalar[markers])) {
    return("documents")
  }
  NA_character_
}

# The lines of YAML text given as `bytes`, with what the scans need of each:
# its text, where it starts and ends, its indentation, and whether it is
# blank, only a comment, a directive (%YAML, %TAG) or a document marker.
yaml_text_lines <- function(bytes) {
  nl <- as.numeric(which(bytes == as.raw(0x0a)))
  text <- strsplit(rawToChar(bytes), "\n", fixed = TRUE, useBytes = TRUE)[[1]]
  n_lines <- length(nl) + 1L
  text <- c(text, rep("", n_lines - length(text)))
  list(
    text = text,
    start = c(1, nl + 1),
    end = c(nl - 1, length(bytes)),
    indent = attr(regexpr("^ *", text, useBytes = TRUE), "match.length"),
    blank = !grepl("[^ \t\r]", text, useBytes = TRUE),
    comment = grepl("^[ \t]*#", text, useBytes = TRUE),
    directive = startsWith(text, "%"),
    marker = grepl("^(---|\\.\\.\\.)([ \t\r]|$)", text, useBytes = TRUE)
  )
}

# The lines holding a `---` or `...` marker after the first document's
# content: a line that is not blank, a comment, a directive or a bare `---`.
# A `...` that only ends the document, with nothing after it, starts none.
yaml_later_markers <- function(lines) {
  bare_start <- grepl("^---[ \t\r]*(#.*)?$", lines$text, useBytes = TRUE)
  content <- !lines$blank & !lines$comment & !lines$directive & !bare_start &
    !grepl("^\\.\\.\\.[ \t\r]*(#.*)?$", lines$text, useBytes = TRUE)
  first <- match(TRUE, content)
  if (is.na(first)) {
    return(integer())
  }
  later <- which(lines$marker & seq_along(lines$marker) > first)
  last_content <- max(which(content))
  ends_only <- startsWith(lines$text[later], "...") & later > last_content
  later[!ends_only]
}

# Scans YAML text, given as `bytes` with its `lines` (yaml_text_lines()), as
# libyaml tokenizes it, for flow collections nested deeper than `max`.
# Returns list(deep, in_block_scalar), the second marking the lines inside
# block scalars. Only the bytes YAML gives a meaning outside plain text are
# visited: quotes, brackets, # and the block scalar indicators | and >.
#
# * In flow context, inside brackets, a bracket is always an indicator. A
#   quote starts a quoted scalar only where a node starts: after [, {, a
#   comma, a ? that begins a token, a colon followed by a blank or that
#   begins a token, or a whole anchor or tag token, itself where a node
#   starts, followed by a blank. A ?, & or ! inside or ending a plain word
#   is plain text.
# * In block context a node starts after "key: ", or at the start of a line
#   after indentation, "- ", "? ", ": ", anchors and tags, unless the line
#   goes on with a plain scalar from the lines above, as it does when it is
#   indented more than the collection holding that scalar. A node also starts
#   after a `---` marker. A directive line is skipped.
# * A quoted scalar or a block scalar is skipped whole, and a comment to the
#   end of its line. A line that is only "key: " and a double-quoted string,
#   or "- " and one, as sbom writes YAML, is skipped whole in block context.
#
# Each byte visited costs constant time, or a binary search: the bytes before
# one are found from the runs of blanks, and what a line says of the lines
# below it is worked out once.
yaml_scan <- function(bytes, lines, max = json_max_depth) {
  n <- length(bytes)
  n_lines <- length(lines$start)
  # findInterval() makes its vector a double and checks it is sorted, which
  # takes linear time, so the vectors it searches are doubles, not checked.
  find <- function(x, vec) findInterval(x, vec, checkSorted = FALSE, checkNA = FALSE)
  byte <- function(p) as.integer(bytes[p])
  blank_bytes <- as.raw(c(0x20, 0x09, 0x0d, 0x0a))
  is_blank <- function(p) bytes[p] %in% blank_bytes
  line_of <- function(p) find(p, lines$start)

  runs <- gregexpr("[ \t\r\n]+", rawToChar(bytes), useBytes = TRUE)[[1]]
  run_start <- if (runs[1L] > 0L) as.numeric(runs) else numeric()
  run_end <- run_start + attr(runs, "match.length") - 1
  # The last byte before p that is not blank, or 0.
  before <- function(p) {
    r <- find(p - 1, run_start)
    if (r > 0L && run_end[r] >= p - 1) run_start[r] - 1 else p - 1
  }
  # Where the run of bytes that are not blank holding q begins, at line
  # start `from` at the earliest.
  word_start <- function(q, from = 1) {
    r <- find(q, run_start)
    max(if (r > 0L) run_end[r] + 1 else 1, from)
  }
  # In flow context a word also ends at [, { and a comma.
  flow_marks <- sort(c(run_end, as.numeric(which(bytes %in% as.raw(c(0x5b, 0x7b, 0x2c, 0x5d, 0x7d))))))
  flow_word_start <- function(q) {
    k <- find(q - 1, flow_marks)
    if (k > 0L) flow_marks[k] + 1 else 1
  }

  events <- as.numeric(which(bytes %in% as.raw(c(0x22, 0x27, 0x5b, 0x5d, 0x7b, 0x7d, 0x23, 0x7c, 0x3e))))
  doubles <- as.numeric(which(bytes == as.raw(0x22)))
  singles <- as.numeric(which(bytes == as.raw(0x27)))
  string <- '"(?:[^"\\\\]++|\\\\.)*+"'
  simple <- grepl(
    paste0(
      "^[ \t]*(?:-[ \t]+)*(?:(?:[A-Za-z0-9_.$@/-]+|", string, "):[ \t]+)?(?:", string,
      "|\\[\\]|\\{\\})[ \t\r]*$"
    ),
    lines$text, perl = TRUE, useBytes = TRUE
  )
  skip_line <- simple | lines$directive
  # For each event, the first event at it or after it on a line that is not
  # skipped in block context.
  kept <- as.numeric(which(!skip_line[line_of(events)]))
  next_kept <- kept[find(seq_along(events) - 1, kept) + 1L]
  # The last line of content before each line.
  content <- !lines$blank & !lines$comment & !lines$directive
  prev_content <- c(0L, cummax(ifelse(content, seq_len(n_lines), 0L)))[seq_len(n_lines)]
  comment_at <- rep(NA_real_, n_lines)
  # Whether a token or a skipped value ends on each line.
  ended <- simple
  in_block_scalar <- logical(n_lines)
  # What each line's value is, worked out once, in `memo`: kind 1 a plain
  # scalar, 2 empty (a value to come on the lines below), 3 anything else, 4
  # plain text that goes on with a scalar from above; `column` the column of
  # the collection holding the value; `holder`, for kind 4, that of the
  # scalar it goes on with.
  memo <- new.env(parent = emptyenv())
  memo$kind <- rep(NA_integer_, n_lines)
  memo$column <- rep(NA_real_, n_lines)
  memo$holder <- rep(NA_real_, n_lines)
  # The end of the quoted scalar opened at p; NA when it is never closed.
  quote_end <- function(p) {
    double <- byte(p) == 0x22
    marks <- if (double) doubles else singles
    q <- p
    repeat {
      q <- marks[find(q, marks) + 1L]
      if (is.na(q)) {
        return(NA_real_)
      }
      if (double) {
        # Escaped when an odd number of backslashes come before it.
        k <- q - 1
        while (k > p && byte(k) == 0x5c) k <- k - 1
        if ((q - 1 - k) %% 2 == 0) {
          return(q)
        }
      } else if (q < n && byte(q + 1) == 0x27) {
        q <- q + 1
      } else {
        return(q)
      }
    }
  }
  # The last significant byte before p, past blanks, line breaks and
  # comments; 0 when there is none.
  prev_sig <- function(p) {
    repeat {
      q <- before(p)
      if (q < 1) {
        return(0)
      }
      at <- comment_at[line_of(q)]
      if (is.na(at) || at > q) {
        return(q)
      }
      p <- at
    }
  }
  # Whether, in flow context, a node can start right after the token that
  # ends at q, which `last` (the end of the last quoted scalar or
  # collection) may be.
  flow_starts_after <- function(q, p, last) {
    repeat {
      if (q == 0) {
        return(TRUE)
      }
      b <- byte(q)
      if (b %in% c(0x5b, 0x7b, 0x2c)) {
        return(TRUE)
      }
      s <- flow_word_start(q)
      if (b == 0x3f) {
        return(s == q)
      }
      if (b == 0x3a) {
        # A colon followed by a blank ends the plain word before it. Glued
        # to what follows, it is an indicator only where it begins a token
        # or follows a quoted key or a collection.
        if (q + 1 < p || s == q) {
          return(TRUE)
        }
        r <- prev_sig(q)
        return(r > 0 && (r == last || byte(r) %in% c(0x5d, 0x7d)))
      }
      # A whole anchor or tag, followed by a blank, where a node starts.
      if (!(byte(s) %in% c(0x26, 0x21)) || q + 1 >= p) {
        return(FALSE)
      }
      p <- s
      q <- prev_sig(s)
    }
  }
  # Works out what line k's value is (`memo`).
  line_value <- function(k) {
    x <- sub("[ \t\r]+$", "", sub("(^|[ \t])#.*$", "", lines$text[k], useBytes = TRUE), useBytes = TRUE)
    lead <- attr(regexpr("^[ \t]*(?:[-?][ \t]+)*", x, useBytes = TRUE), "match.length")
    value_start <- "^[\"'\\[{|>&!*]"
    kind <- 3L
    column <- lead
    if (grepl("^---|^\\.\\.\\.", x, useBytes = TRUE)) {
      kind <- 3L
    } else if (grepl("(^|[ \t])[-?]$", x, useBytes = TRUE)) {
      kind <- 2L
      column <- nchar(x, type = "bytes") - 1L
    } else if (grepl(":$", x, useBytes = TRUE)) {
      kind <- 2L
    } else {
      m <- regmatches(x, regexec("^[ \t]*(?:[-?][ \t]+)*[^ \t#].*?:[ \t]+(.*)$", x, useBytes = TRUE))[[1]]
      if (length(m) > 0L) {
        kind <- if (grepl(value_start, m[2], useBytes = TRUE)) 3L else 1L
      } else if (lead > 0L && grepl("[-?][ \t]+$", substr(x, 1L, lead), useBytes = TRUE)) {
        rest <- substring(x, lead + 1L)
        kind <- if (grepl(value_start, rest, useBytes = TRUE)) 3L else 1L
        column <- lead - 2L
      } else {
        kind <- if (grepl("^[ \t]*[\"'\\[{|>&!*]", x, useBytes = TRUE)) 3L else 4L
      }
    }
    memo$kind[k] <- kind
    memo$column[k] <- column
  }
  kind_of <- function(k) {
    if (is.na(memo$kind[k])) line_value(k)
    memo$kind[k]
  }
  # The column of the collection holding the plain scalar that line k, of
  # kind 4, goes on with: found by walking up the lines it continues, once,
  # then set on each of them; -1 when no collection holds it.
  holder_of <- function(k) {
    j <- k
    repeat {
      if (!is.na(memo$holder[j])) {
        value <- memo$holder[j]
        break
      }
      up <- prev_content[j]
      if (up == 0L || ended[up]) {
        value <- -1
        break
      }
      kind <- kind_of(up)
      if (kind == 4L) {
        j <- up
        next
      }
      value <- if (kind %in% c(1L, 2L)) memo$column[up] else -1
      break
    }
    j <- k
    while (is.na(memo$holder[j]) && kind_of(j) == 4L) {
      memo$holder[j] <- value
      up <- prev_content[j]
      if (up == 0L || ended[up]) break
      j <- up
    }
    value
  }
  # Whether a token after only indentation, indicators, anchors and tags on
  # line l starts a node, rather than going on with a plain scalar.
  starts_line <- function(l) {
    k <- prev_content[l]
    if (k == 0L || ended[k]) {
      return(TRUE)
    }
    kind <- kind_of(k)
    if (kind %in% c(2L, 3L)) {
      return(TRUE)
    }
    column <- if (kind == 1L) memo$column[k] else holder_of(k)
    lines$indent[l] <= column
  }
  # How the token at p, in block context, stands on its line: "key" after
  # "key: ", "line" after only indentation, indicators, anchors and tags,
  # "document" after a `---` marker, "plain" otherwise. Also the column of
  # the collection a block scalar there would be held by.
  block_place <- function(p, l) {
    from <- lines$start[l]
    q <- before(p)
    column <- NA_real_
    repeat {
      if (q < from) {
        return(list(place = "line", column = column))
      }
      s <- word_start(q, from)
      b <- byte(q)
      if (s == from && q == from + 2 && all(bytes[from:q] == as.raw(0x2d))) {
        return(list(place = "document", column = -1))
      }
      if (b == 0x3a && q + 1 < p) {
        # A colon followed by a blank. After a key it starts the key's value;
        # alone, it is the indicator of an explicit value.
        if (s < q || before(s) >= from) {
          key <- regexpr("^[ \t]*(?:[-?][ \t]+)*", lines$text[l], useBytes = TRUE)
          return(list(place = "key", column = attr(key, "match.length")))
        }
      } else if (!(s == q && b %in% c(0x2d, 0x3f, 0x3a)) && !(byte(s) %in% c(0x26, 0x21))) {
        return(list(place = "plain", column = NA))
      } else if (q + 1 >= p) {
        return(list(place = "plain", column = NA))
      }
      if (s == q && b %in% c(0x2d, 0x3f) && is.na(column)) column <- s - from
      p <- s
      q <- before(s)
    }
  }

  depth <- 0L
  last <- 0
  i <- 1L
  while (i <= length(events)) {
    if (depth == 0L) {
      i <- next_kept[i]
      if (is.na(i)) break
    }
    p <- events[i]
    b <- byte(p)
    skip <- NA_real_
    if (b == 0x23) {
      if (p == 1 || is_blank(p - 1)) {
        l <- line_of(p)
        comment_at[l] <- p
        skip <- lines$end[l]
      }
    } else if (depth > 0L) {
      if (b == 0x5b || b == 0x7b) {
        depth <- depth + 1L
        if (depth > max) {
          return(list(deep = TRUE, in_block_scalar = in_block_scalar))
        }
        last <- p
      } else if (b == 0x5d || b == 0x7d) {
        depth <- depth - 1L
        last <- p
        if (depth == 0L) ended[line_of(p)] <- TRUE
      } else if ((b == 0x22 || b == 0x27) && flow_starts_after(prev_sig(p), p, last)) {
        skip <- quote_end(p)
        if (is.na(skip)) break
        last <- skip
      }
    } else if (!(b == 0x5d || b == 0x7d)) {
      l <- line_of(p)
      at <- block_place(p, l)
      start <- at$place %in% c("key", "document") || (at$place == "line" && starts_line(l))
      if (start) {
        if (b == 0x5b || b == 0x7b) {
          depth <- 1L
          last <- p
        } else if (b == 0x22 || b == 0x27) {
          skip <- quote_end(p)
          if (is.na(skip)) break
          last <- skip
          ended[line_of(skip)] <- TRUE
        } else {
          # A block scalar: the lines below indented more than the
          # collection that holds it, and the blank lines among them.
          column <- at$column
          if (is.na(column)) {
            k <- prev_content[l]
            column <- if (k == 0L) -1 else if (kind_of(k) == 2L) memo$column[k] else lines$indent[k]
          }
          k <- l + 1L
          while (k <= n_lines && (lines$blank[k] || lines$indent[k] > column)) k <- k + 1L
          if (k > l + 1L) in_block_scalar[(l + 1L):(k - 1L)] <- TRUE
          skip <- if (k <= n_lines) lines$start[k] - 1 else n
          ended[line_of(skip)] <- TRUE
          last <- skip
        }
      }
    }
    i <- if (is.na(skip)) i + 1L else find(skip, events) + 1L
  }
  list(deep = FALSE, in_block_scalar = in_block_scalar)
}

# The deepest nesting of YAML text written as JSON is: double-quoted strings,
# each where a node starts, and no single quote or # outside them. NA for any
# other text. The strings are found as json_parse_strict() finds them, after
# the escapes, and each must follow [, {, a comma or a colon that is an
# indicator, so that a quote libyaml reads as plain text is never taken for
# one.
yaml_json_depth <- function(txt) {
  if (!grepl("^[ \t\r\n]*[\\[{]", txt, perl = TRUE, useBytes = TRUE)) {
    return(NA_integer_)
  }
  bare <- gsub("\\\\.", "", txt, perl = TRUE, useBytes = TRUE)
  strings <- gregexpr('"[^"]*+"', bare, perl = TRUE, useBytes = TRUE)[[1]]
  bytes <- charToRaw(bare)
  outside <- rep(TRUE, length(bytes))
  if (strings[1L] > 0L) {
    first <- as.integer(strings)
    last <- first + attr(strings, "match.length") - 1L
    inside <- integer(length(bytes) + 1L)
    inside[first] <- 1L
    inside[last + 1L] <- inside[last + 1L] - 1L
    outside <- cumsum(inside[seq_along(bytes)]) == 0L
    # The byte before each string other than a blank.
    solid <- which(!bytes %in% as.raw(c(0x20, 0x09, 0x0d, 0x0a)))
    at <- findInterval(first - 1L, solid, checkSorted = FALSE, checkNA = FALSE)
    before <- ifelse(at > 0L, solid[pmax(at, 1L)], 0L)
    ok <- before == 0L | bytes[pmax(before, 1L)] %in% as.raw(c(0x5b, 0x7b, 0x2c, 0x3a))
    # A colon glued to the string is an indicator only after a quoted key or
    # a collection.
    glued <- before > 0L & before == first - 1L & bytes[pmax(before, 1L)] == as.raw(0x3a)
    if (any(glued)) {
      key_at <- findInterval(before[glued] - 1L, solid, checkSorted = FALSE, checkNA = FALSE)
      key <- ifelse(key_at > 0L, solid[pmax(key_at, 1L)], 0L)
      ok[glued] <- key > 0L & (key %in% last | bytes[pmax(key, 1L)] %in% as.raw(c(0x5d, 0x7d)))
    }
    if (!all(ok)) {
      return(NA_integer_)
    }
  }
  rest <- bytes[outside]
  if (any(rest %in% as.raw(c(0x22, 0x27, 0x23)))) {
    return(NA_integer_)
  }
  step <- ifelse(rest %in% as.raw(c(0x5b, 0x7b)), 1L, ifelse(rest %in% as.raw(c(0x5d, 0x7d)), -1L, 0L))
  step <- step[step != 0L]
  if (length(step) == 0L) 0L else max(cumsum(step))
}
