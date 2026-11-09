# The git commit of a project folder, read from the files in .git without
# running git.

# The commit checked out in the git repository that holds `dir`, read from
# the files in the nearest .git in `dir` or a folder above it, stopping
# before the home folder, or NA. Git itself is never run.
# - HEAD holds a commit (a detached HEAD) or names a branch ref, whose commit
#   is in a loose ref file or else in packed-refs. A ref that names another
#   ref is not followed.
# - .git may be a file naming the git directory, as in a worktree, where
#   `commondir` names the directory that holds the shared refs.
git_commit <- function(dir) {
  tryCatch(
    read_git_commit(dir),
    error = function(e) NA_character_,
    warning = function(w) NA_character_
  )
}

# The commit id of HEAD in the repository holding `dir`; NA when there is no
# repository or HEAD does not resolve.
read_git_commit <- function(dir) {
  top <- git_root(dir)
  gitdir <- if (is.na(top)) NA_character_ else git_dir(top)
  head <- if (is.na(gitdir)) NA_character_ else first_line(file.path(gitdir, "HEAD"))
  sha <- if (!is.na(head) && startsWith(head, "ref:")) {
    git_ref(gitdir, trimws(sub("^ref:", "", head)))
  } else {
    head
  }
  if (is_sha(sha)) sha else NA_character_
}

# The nearest folder, `dir` or one above it, that holds a .git (a folder or,
# in a worktree, a file), or NA at the home folder or the filesystem root
# without one. The home folder's own .git is not looked at.
git_root <- function(dir) {
  d <- normalizePath(dir, winslash = "/", mustWork = FALSE)
  home <- home_folder()
  windows <- .Platform$OS.type == "windows"
  same <- function(a, b) if (windows) identical(tolower(a), tolower(b)) else identical(a, b)
  repeat {
    # A repository at the home folder is a dotfiles repository, not the
    # project's.
    if (same(d, home)) {
      return(NA_character_)
    }
    if (file.exists(file.path(d, ".git"))) {
      return(d)
    }
    parent <- dirname(d)
    if (identical(parent, d)) {
      return(NA_character_)
    }
    d <- parent
  }
}

# The home folder as git finds it: HOME when it is set, also on Windows,
# where R's "~" is the Documents folder; else USERPROFILE on Windows; else "~".
home_folder <- function() {
  home <- Sys.getenv("HOME")
  if (!nzchar(home) && .Platform$OS.type == "windows") {
    home <- Sys.getenv("USERPROFILE")
  }
  if (!nzchar(home)) {
    home <- path.expand("~")
  }
  normalizePath(home, winslash = "/", mustWork = FALSE)
}

# The git directory of the folder `dir`: its .git folder, or the one a .git
# file points to; NA when there is neither.
git_dir <- function(dir) {
  dotgit <- file.path(dir, ".git")
  if (dir.exists(dotgit)) {
    return(dotgit)
  }
  line <- first_line(dotgit)
  if (is.na(line) || !startsWith(line, "gitdir:")) {
    return(NA_character_)
  }
  target <- relative_to(dir, trimws(sub("^gitdir:", "", line)))
  if (dir.exists(target)) target else NA_character_
}

# The commit of `ref`, from the git directory or else the shared one: a loose
# ref file wins over packed-refs, as in git.
git_ref <- function(gitdir, ref) {
  parts <- strsplit(ref, "/", fixed = TRUE)[[1L]]
  if (!startsWith(ref, "refs/") || any(parts %in% c("", ".", ".."))) {
    return(NA_character_)
  }
  common <- first_line(file.path(gitdir, "commondir"))
  dirs <- unique(c(gitdir, if (!is.na(common)) relative_to(gitdir, common)))
  for (d in dirs) {
    loose <- file.path(d, ref)
    if (file.exists(loose) && !dir.exists(loose)) {
      return(first_line(loose))
    }
  }
  for (d in dirs) {
    packed <- file.path(d, "packed-refs")
    if (!file.exists(packed) || dir.exists(packed)) {
      next
    }
    lines <- trimws(readLines(packed, warn = FALSE))
    hit <- regmatches(lines, regexec("^([0-9a-f]{40}) (.+)$", lines))
    for (h in hit) {
      if (length(h) == 3L && identical(h[[3L]], ref)) {
        return(h[[2L]])
      }
    }
  }
  NA_character_
}

# The first line of a file, trimmed, or NA when there is none.
first_line <- function(file) {
  if (!file.exists(file) || dir.exists(file)) {
    return(NA_character_)
  }
  line <- readLines(file, n = 1L, warn = FALSE)
  if (length(line) == 0L) NA_character_ else trimws(line)
}

# `path` as given when it is absolute, else `path` under `dir`.
relative_to <- function(dir, path) {
  if (grepl("^(/|[A-Za-z]:[/\\\\]|\\\\\\\\)", path)) path else file.path(dir, path)
}

# Whether `x` is one full, lowercase 40-digit hexadecimal commit id.
is_sha <- function(x) {
  length(x) == 1L && !is.na(x) && grepl("^[0-9a-f]{40}$", x)
}
