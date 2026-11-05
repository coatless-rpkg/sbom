# The real file reader, kept for the one test that calls it (it reads a file, not a command).
sys_os_release_real <- sys_os_release

# The real pak functions, kept for the tests that call them.
sysreqs_match_real <- sysreqs_match
pak_function_real <- pak_function
sys_ui_dependencies_real <- sys_ui_dependencies

# No test reaches pak: to every test, pak is not installed. A test that wants
# a mapping mocks sysreqs_match() or another wrapper itself.
local_mocked_bindings(
  pak_function = function(name) NULL,
  .package = "sbom", .env = testthat::teardown_env()
)

# Nor does any test run otool, ldd, xcode-select, dpkg or rpm, or read
# /etc/os-release, and every test sees Linux, whatever runs it. A test that
# wants linked libraries, an operating system package, a release or another
# system mocks them itself.
local_mocked_bindings(
  sys_linked_libraries = function(so_file) structure(character(), versions = character(), tool_missing = FALSE),
  sys_otool_rpaths = function(so_file) character(),
  sys_os_package = function(path) NULL,
  sys_os_release = function() NULL,
  sys_os_name = function() "Linux",
  sys_xcode_tools = function() TRUE,
  sys_ui_dependencies = function(dir, layout, ...) structure(list(), reason = "not run in tests"),
  .package = "sbom", .env = testthat::teardown_env()
)

# Nor is Nix ever found: no test sees nix-instantiate or nix-store.
sys_nix_available_real <- sys_nix_available
sys_nix_instantiate_real <- sys_nix_instantiate
sys_nix_query_real <- sys_nix_query
nix_store_exists_real <- nix_store_exists
nix_store_description_real <- nix_store_description
local_mocked_bindings(
  sys_nix_available = function() FALSE,
  sys_nix_instantiate = function(file) NULL,
  sys_nix_query = function(args) NULL,
  nix_store_exists = function(paths) rep(FALSE, length(paths)),
  nix_store_description = function(out, pkg) NULL,
  .package = "sbom", .env = testthat::teardown_env()
)

# Nor does any test reach the network: the one wrapper that can read a CRAN
# PACKAGES file from a URL fails for every test. A test that wants a snapshot
# mocks read_packages_file() itself.
read_packages_file_real <- read_packages_file
local_mocked_bindings(
  read_packages_file = function(location, ...) structure(list(), reason = "not run in tests"),
  .package = "sbom", .env = testthat::teardown_env()
)
