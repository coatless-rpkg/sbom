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
# system mocks them itself. The real wrappers are kept for the tests that
# mock the commands below them.
sys_linked_libraries_real <- sys_linked_libraries
sys_os_package_real <- sys_os_package
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

# Nor does any test download OSV's advisory data or look up an advisory: the
# download fails and every lookup finds nothing. A test that wants either
# mocks osv_download() or osv_lookup() itself.
osv_download_real <- osv_download
osv_lookup_real <- osv_lookup
local_mocked_bindings(
  osv_download = function(url, dest, ...) structure(FALSE, reason = "not run in tests"),
  osv_lookup = function(id, ...) NULL,
  .package = "sbom", .env = testthat::teardown_env()
)
