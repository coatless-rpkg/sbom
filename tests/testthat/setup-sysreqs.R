# The real file reader, kept for the one test that calls it (it reads a file, not a command).
sys_os_release_real <- sys_os_release

# The real pak functions, kept for the tests that call them.
sysreqs_match_real <- sysreqs_match
pak_function_real <- pak_function

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
  .package = "sbom", .env = testthat::teardown_env()
)
