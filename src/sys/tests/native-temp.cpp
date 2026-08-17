#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>

int main() {
	assert(unsetenv("TMPDIR") == 0);
	assert(unsetenv("TMP") == 0);
	assert(unsetenv("TEMP") == 0);
	assert(unsetenv("TEMPDIR") == 0);
	assert(std::filesystem::temp_directory_path() == "/user/tmp");

	assert(setenv("TMPDIR", "/devtools/tmp", 1) == 0);
	assert(std::filesystem::temp_directory_path() == "/devtools/tmp");

	std::cout << "native-temp-cpp PASS\n";
	return 0;
}
