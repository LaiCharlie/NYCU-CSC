all: hijack

hijack:
	cmake -S all -B build -D CMAKE_CXX_COMPILER=/usr/bin/g++-10
	cmake --build build --config Release --target hijack
	mv bin/hijack hijack