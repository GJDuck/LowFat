CXX=../build/bin/clang++
CXXFLAGS_0=-std=c++11 -O2 \
    -I ../llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/ \
    -I ../config/ -mllvm -lowfat-no-abort -mllvm -lowfat-debug \
    -mllvm -lowfat-check-whole-access
CXXFLAGS=-fsanitize=lowfat $(CXXFLAGS_0)

Test: Test.cpp
	$(CXX) $(CXXFLAGS_0) -c TestUninstrumented.cpp
	$(CXX) $(CXXFLAGS) -c TestSupport.cpp
	$(CXX) $(CXXFLAGS) -c Test.cpp
	$(CXX) $(CXXFLAGS) Test.o TestSupport.o TestUninstrumented.o -o Test

clean:
	rm -rf Test a.out *.ll

