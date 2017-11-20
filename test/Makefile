CXX=../build/bin/clang++
CXXFLAGS=-std=c++11 -fsanitize=lowfat -O2 \
    -I ../llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/ \
    -I ../config/ -mllvm -lowfat-no-abort -mllvm -lowfat-debug \
    -mllvm -lowfat-check-whole-access

Test: Test.cpp
	$(CXX) $(CXXFLAGS) -c TestSupport.cpp
	$(CXX) $(CXXFLAGS) -c Test.cpp
	$(CXX) $(CXXFLAGS) Test.o TestSupport.o -o Test

clean:
	rm -rf Test a.out *.ll

