export ELK_TOP=$(pwd)

export ELK_LLVM_TOP=$ELK_TOP/llvm-project-15
export ELK_LLVM_BUILD=$ELK_LLVM_TOP/build
export ELK_C=$ELK_LLVM_BUILD/bin/clang

cd $ELK_LLVM_TOP
cmake -S llvm -B build -G Ninja -DLLVM_ENABLE_PROJECTS="clang" -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD="ARM" -DBUILD_SHARED_LIBS=ON -DCLANG_ENABLE_OPAQUE_POINTERS=OFF
cmake --build ./build -j20