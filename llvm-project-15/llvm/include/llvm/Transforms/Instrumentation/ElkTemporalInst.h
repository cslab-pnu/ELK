#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_ELKTEMPORALINST_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_ELKTEMPORALINST_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;
class Pass;

/// A pass to instrument code and perform run-time bounds checking on loads,
/// stores, and other memory intrinsics.
struct ElkTemporalInstPass : PassInfoMixin<ElkTemporalInstPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};


/// Legacy pass creation function for the above pass.
Pass *createElkTemporalInstLegacyPass();

} // end namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_ELKTEMPORALINST_H
