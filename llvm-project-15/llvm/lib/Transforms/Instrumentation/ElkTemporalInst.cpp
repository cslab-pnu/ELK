/*
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */
#include "llvm/Transforms/Instrumentation/ElkTemporalInst.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsARM.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"

#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include <assert.h>
#include <stdio.h>

using namespace llvm;

Function *__TranslationOnly;
Function *__CheckAndTranslation;
Function *__RestoreOnly;
Type *Int8Ty;
Type *VoidType;
Type *VoidPtrTy;
std::set<std::string> optimized;

static Value *CheckandTranslationPointer(IRBuilder<> &Builder, Value *Ptr) {
  Value *V = Builder.CreateBitCast(Ptr, VoidPtrTy);
  V = Builder.CreateCall(__CheckAndTranslation, {V});
  Value *ii = Builder.CreateBitCast(V, Ptr->getType());
  return ii;
}

static Value *TranslationPointer(IRBuilder<> &Builder, Value *Ptr) {
  Value *V = Builder.CreateBitCast(Ptr, VoidPtrTy);
  V = Builder.CreateCall(__TranslationOnly, {V});
  Value *ii = Builder.CreateBitCast(V, Ptr->getType());
  return ii;
}

static Value *RestorePointer(IRBuilder<> &Builder, Value *Ptr) {
  Value *V = Builder.CreateBitCast(Ptr, VoidPtrTy);
  V = Builder.CreateCall(__RestoreOnly, {V});
  Value *ii = Builder.CreateBitCast(V, Ptr->getType());
  return ii;
}

bool isPeripheralAddr(Value *Ptr) {
  ConstantExpr *CE = dyn_cast<ConstantExpr>(Ptr);
  if (!CE || CE->getOpcode() != Instruction::IntToPtr)
    return false;

  auto *CInt = dyn_cast<ConstantInt>(CE->getOperand(0));
  if (!CInt)
    return false;

  uint64_t addr = CInt->getZExtValue();
  /* 0x4000_0000 – 0x5FFF_FFFF : AHB/APB MMIO
     0xE000_0000 – 0xE00F_FFFF : PPB(System control space) */
  return (addr >= 0x40000000ULL && addr < 0x60000000ULL) ||
         (addr >= 0xE0000000ULL && addr < 0xE0100000ULL);
}

bool isCodePointer(Value *V) {
  V = V->stripPointerCasts();

  if (isa<Function>(V) || isa<BlockAddress>(V))
    return true;

  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    if (CE->getOpcode() == Instruction::IntToPtr) {
      if (auto *CI = dyn_cast<ConstantInt>(CE->getOperand(0))) {
        uint64_t a = CI->getZExtValue();
        /* STM32F4: 0x0800_0000‑0x080F_FFFF Flash,
           0x0000_0000 alias, 0x1FFF_0000 SysMem */
        return (a >= 0x08000000ULL && a < 0x08100000ULL) ||
               (a < 0x00200000ULL) || /* alias/boot */
               (a >= 0x1FFF0000ULL && a < 0x1FFF8000ULL);
      }
    }
  }
  return false;
}

static StringRef
analyzePointer(Instruction *I, Value *Ptr,
               std::map<Value *, std::set<Instruction *>> &mallocUsers,
               std::map<Value *, int> &isPointerNotFree) {
  Value *Underlying = getUnderlyingObject(Ptr, 50);

  if (auto *callInst = dyn_cast<CallInst>(Underlying)) {
    Function *CalledFunc = callInst->getCalledFunction();
    if (CalledFunc &&
        (CalledFunc->getName() == "malloc" ||
         CalledFunc->getName() == "calloc" ||
         CalledFunc->getName() == "realloc" ||
         CalledFunc->getName() == "__wrap_malloc" ||
         CalledFunc->getName() == "__wrap_calloc" ||
         CalledFunc->getName() == "__wrap_realloc") &&
        (isPointerNotFree[Underlying] == 1 || isPointerNotFree[Ptr] == 1)) {
      return "FastPath";
    }
  }

  if (isa<AllocaInst>(Underlying) || isa<GlobalVariable>(Underlying) ||
      isa<AllocaInst>(Ptr) || isa<GlobalVariable>(Ptr)) {
    return "Exclude";
  }

  if (isPeripheralAddr(Ptr) || isCodePointer(Ptr))
    return "Exclude";

  Value *targetValue = nullptr;
  for (const auto &[key, value] : mallocUsers) {
    for (auto i : value) {
      if (i == I && (Ptr == key || Underlying == key))
        targetValue = key;
    }
  }
  if (targetValue == nullptr)
    return "SlowPath";
  if (isPointerNotFree[targetValue] == 1)
    return "FastPath";

  return "SlowPath";
}

static void
applyTranslation(Function &F, Instruction *I, const TargetLibraryInfo &TLI,
                 std::map<Value *, std::set<Instruction *>> &mallocUsers,
                 std::map<Value *, int> &isPointerNotFree) {
  IRBuilder<> Builder(I);
  if (auto *storeInst = dyn_cast<StoreInst>(I)) {
    Value *Ptr = storeInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Ptr, mallocUsers, isPointerNotFree);
    Value *TransformedPtr = nullptr;

    if (Path == "FastPath") {
      TransformedPtr = TranslationPointer(Builder, Ptr);
    } else if (Path == "SlowPath") {
      TransformedPtr = CheckandTranslationPointer(Builder, Ptr);
    }

    if (TransformedPtr) {
      Value *CorrectedPtr =
          Builder.CreateBitCast(TransformedPtr, Ptr->getType());
      storeInst->setOperand(1, CorrectedPtr);
    }
  } else if (auto *loadInst = dyn_cast<LoadInst>(I)) {
    Value *Ptr = loadInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Ptr, mallocUsers, isPointerNotFree);
    if (Path == "Exclude") {
      return;
    }
    if (Path == "FastPath") {
      loadInst->setOperand(0, TranslationPointer(Builder, Ptr));
    } else if (Path == "SlowPath") {
      loadInst->setOperand(0, CheckandTranslationPointer(Builder, Ptr));
    }
  } else if (auto *memSetInst = dyn_cast<MemSetInst>(I)) {
    Value *Dst = memSetInst->getRawDest();
    if (!Dst->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Dst, mallocUsers, isPointerNotFree);
    if (Path == "Exclude") {
      return;
    }
    Value *TranslatedDst = (Path == "FastPath")
                               ? TranslationPointer(Builder, Dst)
                               : CheckandTranslationPointer(Builder, Dst);

    // New MemSet instruction
    Value *Length = memSetInst->getLength();
    Value *Value = memSetInst->getValue();
    Align Alignment = *memSetInst->getDestAlign();
    auto *NewMemSet =
        Builder.CreateMemSet(TranslatedDst, Value, Length, Alignment);
    memSetInst->replaceAllUsesWith(NewMemSet);
    memSetInst->eraseFromParent();
  } else if (auto *memTransferInst = dyn_cast<MemTransferInst>(I)) {
    Value *Src = memTransferInst->getRawSource();
    Value *Dst = memTransferInst->getRawDest();

    if (!Src->getType()->isPointerTy() || !Dst->getType()->isPointerTy()) {
      // errs() << "Error: MemTransferInst Src or Dst is not a pointer type!\n";
      return;
    }

    StringRef SrcPath = analyzePointer(I, Src, mallocUsers, isPointerNotFree);
    StringRef DstPath = analyzePointer(I, Dst, mallocUsers, isPointerNotFree);

    if (SrcPath == "Exclude" && DstPath == "Exclude") {
      errs() << "Skipping Translation for MemTransfer: Both Src and Dst are "
                "Exclude\n";
      return;
    }

    Value *TranslatedSrc = (SrcPath == "FastPath")
                               ? TranslationPointer(Builder, Src)
                               : CheckandTranslationPointer(Builder, Src);
    Value *TranslatedDst = (DstPath == "FastPath")
                               ? TranslationPointer(Builder, Dst)
                               : CheckandTranslationPointer(Builder, Dst);

    Value *Length = memTransferInst->getLength();
    Align SrcAlign = *memTransferInst->getSourceAlign();
    Align DstAlign = *memTransferInst->getDestAlign();
    bool IsVolatile = memTransferInst->isVolatile();

    auto *NewMemTransfer = Builder.CreateMemCpy(
        TranslatedDst, DstAlign, TranslatedSrc, SrcAlign, Length, IsVolatile);

    memTransferInst->replaceAllUsesWith(NewMemTransfer);
    memTransferInst->eraseFromParent();
  }

  else if (auto *callInst = dyn_cast<CallInst>(I)) {
    Function *calledFunction = callInst->getCalledFunction();
    if (calledFunction) {
      if (calledFunction->getName() == "malloc" ||
          calledFunction->getName() == "__wrap_malloc" ||
          calledFunction->getName() == "calloc" ||
          calledFunction->getName() == "__wrap_calloc" ||
          calledFunction->getName() == "realloc" ||
          calledFunction->getName() == "__wrap_realloc") {
        Value *ptr = callInst;
        isPointerNotFree[ptr] = 1;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "__wrap_free") {
        Value *ptr = callInst->getArgOperand(0);
        isPointerNotFree[ptr] = 0;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "realloc")
        return;
      if (calledFunction->getName() == "check_and_translation" ||
          calledFunction->getName() == "translation_only")
        return;
      LibFunc libFunc;
      // if (!TLI.getLibFunc(*calledFunction, libFunc) &&
      // optimized.count(calledFunction->getName().str()) > 0) {
      if (!TLI.getLibFunc(*calledFunction, libFunc)) {
        return;
      }
      if (optimized.count(calledFunction->getName().str()) > 0 &&
          !calledFunction->getName().contains("memchr"))
        return;
      for (unsigned i = 0; i < callInst->arg_size(); ++i) {
        Value *Arg = callInst->getArgOperand(i);
        if (!Arg->getType()->isPointerTy()) {
          continue;
        }

        StringRef Path = analyzePointer(I, Arg, mallocUsers, isPointerNotFree);
        if (Path == "Exclude") {
          continue;
        }
        Value *TranslatedArg = (Path == "FastPath")
                                   ? TranslationPointer(Builder, Arg)
                                   : CheckandTranslationPointer(Builder, Arg);
        callInst->setArgOperand(i, TranslatedArg);
      }
    }
  } else if (auto *invokeInst = dyn_cast<InvokeInst>(I)) {
    Function *calledFunction = invokeInst->getCalledFunction();
    if (calledFunction) {
      if (calledFunction->getName() == "malloc" ||
          calledFunction->getName() == "__wrap_malloc" ||
          calledFunction->getName() == "calloc" ||
          calledFunction->getName() == "__wrap_calloc" ||
          calledFunction->getName() == "realloc" ||
          calledFunction->getName() == "__wrap_realloc") {
        Value *ptr = invokeInst;
        isPointerNotFree[ptr] = 1;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "__wrap_free") {
        Value *ptr = invokeInst->getArgOperand(0);
        isPointerNotFree[ptr] = 0;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "realloc")
        return;
      if (calledFunction->getName() == "check_and_translation" ||
          calledFunction->getName() == "translation_only")
        return;
      LibFunc libFunc;
      if (!TLI.getLibFunc(*calledFunction, libFunc)) {
        return;
      }
      for (unsigned i = 0; i < invokeInst->arg_size(); ++i) {
        Value *Arg = invokeInst->getArgOperand(i);

        if (!Arg->getType()->isPointerTy()) {
          continue;
        }

        StringRef Path = analyzePointer(I, Arg, mallocUsers, isPointerNotFree);
        if (Path == "Exclude") {
          continue;
        }

        Value *TranslatedArg = (Path == "FastPath")
                                   ? TranslationPointer(Builder, Arg)
                                   : CheckandTranslationPointer(Builder, Arg);
        invokeInst->setArgOperand(i, TranslatedArg);
      }
    }
  }
  /* for wasm (wasm_runtime_exec_env_check) */
  // else if (auto icmpInst = dyn_cast<ICmpInst>(I)) {
  //       Value *lhs = icmpInst->getOperand(0);
  //       Value *rhs = icmpInst->getOperand(1);
  //       bool isLhsPointer = lhs->getType()->isPointerTy();
  //       bool isRhsPointer = rhs->getType()->isPointerTy();
  //       if (isLhsPointer && isRhsPointer) {
  //         icmpInst->setOperand(0, CheckandTranslationPointer(Builder, lhs));
  //         icmpInst->setOperand(1, CheckandTranslationPointer(Builder, rhs));
  //       }
  // }
}

void findAllUsers(Value *V, std::set<Instruction *> &Result,
                  std::set<Value *> &Visited) {
  if (Visited.find(V) != Visited.end())
    return;
  Visited.insert(V);
  for (User *U : V->users()) {
    if (Instruction *Inst = dyn_cast<Instruction>(U)) {
      Result.insert(Inst);
      findAllUsers(Inst, Result, Visited);
    }
  }
}

std::unordered_set<std::string> FunctionNofreeList = {};
std::unordered_set<std::string> FunctionCallList = {};

static bool isOptimizableTarget(const TargetLibraryInfo &TLI,
                                Function *Target) {
  errs() << Target->getName() << " Optimized...\n";
  if (!Target)
    return false;
  if (!Target->getName().data())
    return false;
  for (auto &BB : *Target) {
    for (auto &I : BB) {
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        // return false;
        if (CI->getCalledFunction() &&
            (CI->getCalledFunction()->getName().contains("free") ||
             CI->getCalledFunction()->getName().contains("malloc"))) {
          errs() << "free/malloc called! (No Optimized" << Target->getName()
                 << "\n";
          return false;
        }
        if (CI->getType()->isPointerTy() && CI->getCalledFunction() &&
            !CI->getCalledFunction()->getName().contains("mem") &&
            FunctionNofreeList.count(
                CI->getCalledFunction()->getName().str()) == 0) {
          // if (CI->getCalledFunction() &&
          // !CI->getCalledFunction()->getName().contains("mem")) {
          errs() << "ret pointer function!!" << CI->getName() << "\n";
          return false;
        }
        // if (CI->getCalledFunction() &&
        // (CI->getCalledFunction()->getName().contains("strcpy"))) return
        // false;
        if (!(CI->getCalledFunction()))
          continue;
      }
    }
  }
  return true;
}

bool isDoublePointer(Value *V) {
  Type *T = V->getType();
  if (!T->isPointerTy())
    return false;

  Type *inner = T->getPointerElementType();
  return inner->isPointerTy(); // T**
}

bool isUsedInGEP(Value *V) {
  for (User *U : V->users()) {
    if (isa<GetElementPtrInst>(U))
      return true;
  }
  return false;
}

bool isPointerToPointer(const Value *V) {
  const Type *T = V->getType();
  return T->isPointerTy() && T->getContainedType(0)->isPointerTy();
}

bool cameFromDoublePointer(Value *V) {
  Value *underlying = getUnderlyingObject(V, 20);

  if (PointerType *PTy = dyn_cast<PointerType>(underlying->getType())) {
    Type *ElemTy = PTy->getNonOpaquePointerElementType();
    if (ElemTy->isStructTy())
      return true;
    if (ElemTy->isPointerTy())
      return true;
  }
  Value *root = V->stripPointerCasts();
  if (auto *LI = dyn_cast<LoadInst>(root)) {
    Value *T = LI->getPointerOperand();
    if (isPointerToPointer(T))
      return true;
  }
  if (auto *LI = dyn_cast<LoadInst>(root)) {
    Value *gep = LI->getPointerOperand();
    if (auto *GEP = dyn_cast<GetElementPtrInst>(gep)) {
      Value *base = GEP->getPointerOperand();
      if (base->getType()->getPointerElementType()->isStructTy())
        return true;
    }
  }
  return false;
}

void replaceAllPointerArgsWithTranslation(Function &F) {
  if (F.isDeclaration())
    return;
  IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

  std::vector<Instruction *> InstsToProcess;
  for (auto &BB : F) {
    for (auto &I : BB) {
      InstsToProcess.push_back(&I);
    }
  }

  std::map<Value *, Value *> ReplacementMap;
  std::set<Instruction *> CreatedInsts;
  std::set<Instruction *> ChangesArg;

  for (auto &Arg : F.args()) {
    if (!Arg.getType()->isPointerTy())
      continue;

    Value *CastArg = Builder.CreateBitCast(&Arg, VoidPtrTy);
    if (Instruction *Inst = dyn_cast<Instruction>(CastArg))
      CreatedInsts.insert(Inst);

    Value *Call = Builder.CreateCall(__TranslationOnly, {CastArg});
    if (Instruction *Inst = dyn_cast<Instruction>(Call))
      CreatedInsts.insert(Inst);

    Value *Final = Builder.CreateBitCast(Call, Arg.getType());
    if (Instruction *Inst = dyn_cast<Instruction>(Final))
      CreatedInsts.insert(Inst);

    ReplacementMap[&Arg] = Final;
  }
  // 2. Replace all operand uses, skipping our own newly created instructions
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (CreatedInsts.count(&I))
        continue;
      if (isa<CallInst>(&I)) {
        // continue;
        CallInst *CI = dyn_cast<CallInst>(&I);
        if (CI->getCalledFunction() &&
            !CI->getCalledFunction()->getName().contains("__aeabi") &&
            !CI->getCalledFunction()->getName().contains("llvm"))
          continue;
      }
      for (unsigned i = 0; i < I.getNumOperands(); ++i) {
        Value *Op = I.getOperand(i);
        if (ReplacementMap.count(Op)) {
          I.setOperand(i, ReplacementMap[Op]);
          ChangesArg.insert(&I);
        }
      }
    }
  }

  for (auto &BB : F) {
    for (auto &I : BB) {
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        if (CI->getType()->isPointerTy()) {
        }
      }
    }
  }


  std::map<Value *, Value *> translatedOnce;
  std::set<Instruction *> createdInsts2;

  for (Instruction *I : InstsToProcess) {
    if (isa<PHINode>(I))
      continue;

    if (auto *memSetInst = dyn_cast<MemSetInst>(I)) {
      Value *Dst = memSetInst->getRawDest();
      if (!Dst->getType()->isPointerTy())
        continue;

      IRBuilder<> IRB(memSetInst);
      Value *casted = IRB.CreateBitCast(Dst, VoidPtrTy);
      Value *translated = IRB.CreateCall(__CheckAndTranslation, {casted});
      Value *converted = IRB.CreateBitCast(translated, Dst->getType());

      auto *NewMemSet = IRB.CreateMemSet(
          converted, memSetInst->getValue(), memSetInst->getLength(),
          *memSetInst->getDestAlign(), memSetInst->isVolatile());
      memSetInst->replaceAllUsesWith(NewMemSet);
      memSetInst->eraseFromParent();
      continue;
    }

    if (auto *memTransferInst = dyn_cast<MemTransferInst>(I)) {
      Value *Src = memTransferInst->getRawSource();
      Value *Dst = memTransferInst->getRawDest();

      if (!Src->getType()->isPointerTy() || !Dst->getType()->isPointerTy())
        continue;

      IRBuilder<> IRB(memTransferInst);
      Value *castedSrc = IRB.CreateBitCast(Src, VoidPtrTy);
      Value *translatedSrc = IRB.CreateCall(__CheckAndTranslation, {castedSrc});
      Value *convertedSrc = IRB.CreateBitCast(translatedSrc, Src->getType());

      Value *castedDst = IRB.CreateBitCast(Dst, VoidPtrTy);
      Value *translatedDst = IRB.CreateCall(__CheckAndTranslation, {castedDst});
      Value *convertedDst = IRB.CreateBitCast(translatedDst, Dst->getType());

      auto *NewMemTransfer = IRB.CreateMemCpy(
          convertedDst, *memTransferInst->getDestAlign(), convertedSrc,
          *memTransferInst->getSourceAlign(), memTransferInst->getLength(),
          memTransferInst->isVolatile());
      memTransferInst->replaceAllUsesWith(NewMemTransfer);
      memTransferInst->eraseFromParent();
      continue;
    }

    if (auto *CI = dyn_cast<CallInst>(I)) {
      Function *calledFunc = CI->getCalledFunction();
      if (!calledFunc)
        continue;

      StringRef funcName = calledFunc->getName();

      bool isMemFunc = funcName.contains("memset") ||
                       funcName.contains("memcpy") ||
                       funcName.contains("memclr");
      if (!isMemFunc)
        continue;
      if (funcName.contains("memclr")) {
        errs() << "memclr Find!!: " << CI << "\n";
      }

      if (funcName.contains("memset")) {
        errs() << "memset Find!!: " << CI << "\n";
      }

      IRBuilder<> IRB(CI);

      for (unsigned argIdx = 0; argIdx < CI->arg_size(); ++argIdx) {
        Value *arg = CI->getArgOperand(argIdx);
        if (!arg->getType()->isPointerTy())
          continue;

        Value *casted = IRB.CreateBitCast(arg, VoidPtrTy);
        Value *translated = IRB.CreateCall(__CheckAndTranslation, {casted});
        Value *converted = IRB.CreateBitCast(translated, arg->getType());

        CI->setArgOperand(argIdx, converted);
        errs() << "Transformed pointer arg in call to: " << funcName << "\n";
      }

      continue;
    }
    if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
      Value *basePtr = GEP->getPointerOperand();
      if (!cameFromDoublePointer(basePtr))
        continue;

      IRBuilder<> IRB(GEP);

      Value *casted = IRB.CreateBitCast(basePtr, VoidPtrTy);
      Value *translated = IRB.CreateCall(__CheckAndTranslation, {casted});
      Value *converted = IRB.CreateBitCast(translated, basePtr->getType());

      // if (Instruction *CI = dyn_cast<Instruction>(converted))
      // createdInsts2.insert(CI);
      GEP->setOperand(0, converted);
    }
    if (auto *LI = dyn_cast<LoadInst>(I)) {
      Value *ptr = LI->getPointerOperand();

      // strip off pointer casts
      // Value *underlying = getUnderlyingObject(ptr, 30);

      // Type *ty = underlying->getType();
      // if (!ty->isPointerTy()) continue;

      // Type *elemTy = ty->getPointerElementType();
      // if (!elemTy || !elemTy->isPointerTy()) continue;
      // if (!isPointerToPointer(ptr)) continue;
      if (!cameFromDoublePointer(ptr))
        continue;
      errs() << "Double Pointer!!!: " << *LI << "\n";

      IRBuilder<> IRB(LI);
      Value *casted = IRB.CreateBitCast(ptr, VoidPtrTy);
      Value *translated = IRB.CreateCall(__CheckAndTranslation, {casted});
      Value *converted = IRB.CreateBitCast(translated, ptr->getType());
      LI->setOperand(0, converted);
    }

    else if (auto *SI = dyn_cast<StoreInst>(I)) {
      Value *ptr = SI->getPointerOperand();
      if (!cameFromDoublePointer(ptr))
        continue;
      errs() << "Double Pointer!!!: " << *SI << "\n";

      IRBuilder<> IRB(SI);
      Value *casted = IRB.CreateBitCast(ptr, VoidPtrTy);
      Value *translated = IRB.CreateCall(__CheckAndTranslation, {casted});
      Value *converted = IRB.CreateBitCast(translated, ptr->getType());
      SI->setOperand(1, converted);
    }
  }
}

void replaceAllPointerArgsWithTranslation2(Function &F) {
  if (F.isDeclaration())
    return;
  IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

  std::vector<Instruction *> InstsToProcess;
  for (auto &BB : F) {
    for (auto &I : BB) {
      InstsToProcess.push_back(&I);
    }
  }

  std::map<Value *, Value *> ReplacementMap;
  std::set<Instruction *> CreatedInsts;
  std::set<Instruction *> ChangesArg;

  for (auto &Arg : F.args()) {
    if (!Arg.getType()->isPointerTy())
      continue;

    Value *CastArg = Builder.CreateBitCast(&Arg, VoidPtrTy);
    if (Instruction *Inst = dyn_cast<Instruction>(CastArg))
      CreatedInsts.insert(Inst);

    // Value *Call = Builder.CreateCall(__TranslationOnly, {CastArg});
    // for juliet
    Value *Call = Builder.CreateCall(__CheckAndTranslation, {CastArg});
    if (Instruction *Inst = dyn_cast<Instruction>(Call))
      CreatedInsts.insert(Inst);

    Value *Final = Builder.CreateBitCast(Call, Arg.getType());
    if (Instruction *Inst = dyn_cast<Instruction>(Final))
      CreatedInsts.insert(Inst);

    ReplacementMap[&Arg] = Final;
  }
  // 2. Replace all operand uses, skipping our own newly created instructions
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (CreatedInsts.count(&I))
        continue;
      if (isa<CallInst>(&I)) {
        // continue;
        CallInst *CI = dyn_cast<CallInst>(&I);
        if (CI->getCalledFunction() &&
            !CI->getCalledFunction()->getName().contains("__aeabi") &&
            !CI->getCalledFunction()->getName().contains("llvm") &&
            !CI->getCalledFunction()->getName().contains("print"))
          continue;
      }
      for (unsigned i = 0; i < I.getNumOperands(); ++i) {
        Value *Op = I.getOperand(i);
        if (ReplacementMap.count(Op)) {
          I.setOperand(i, ReplacementMap[Op]);
          ChangesArg.insert(&I);
        }
      }
    }
  }
}

std::unordered_set<std::string> FunctionAvoidList = {};
std::unordered_set<std::string> FunctionArgumentIsAlloca = {};

void CheckFunctionArgument(Function &F) {
  if (F.isDeclaration())
    return;
}
void CheckFunctionAvoid(Function &F) {
  if (F.isDeclaration())
    return;
}

StringRef analyzePtr(Instruction *I, Value *Ptr) {
  Value *Underlying = getUnderlyingObject(Ptr, 50);

  if (auto *callInst = dyn_cast<CallInst>(Underlying)) {
    Function *CalledFunc = callInst->getCalledFunction();
    if (CalledFunc && (CalledFunc->getName() == "malloc" ||
                       CalledFunc->getName() == "calloc" ||
                       CalledFunc->getName() == "realloc" ||
                       CalledFunc->getName() == "__wrap_malloc" ||
                       CalledFunc->getName() == "__wrap_calloc" ||
                       CalledFunc->getName() == "__wrap_realloc")) {
      return "FastPath";
    }
  }

  if (isa<AllocaInst>(Underlying) || isa<GlobalVariable>(Underlying) ||
      isa<AllocaInst>(Ptr) || isa<GlobalVariable>(Ptr)) {
    return "Exclude";
  }

  return "SlowPath";
}

void applyTranslate(Function &F, Instruction *I) {
  IRBuilder<> Builder(I);
  if (auto *storeInst = dyn_cast<StoreInst>(I)) {
    Value *Ptr = storeInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }
    StringRef Path = analyzePtr(I, Ptr);
    Value *TransformedPtr = nullptr;
    if (Path == "Exclude") {
      return;
    } else if (Path == "FastPath") {
      storeInst->setOperand(1, TranslationPointer(Builder, Ptr));
    } else if (Path == "SlowPath") {
      storeInst->setOperand(1, CheckandTranslationPointer(Builder, Ptr));
    }
  } else if (auto *loadInst = dyn_cast<LoadInst>(I)) {
    Value *Ptr = loadInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }
    StringRef Path = analyzePtr(I, Ptr);
    if (Path == "Exclude") {
      return;
    } else if (Path == "FastPath") {
      loadInst->setOperand(0, TranslationPointer(Builder, Ptr));
    } else if (Path == "SlowPath") {
      loadInst->setOperand(0, CheckandTranslationPointer(Builder, Ptr));
    }
  } else if (auto *callInst = dyn_cast<CallInst>(I)) {
    Function *calledFunction = callInst->getCalledFunction();
    if (calledFunction) {
      if (!FunctionNofreeList.count(calledFunction->getName().str()))
        return;
      for (unsigned i = 0; i < callInst->arg_size(); ++i) {
        Value *Arg = callInst->getArgOperand(i);
        if (!Arg->getType()->isPointerTy()) {
          continue;
        }
        StringRef Path = analyzePtr(I, Arg);
        if (Path == "Exclude") {
          continue;
        }
        Value *TranslatedArg = (Path == "FastPath")
                                   ? TranslationPointer(Builder, Arg)
                                   : CheckandTranslationPointer(Builder, Arg);
        callInst->setArgOperand(i, TranslatedArg);
      }
    }
  }
}

void applyTranslation2(Function &F, Instruction *I,
                       const TargetLibraryInfo &TLI,
                       std::map<Value *, std::set<Instruction *>> &mallocUsers,
                       std::map<Value *, int> &isPointerNotFree) {
  IRBuilder<> Builder(I);
  if (auto *storeInst = dyn_cast<StoreInst>(I)) {
    Value *Ptr = storeInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Ptr, mallocUsers, isPointerNotFree);
    Value *TransformedPtr = nullptr;

    if (Path == "FastPath") {
      TransformedPtr = TranslationPointer(Builder, Ptr);
    } else if (Path == "SlowPath") {
      TransformedPtr = CheckandTranslationPointer(Builder, Ptr);
    }

    if (TransformedPtr) {
      Value *CorrectedPtr =
          Builder.CreateBitCast(TransformedPtr, Ptr->getType());
      storeInst->setOperand(1, CorrectedPtr);
    }
  } else if (auto *loadInst = dyn_cast<LoadInst>(I)) {
    Value *Ptr = loadInst->getPointerOperand();
    if (!Ptr->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Ptr, mallocUsers, isPointerNotFree);
    if (Path == "Exclude") {
      return;
    }
    if (Path == "FastPath") {
      loadInst->setOperand(0, TranslationPointer(Builder, Ptr));
    } else if (Path == "SlowPath") {
      loadInst->setOperand(0, CheckandTranslationPointer(Builder, Ptr));
    }
  } else if (auto *memSetInst = dyn_cast<MemSetInst>(I)) {
    Value *Dst = memSetInst->getRawDest();
    if (!Dst->getType()->isPointerTy()) {
      return;
    }

    StringRef Path = analyzePointer(I, Dst, mallocUsers, isPointerNotFree);
    if (Path == "Exclude") {
      return;
    }
    Value *TranslatedDst = (Path == "FastPath")
                               ? TranslationPointer(Builder, Dst)
                               : CheckandTranslationPointer(Builder, Dst);

    // New MemSet instruction
    Value *Length = memSetInst->getLength();
    Value *Value = memSetInst->getValue();
    Align Alignment = *memSetInst->getDestAlign();
    auto *NewMemSet =
        Builder.CreateMemSet(TranslatedDst, Value, Length, Alignment);
    memSetInst->replaceAllUsesWith(NewMemSet);
    memSetInst->eraseFromParent();
  } else if (auto *memTransferInst = dyn_cast<MemTransferInst>(I)) {
    Value *Src = memTransferInst->getRawSource();
    Value *Dst = memTransferInst->getRawDest();

    if (!Src->getType()->isPointerTy() || !Dst->getType()->isPointerTy()) {
      // errs() << "Error: MemTransferInst Src or Dst is not a pointer type!\n";
      return;
    }

    StringRef SrcPath = analyzePointer(I, Src, mallocUsers, isPointerNotFree);
    StringRef DstPath = analyzePointer(I, Dst, mallocUsers, isPointerNotFree);

    if (SrcPath == "Exclude" && DstPath == "Exclude") {
      errs() << "Skipping Translation for MemTransfer: Both Src and Dst are "
                "Exclude\n";
      return;
    }

    Value *TranslatedSrc = (SrcPath == "FastPath")
                               ? TranslationPointer(Builder, Src)
                               : CheckandTranslationPointer(Builder, Src);
    Value *TranslatedDst = (DstPath == "FastPath")
                               ? TranslationPointer(Builder, Dst)
                               : CheckandTranslationPointer(Builder, Dst);

    Value *Length = memTransferInst->getLength();
    Align SrcAlign = *memTransferInst->getSourceAlign();
    Align DstAlign = *memTransferInst->getDestAlign();
    bool IsVolatile = memTransferInst->isVolatile();

    auto *NewMemTransfer = Builder.CreateMemCpy(
        TranslatedDst, DstAlign, TranslatedSrc, SrcAlign, Length, IsVolatile);

    memTransferInst->replaceAllUsesWith(NewMemTransfer);
    memTransferInst->eraseFromParent();
  }

  else if (auto *callInst = dyn_cast<CallInst>(I)) {
    Function *calledFunction = callInst->getCalledFunction();
    if (calledFunction) {
      if (calledFunction->getName() == "malloc" ||
          calledFunction->getName() == "__wrap_malloc" ||
          calledFunction->getName() == "calloc" ||
          calledFunction->getName() == "__wrap_calloc" ||
          calledFunction->getName() == "realloc" ||
          calledFunction->getName() == "__wrap_realloc") {
        Value *ptr = callInst;
        isPointerNotFree[ptr] = 1;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "__wrap_free") {
        Value *ptr = callInst->getArgOperand(0);
        isPointerNotFree[ptr] = 0;
      }
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "realloc")
        return;
      if (calledFunction->getName() == "free" ||
          calledFunction->getName() == "__wrap_free")
        return;
      if (calledFunction->getName() == "check_and_translation" ||
          calledFunction->getName() == "translation_only")
        return;

      if (FunctionNofreeList.count(calledFunction->getName().str())) {
        for (unsigned i = 0; i < callInst->arg_size(); ++i) {
          Value *Arg = callInst->getArgOperand(i);
          if (!Arg->getType()->isPointerTy()) {
            continue;
          }

          StringRef Path =
              analyzePointer(I, Arg, mallocUsers, isPointerNotFree);
          if (Path == "Exclude") {
            continue;
          }
          // Value *TranslatedArg = (Path == "FastPath")
          //                           ? TranslationPointer(Builder, Arg)
          //                           : CheckandTranslationPointer(Builder,
          //                           Arg);
          Value *TranslatedArg = TranslationPointer(Builder, Arg);
          callInst->setArgOperand(i, TranslatedArg);
        }
        return;
      }
      LibFunc libFunc;
      // if (!TLI.getLibFunc(*calledFunction, libFunc) &&
      // optimized.count(calledFunction->getName().str()) > 0) {
      if (!TLI.getLibFunc(*calledFunction, libFunc)) {
        return;
      }
      if (optimized.count(calledFunction->getName().str()) > 0 &&
          !calledFunction->getName().contains("memchr"))
        return;
      for (unsigned i = 0; i < callInst->arg_size(); ++i) {
        Value *Arg = callInst->getArgOperand(i);
        if (!Arg->getType()->isPointerTy()) {
          continue;
        }

        StringRef Path = analyzePointer(I, Arg, mallocUsers, isPointerNotFree);
        if (Path == "Exclude") {
          continue;
        }
        Value *TranslatedArg = (Path == "FastPath")
                                   ? TranslationPointer(Builder, Arg)
                                   : CheckandTranslationPointer(Builder, Arg);
        callInst->setArgOperand(i, TranslatedArg);
      }
    }
  }
}

void applyDoublePtrTranslate(Function &F) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      auto *LI = dyn_cast<LoadInst>(&I);
      if (!LI)
        continue;
      Type *loadedTy = LI->getType();
      if (!loadedTy->isPointerTy())
        continue;
      SmallVector<Use *, 8> Uses;
      Uses.reserve(LI->getNumUses());
      for (Use &U : LI->uses())
        Uses.push_back(&U);

      IRBuilder<> B(LI->getNextNode() ? LI->getNextNode()
                                      : LI->getParent()->getTerminator());
      Value *origPtr = LI;
      Value *asVoid = B.CreateBitCast(origPtr, VoidPtrTy);
      // CallInst *ci = B.CreateCall(__CheckAndTranslation, {asVoid});
      CallInst *ci = B.CreateCall(__TranslationOnly, {asVoid});
      Value *newVal = B.CreateBitCast(ci, loadedTy);

      for (Use *U : Uses)
        U->set(newVal);

      // if (LI->use_empty()) LI->eraseFromParent();
    }
  }
}

std::unordered_set<std::string> ModuleAvoidList = {"sys", "periph", "stm32",
                                                   "cpu", "libc",   "boards"};

std::unordered_set<std::string> FunctionExcludeList = {
    "check_and_translation",
    "translation_only",
    "restore_only",
    "__wrap_malloc",
    "__wrap_free",
    "__wrap_realloc",
    "__wrap_calloc",
    "elk_init",
    "setMPU",
    "hwrng_init",
    "hwrng_read",
    "get_alloc_idx",
    "print_memory_peak",
    // for malloc, free
    // "mutex_lock_internal",
    // "mutex_unlock",
    "sched_set_status",
    "thread_add_to_list",
    "sched_switch",
};

std::unordered_set<std::string> FunctionExcludeList2 = { // for wasm
    "check_and_translation",
    "translation_only",
    "restore_only",
    "__wrap_malloc",
    "__wrap_free",
    "__wrap_realloc",
    "__wrap_calloc",
    "elk_init",
    "setMPU",
    "hwrng_init",
    "hwrng_read",
    "get_alloc_idx",
    "print_memory_peak",
    // for malloc, free
    // "mutex_lock_internal",
    // "mutex_unlock",
    "sched_set_status",
    "thread_add_to_list",
    "sched_switch",
};

#define DEBUG_TYPE "elk-temporal-inst"
PreservedAnalyses ElkTemporalInstPass::run(Module &M,
                                           ModuleAnalysisManager &AM) {
  /* for wasm */
  // if (M.getName() == "hello.c")
  //   return PreservedAnalyses::none();
  /* for wasm */

  std::string name = M.getName().str();
  std::istringstream iss(name);
  std::string token;

  while (std::getline(iss, token, '/')) {
    //if (ModuleAvoidList.count(token)) {
    //if (token == "pkg") return PreservedAnalyses::none();
      // errs() << "[ELK] Avoid: " << M.getName() << "\n";
      // return PreservedAnalyses::none();
    //}
  }

  errs() << "[ELK] Instrumentation: " << M.getName() << "\n";

  // Inserting Runtime Check Functions
  Int8Ty = Type::getInt8Ty(M.getContext());
  VoidPtrTy = PointerType::getUnqual(Type::getInt8Ty(M.getContext()));
  VoidType = Type::getVoidTy(M.getContext());

  FunctionType *FTy = FunctionType::get(VoidPtrTy, {VoidPtrTy}, false);
  FunctionCallee hookFunc = M.getOrInsertFunction("translation_only", FTy);
  __TranslationOnly = cast<Function>(hookFunc.getCallee());

  FTy = FunctionType::get(VoidPtrTy, {VoidPtrTy}, false);
  hookFunc = M.getOrInsertFunction("check_and_translation", FTy);
  __CheckAndTranslation = cast<Function>(hookFunc.getCallee());

  FTy = FunctionType::get(VoidPtrTy, {VoidPtrTy}, false);
  hookFunc = M.getOrInsertFunction("restore_only", FTy);
  __RestoreOnly = cast<Function>(hookFunc.getCallee());

  for (auto &F : M) {
    if (F.hasFnAttribute(Attribute::NoFree)) {
      errs() << "[ELK] Function " << F.getName() << " is nofree!\n";
      FunctionNofreeList.insert(F.getName().str());
    }
  }

  for (auto &F : M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
          if (Function *CF = CI->getCalledFunction()) {
            FunctionCallList.insert(CF->getName().str());
          }
        }
      }
    }
  }

  for (auto FN : FunctionNofreeList) {
    if (FunctionCallList.count(FN)) {
      errs() << "[ELK] Instrument Avoid: " << FN << "\n";
    }
  }

  for (auto &F : M) {
    auto &FAM =
        AM.getResult<llvm::FunctionAnalysisManagerModuleProxy>(M).getManager();
    const TargetLibraryInfo &TLI =
        FAM.getResult<llvm::TargetLibraryAnalysis>(F);
    if (isOptimizableTarget(TLI, &F)) {
      if (!M.getName().contains("wasm") && !M.getName().contains("wamr"))
        optimized.insert(F.getName().str());
    }
  }
  for (auto &F : M) {
    if (FunctionExcludeList.count(F.getName().str()))
      continue;
    if (M.getName().contains("wasm") || M.getName().contains("wamr") || M.getName().contains("tiny-asn1")) {
      auto &FAM = AM.getResult<llvm::FunctionAnalysisManagerModuleProxy>(M)
                      .getManager();
      const TargetLibraryInfo &TLI =
          FAM.getResult<llvm::TargetLibraryAnalysis>(F);
      std::vector<Instruction *> InstsToProcess;
      std::vector<Instruction *> InstsToProcessOptimized;
      std::map<Value *, std::set<Instruction *>> mallocUsers;
      std::set<Value *> Visited;
      std::map<Value *, int> isPointerNotFree;
      for (auto &BB : F) {
        for (auto &I : BB) {
          InstsToProcess.push_back(&I);
        }
      }
      for (Instruction *I : InstsToProcess) {
        if (auto *callInst = dyn_cast<CallInst>(I)) {
          Function *calledFunction = callInst->getCalledFunction();
          if (calledFunction) {
            if (calledFunction->getName() == "malloc" ||
                calledFunction->getName() == "__wrap_malloc" ||
                calledFunction->getName() == "calloc" ||
                calledFunction->getName() == "__wrap_calloc" ||
                calledFunction->getName() == "realloc" ||
                calledFunction->getName() == "__wrap_realloc") {
              Value *mallocPtr = callInst;
              findAllUsers(callInst, mallocUsers[mallocPtr], Visited);
            }
          }
        }
      }
      for (Instruction *I : InstsToProcess) {
        applyTranslation(F, I, TLI, mallocUsers, isPointerNotFree);
      }
      continue;
    }
    if (FunctionNofreeList.count(F.getName().str())) {
      if (FunctionCallList.count(F.getName().str())) {
        applyDoublePtrTranslate(F);
      }
      else {
        replaceAllPointerArgsWithTranslation2(F);
        applyDoublePtrTranslate(F);
      }
    } else {
      auto &FAM = AM.getResult<llvm::FunctionAnalysisManagerModuleProxy>(M)
                      .getManager();
      const TargetLibraryInfo &TLI =
          FAM.getResult<llvm::TargetLibraryAnalysis>(F);
      if (optimized.count(F.getName().str()) > 0) {
        replaceAllPointerArgsWithTranslation2(F);
        applyDoublePtrTranslate(F);
      } else {
        std::vector<Instruction *> InstsToProcess;
        std::map<Value *, std::set<Instruction *>> mallocUsers;
        std::set<Value *> Visited;
        std::map<Value *, int> isPointerNotFree;
        for (auto &BB : F) {
          for (auto &I : BB) {
            InstsToProcess.push_back(&I);
          }
        }
        for (Instruction *I : InstsToProcess) {
          if (auto *callInst = dyn_cast<CallInst>(I)) {
            Function *calledFunction = callInst->getCalledFunction();
            if (calledFunction) {
              if (calledFunction->getName() == "malloc" ||
                  calledFunction->getName() == "__wrap_malloc" ||
                  calledFunction->getName() == "calloc" ||
                  calledFunction->getName() == "__wrap_calloc" ||
                  calledFunction->getName() == "realloc" ||
                  calledFunction->getName() == "__wrap_realloc") {
                Value *mallocPtr = callInst;
                findAllUsers(callInst, mallocUsers[mallocPtr], Visited);
              }
            }
          }
        }
        for (Instruction *I : InstsToProcess) {
          // applyTranslation(F, I, TLI, mallocUsers, isPointerNotFree);
          applyTranslation2(F, I, TLI, mallocUsers, isPointerNotFree);
        }
      }
    }
  }
  return PreservedAnalyses::none();
}

namespace {
struct ElkTemporalInstLegacyPass : public ModulePass {

  static char ID;
  ElkTemporalInstLegacyPass() : ModulePass(ID) {
    initializeElkTemporalInstLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override {
    errs() << "ElkTemporalInst" << "\n";
    return false;
  }
};
} // namespace

char ElkTemporalInstLegacyPass::ID = 0;
INITIALIZE_PASS_BEGIN(ElkTemporalInstLegacyPass, "elk-temporal-inst",
                      "ELK for temporal instrumentation", false, false)
INITIALIZE_PASS_END(ElkTemporalInstLegacyPass, "elk-temporal-inst",
                    "ELK for temporal instrumentation", false, false)

Pass *llvm::createElkTemporalInstLegacyPass() {
  return new ElkTemporalInstLegacyPass();
}