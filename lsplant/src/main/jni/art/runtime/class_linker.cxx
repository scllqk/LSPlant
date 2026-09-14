module;

#include <sys/types.h>

#include "logging.hpp"

export module lsplant:class_linker;

import :art_method;
import :thread;
import :common;
import :clazz;
import :handle;
import :runtime;
import hook_helper;

namespace lsplant::art {
export class ClassLinker {
private:
    inline static auto SetEntryPointsToInterpreter_ =
        "_ZNK3art11ClassLinker27SetEntryPointsToInterpreterEPNS_9ArtMethodE"_sym.as<void(ClassLinker::*)(ArtMethod *)>;

    inline static auto ShouldUseInterpreterEntrypoint_ =
        "_ZN3art11ClassLinker30ShouldUseInterpreterEntrypointEPNS_9ArtMethodEPKv"_sym.hook->*[]
        <Backup auto backup>
        (ArtMethod *art_method, const void *quick_code)static -> bool {
            if (quick_code != nullptr && IsHooked(art_method)) [[unlikely]] {
                return false;
            }
            return backup(art_method, quick_code);
        };

    inline static auto art_quick_to_interpreter_bridge_ =
            "art_quick_to_interpreter_bridge"_sym.as<void(void *)>;

    inline static auto GetOptimizedCodeFor_ =
            "_ZN3art15instrumentationL19GetOptimizedCodeForEPNS_9ArtMethodE"_sym.as<void *(ArtMethod *)>;

    inline static auto GetRuntimeQuickGenericJniStub_=
            "_ZNK3art11ClassLinker29GetRuntimeQuickGenericJniStubEv"_sym.as<void *(ClassLinker::*)()>;

    // [ScllQk] MayGetBackup simplified — original used IsHooked() which referenced removed hooks
    inline static art::ArtMethod *MayGetBackup(art::ArtMethod *method) {
        return method;
    }

    // [ScllQk] 10 hook declarations removed (RegisterNative/UnregisterNative/FixupStaticTrampolines)
    // These contain _ZN3art* strings that加固 apps scan for hooking detection.
    // Remaining hooks: SetEntryPointsToInterpreter_, ShouldUseInterpreterEntrypoint_,
    // GetOptimizedCodeFor_, AdjustThreadVisibilityCounter_, MarkVisiblyInitialized_

    static void RestoreBackup(const dex::ClassDef *class_def, art::Thread *self) {
        auto methods = mirror::Class::PopBackup(class_def, self);
        for (const auto &[art_method, old_trampoline] : methods) {
            auto new_trampoline = art_method->GetEntryPoint();
            art_method->SetEntryPoint(old_trampoline);
            auto deoptimized = IsDeoptimized(art_method);
            auto backup_method = IsHooked(art_method);
            if (backup_method) {
                // If deoptimized, the backup entrypoint should be already set to interpreter
                if (!deoptimized && new_trampoline != old_trampoline) [[unlikely]] {
                    LOGV("propagate entrypoint for orig %p backup %p", art_method, backup_method);
                    backup_method->SetEntryPoint(new_trampoline);
                }
            } else if (deoptimized) {
                if (new_trampoline != &art_quick_to_interpreter_bridge_ && !art_method->IsNative()) {
                    LOGV("re-deoptimize for %p", art_method);
                    SetEntryPointsToInterpreter(art_method);
                }
            }
        }
    }

    // [ScllQk] FixupStaticTrampolines hooks removed — their _ZN3art* strings leak hooking detection

    inline static auto AdjustThreadVisibilityCounter_ =
        ("_ZN3art11ClassLinker26VisiblyInitializedCallback29AdjustThreadVisibilityCounterEPNS_6ThreadEi"_sym |
         "_ZN3art11ClassLinker26VisiblyInitializedCallback29AdjustThreadVisibilityCounterEPNS_6ThreadEl"_sym).hook->*[]
         <MemBackup auto backup>
         (ClassLinker *thiz, Thread *self, ssize_t adjustment) static -> void {
            backup(thiz, self, adjustment);
            RestoreBackup(nullptr, self);
        };

    inline static auto MarkVisiblyInitialized_ =
        "_ZN3art11ClassLinker26VisiblyInitializedCallback22MarkVisiblyInitializedEPNS_6ThreadE"_sym.hook->*[]
        <MemBackup auto backup>
        (ClassLinker *thiz, Thread *self) static -> void {
            backup(thiz, self);
            RestoreBackup(nullptr, self);
        };

public:
    static bool Init(JNIEnv *env, const HookHandler &handler) {
        int sdk_int = GetAndroidApiLevel();

        if (sdk_int >= __ANDROID_API_N__ && sdk_int < __ANDROID_API_T__) {
            handler(ShouldUseInterpreterEntrypoint_);
        }

        // [ScllQk] RegisterNative/UnregisterNative handler calls removed (symbols deleted above)
        // Original code returned false if these failed; now unconditionally pass

        if (sdk_int >= __ANDROID_API_R__) {
            if constexpr (kArch != Arch::kX86 && kArch != Arch::kX86_64) {
                if (!handler(AdjustThreadVisibilityCounter_, MarkVisiblyInitialized_)) {
                    LOGW("MarkVisiblyInitialized not hooked");
                }
            }
        }

        if (!handler(SetEntryPointsToInterpreter_)) [[likely]] {
            if (handler(GetOptimizedCodeFor_, true)) [[likely]] {
                auto obj = JNI_FindClass(env, "java/lang/Object");
                if (!obj) {
                    return false;
                }
                auto method = JNI_GetMethodID(env, obj, "equals", "(Ljava/lang/Object;)Z");
                if (!method) {
                    return false;
                }
                auto dummy = ArtMethod::FromReflectedMethod(
                        env, JNI_ToReflectedMethod(env, obj, method, false).get())->Clone();
                JavaDebuggableGuard guard;
                // just in case
                dummy->SetNonNative();
                art_quick_to_interpreter_bridge_ = GetOptimizedCodeFor_(dummy.get());
            } else if (!handler(art_quick_to_interpreter_bridge_)) [[unlikely]] {
                return false;
            }
        }
        LOGD("art_quick_to_interpreter_bridge = %p", &art_quick_to_interpreter_bridge_);
        return true;
    }

    [[gnu::always_inline]] static bool SetEntryPointsToInterpreter(ArtMethod *art_method) {
        if (art_method->IsNative()) {
            return false;
        }
        if (SetEntryPointsToInterpreter_) [[likely]] {
            SetEntryPointsToInterpreter_(nullptr, art_method);
            return true;
        }
        // Android 13
        if (art_quick_to_interpreter_bridge_) [[likely]] {
            LOGV("deoptimize method %s from %p to %p", art_method->PrettyMethod(true).data(),
                 art_method->GetEntryPoint(), &art_quick_to_interpreter_bridge_);
            art_method->SetEntryPoint(
                reinterpret_cast<void *>(&art_quick_to_interpreter_bridge_));
            return true;
        }
        return false;
    }
};
}  // namespace lsplant::art
