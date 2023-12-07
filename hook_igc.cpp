#include <PFishHook.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*dlopenptr)(const char *__file, int __mode);
typedef bool (*ptrverifyModule)(void *M, void *OS, bool *BrokenDebugInfo);
typedef void *(*dbgsptr)();

static dlopenptr old_dlopen = nullptr;
static ptrverifyModule impl = nullptr;
static dbgsptr pdbgs;

static bool myverifyModule(void *M, void *OS, bool *BrokenDebugInfo) {
    fprintf(stderr, "igchook: verifyModule:\n");
    auto ret = impl(M, pdbgs(), BrokenDebugInfo);
    fprintf(stderr, "igchook: verifyModule done\n");
    return ret;
}
static void hook_impl(void *igc_handle) {
    auto old_verify = (ptrverifyModule)dlsym(igc_handle,
            "_ZN4llvm12verifyModuleERKNS_6ModuleEPNS_11raw_ostreamEPb");
    pdbgs = (dbgsptr)dlsym(igc_handle, "_ZN4llvm4dbgsEv");
    if (HookIt((void *)old_verify, (void **)&impl, (void *)&myverifyModule)
            != HookStatus::FHSuccess) {
        fprintf(stderr, "igchook: Hook verifyModule failed\n");
        abort();
    }
    fprintf(stderr, "igchook: Hook verifyModule Done\n");
}

void *my_dlopen(const char *__file, int __mode) __THROWNL {
    fprintf(stderr, "dlopen:%s\n", __file);
    auto ret = old_dlopen(__file, __mode);
    if (ret && !strcmp(__file, "libigc.so.1") && !impl) {
        fprintf(stderr, "igchook: Hook libigc\n");
        hook_impl(ret);
    }
    return ret;
}

struct init_igc_hook {
    init_igc_hook() {
        if (HookIt((void *)&dlopen, (void **)&old_dlopen, (void *)&my_dlopen)
                != HookStatus::FHSuccess) {
            fprintf(stderr, "igchook: Hook failed\n");
            abort();
        }
    }
};
static init_igc_hook __v;
