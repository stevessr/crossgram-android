#include <unistd.h>
// Called only from the tgnet network thread, attached by ConnectionsManager.
bool crossgramOpenWss(int32_t account, int32_t dc, int fd) {
    JNIEnv *env = jniEnv[account];
    if (!env) { close(fd); return false; }
    // Resolve through the application's already-loaded class, not FindClass
    // on a native-created thread (which uses the wrong classloader).
    jmethodID method = env->GetStaticMethodID(jclass_ConnectionsManager,
            "openCrossgramWss", "(III)Z");
    if (!method || env->ExceptionCheck()) {
        env->ExceptionClear(); close(fd); return false;
    }
    bool ok = env->CallStaticBooleanMethod(jclass_ConnectionsManager, method, account, dc, fd);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return ok;
}
