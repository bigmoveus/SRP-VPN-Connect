/* SPDX-License-Identifier: MIT
 *
 * JNI for WireGuardNative (WireGuardClient.kt): thin calls into api.go's exports (Android builds only: the _android suffix).
 */
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "_cgo_export.h"

JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WireGuardNative_turnOn(JNIEnv *env, jclass c, jstring settings, jint tunFd) {
    const char *text = (*env)->GetStringUTFChars(env, settings, NULL);
    if (!text) return -1;
    int handle = srpWgTurnOn((char *)text, tunFd);
    (*env)->ReleaseStringUTFChars(env, settings, text);
    return handle;
}

JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WireGuardNative_turnOnAmnezia(JNIEnv *env, jclass c, jstring settings, jint tunFd) {
    const char *text = (*env)->GetStringUTFChars(env, settings, NULL);
    if (!text) return -1;
    int handle = srpAwgTurnOn((char *)text, tunFd);
    (*env)->ReleaseStringUTFChars(env, settings, text);
    return handle;
}

JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_WireGuardNative_lastError(JNIEnv *env, jclass c) {
    char *text = srpWgLastError();
    if (!text) return NULL;
    jstring result = (*env)->NewStringUTF(env, text);
    srpWgFree(text);
    return result;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_turnOff(JNIEnv *env, jclass c, jint handle) {
    srpWgTurnOff(handle);
}

JNIEXPORT jlong JNICALL Java_tr_com_srp_vpn_WireGuardNative_setConfig(JNIEnv *env, jclass c, jint handle, jstring settings) {
    const char *text = (*env)->GetStringUTFChars(env, settings, NULL);
    if (!text) return -1;
    long long result = srpWgSetConfig(handle, (char *)text);
    (*env)->ReleaseStringUTFChars(env, settings, text);
    return result;
}

JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_WireGuardNative_getConfig(JNIEnv *env, jclass c, jint handle) {
    char *text = srpWgGetConfig(handle);
    if (!text) return NULL;
    jstring result = (*env)->NewStringUTF(env, text);
    memset(text, 0, strlen(text));   // it held the private key
    srpWgFree(text);
    return result;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_bumpSockets(JNIEnv *env, jclass c, jint handle) {
    srpWgBumpSockets(handle);
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_setVerbose(JNIEnv *env, jclass c, jboolean on) {
    srpWgSetVerbose(on ? 1 : 0);
}

JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_WireGuardNative_nextLog(JNIEnv *env, jclass c, jint timeoutMs) {
    char *line = srpWgNextLog(timeoutMs);
    if (!line) return NULL;
    jstring result = (*env)->NewStringUTF(env, line);
    srpWgFree(line);
    return result;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_setProbeFlows(JNIEnv *env, jclass c, jint handle, jintArray flows) {
    jsize length = (*env)->GetArrayLength(env, flows);
    jint *values = (*env)->GetIntArrayElements(env, flows, NULL);
    if (!values) return;
    srpWgSetProbeFlows(handle, (int *)values, length / 3);
    (*env)->ReleaseIntArrayElements(env, flows, values, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_submit(JNIEnv *env, jclass c, jint handle, jbyteArray packet) {
    jsize length = (*env)->GetArrayLength(env, packet);
    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    if (!bytes) return;
    srpWgSubmit(handle, (char *)bytes, length);
    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_WireGuardNative_nextProbe(JNIEnv *env, jclass c, jint handle, jint timeoutMs) {
    char buffer[2048];
    int length = srpWgNextProbe(handle, buffer, sizeof(buffer), timeoutMs);
    if (length <= 0) return NULL;
    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, length, (const jbyte *)buffer);
    return result;
}

// Aether's Private mode (netstack.go): a WireGuard relay on a userspace TUN to the proxy on the user's server
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WireGuardNative_netstackStart(JNIEnv *env, jclass c, jstring uapi, jstring ifAddr,
                                                                         jstring listen, jstring target) {
    const char *u = (*env)->GetStringUTFChars(env, uapi, NULL);
    const char *a = (*env)->GetStringUTFChars(env, ifAddr, NULL);
    const char *l = (*env)->GetStringUTFChars(env, listen, NULL);
    const char *t = (*env)->GetStringUTFChars(env, target, NULL);
    int handle = srpWgNetstackStart((char *)u, (char *)a, (char *)l, (char *)t);
    (*env)->ReleaseStringUTFChars(env, uapi, u);
    (*env)->ReleaseStringUTFChars(env, ifAddr, a);
    (*env)->ReleaseStringUTFChars(env, listen, l);
    (*env)->ReleaseStringUTFChars(env, target, t);
    return handle;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WireGuardNative_netstackStop(JNIEnv *env, jclass c, jint handle) {
    srpWgNetstackStop(handle);
}
