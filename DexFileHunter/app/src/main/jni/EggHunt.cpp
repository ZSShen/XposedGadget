//
// Created by userpc on 2016/11/10.
//

#include "org_zsshen_dexfilehunter_DexFileHunter.h"
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <iosfwd>
#include <fstream>
#include <unistd.h>
#include <android/log.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "EggHunt", __VA_ARGS__)

static const int32_t kBlahSize = 2048;
static const char* kSelfProcMap = "/proc/self/maps";
static const char* kOriginalDex = "/data/data/tx.qq898507339.bzy9/.cache/classes.dex";
static const char* kTempStore = "/data/local/tmp";


JNIEXPORT void JNICALL Java_org_zsshen_dexfilehunter_DexFileHunter_ScanMemory
  (JNIEnv* env, jobject self)
{
    char buf[kBlahSize];
    snprintf(buf, kBlahSize, "%s", kSelfProcMap);

    std::ifstream map(buf, std::ifstream::in);
    while (map.good() && !map.eof()) {
        map.getline(buf, kBlahSize);

        if (!strstr(buf, kOriginalDex))
            continue;

        uint32_t addr_bgn, addr_end;
        sscanf(buf, "%x-%x", &addr_bgn, &addr_end);

        // Check DEX magic.
        char* scan_bgn = reinterpret_cast<char*>(addr_bgn);
        char* scan_end = reinterpret_cast<char*>(addr_end);
        bool found = false;
        while (scan_bgn < scan_end - 1) {
            if (*scan_bgn == 'd' &&
                *(scan_bgn + 1) == 'e' &&
                *(scan_bgn + 2) == 'x') {
                found = true;
                break;
            }
            ++scan_bgn;
        }

        if (!found)
            continue;

        // Dump the potentially unpacked code.
        snprintf(buf, kBlahSize, "%s/%08x_%08x", kTempStore, addr_bgn, addr_end);
        LOGD("Open: %s", buf);
        std::ofstream out(buf, std::ios::out | std::ios::binary);

        LOGD("Write: %s", buf);
        out.write(scan_bgn, scan_end - scan_bgn + 1);

        out.close();
        LOGD("Close: %s", buf);
    }
}
