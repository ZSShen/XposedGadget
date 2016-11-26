LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := EggHunt
LOCAL_SRC_FILES := EggHunt.cpp
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)