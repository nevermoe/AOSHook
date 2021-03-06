LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := target
LOCAL_SRC_FILES := target.c.arm
# cmd-strip :=  

include $(BUILD_EXECUTABLE)

###########################################################

include $(CLEAR_VARS)
LOCAL_MODULE    := hook
LOCAL_SRC_FILES := hook.c

include $(BUILD_STATIC_LIBRARY)

###########################################################

include $(CLEAR_VARS)
LOCAL_MODULE    := stalker
LOCAL_SRC_FILES := stalker.c
LOCAL_STATIC_LIBRARIES := hook

include $(BUILD_EXECUTABLE)

###########################################################

include $(CLEAR_VARS)
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE    := inject
LOCAL_SRC_FILES := inject.c inject_arm.c.arm
LOCAL_LDLIBS := -llog 
LOCAL_STATIC_LIBRARIES := hook

include $(BUILD_SHARED_LIBRARY)

###########################################################
