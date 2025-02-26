#include <jni.h>
#include <cassert>
#include <string>
#include <android/log.h>

extern "C" {
#include "librust_rcs_client.h"
#include "librust_rcs_core.h"
#include "librust_rcs_core_ffi_android.h"
}

#include <pthread.h>

#define LOG_TAG "rust-rcs"

static struct rcs_runtime *runtime = nullptr;

struct rcs_client_handle {
    struct rcs_client *client;
};

struct rcs_messaging_session_handle {
    struct rcs_messaging_session *session;
};

struct rcs_multi_conference_v1_handle {
    struct rcs_multi_conference_v1 *conferenceV1;
};

struct multi_conference_v1_invite_response_receiver_handle {
    struct multi_conference_v1_invite_response_receiver *receiver;
};

struct state_change_callback_context {
    jobject obj;
};

struct message_callback_context {
    jobject obj;
};

struct multi_conference_v1_invite_handler_context {
    jobject obj;
};

struct auto_config_callback_context {
    jobject obj;
};

struct message_result_callback_context {
    jobject obj;
};

struct send_imdn_report_result_callback_context {
    jobject obj;
};

struct upload_file_progress_callback_context {
    jobject obj;
};

struct upload_file_result_callback_context {
    jobject obj;
};

struct download_file_progress_callback_context {
    jobject obj;
};

struct download_file_result_callback_context {
    jobject obj;
};

struct multi_conference_v1_event_listener_context {
    jobject obj;
};

struct multi_conference_v1_create_result_callback_context {
    jobject obj;
};

struct retrieve_specific_chatbots_result_callback_context {
    jobject obj;
};

struct search_chatbot_result_callback_context {
    jobject obj;
};

struct retrieve_chatbot_info_result_callback_context {
    jobject obj;
};

struct rust_async_waker_handle {
    struct rust_async_waker *waker;
};

static JavaVM *javaVm = nullptr;

static pthread_key_t env_key;
static pthread_once_t env_key_once = PTHREAD_ONCE_INIT;

static jmethodID state_change_callback_method_id = nullptr;

static jmethodID message_callback_method_id = nullptr;

static jmethodID multi_conference_v1_invite_handler_method_id = nullptr;

static jmethodID auto_config_progress_callback_method_id = nullptr;

static jmethodID auto_config_result_callback_method_id = nullptr;

static jmethodID message_result_callback_method_id = nullptr;

static jmethodID send_imdn_report_result_callback_method_id = nullptr;

static jmethodID upload_file_progress_callback_method_id = nullptr;

static jmethodID upload_file_result_callback_method_id = nullptr;

static jmethodID download_file_progress_callback_method_id = nullptr;

static jmethodID download_file_result_callback_method_id = nullptr;

static jmethodID multi_conference_v1_event_listener_on_user_joined_method_id = nullptr;

static jmethodID multi_conference_v1_event_listener_on_user_left_method_id = nullptr;

static jmethodID multi_conference_v1_event_listener_on_conference_ended_method_id = nullptr;

static jmethodID create_multi_conference_v1_result_callback_method_id = nullptr;

static jmethodID retrieve_specific_chatbots_result_callback_method_id = nullptr;

static jmethodID search_chatbot_result_callback_method_id = nullptr;

static jmethodID retrieve_chatbot_info_result_callback_method_id = nullptr;

static void jni_env_destructor(void *obj)
{
    auto *env = static_cast<JNIEnv *>(obj);

    if (env) {
        javaVm->DetachCurrentThread();
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved)
{
    JNIEnv *env;
    if (jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI_OnLoad start\n");

    javaVm = jvm;

    jclass listener = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$Listener");

    state_change_callback_method_id = env->GetMethodID(listener, "onStateChange", "(I)V");

    message_callback_method_id = env->GetMethodID(listener, "onMessage",
                                                  "(IJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    multi_conference_v1_invite_handler_method_id = env->GetMethodID(listener, "onMultiConferenceV1Invite", "(J[BJ)V");

    jclass config_listener = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$ConfigListener");

    auto_config_progress_callback_method_id = env->GetMethodID(config_listener, "onProgress", "(I)V");

    auto_config_result_callback_method_id = env->GetMethodID(config_listener, "onResult",
                                                             "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    jclass send_message_listener_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$SendMessageListener");

    message_result_callback_method_id = env->GetMethodID(send_message_listener_interface_class, "onResult",
                                                         "(ILjava/lang/String;)V");

    jclass send_imdn_report_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$SendImdnReportCallback");

    send_imdn_report_result_callback_method_id = env->GetMethodID(send_imdn_report_callback_interface_class, "onResult", "(ILjava/lang/String;)V");

    jclass upload_file_progress_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$UploadFileProgressCallback");

    upload_file_progress_callback_method_id = env->GetMethodID(upload_file_progress_callback_interface_class, "onProgress",
                                                             "(II)V");

    jclass upload_file_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$UploadFileResultCallback");

    upload_file_result_callback_method_id = env->GetMethodID(upload_file_result_callback_interface_class, "onResult",
                                                             "(ILjava/lang/String;Ljava/lang/String;)V");

    jclass download_file_progress_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$DownloadFileProgressCallback");

    download_file_progress_callback_method_id = env->GetMethodID(download_file_progress_callback_interface_class, "onProgress",
                                                               "(II)V");
    
    jclass download_file_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$DownloadFileResultCallback");

    download_file_result_callback_method_id = env->GetMethodID(download_file_result_callback_interface_class, "onResult",
                                                               "(ILjava/lang/String;)V");

    jclass multi_conference_v1_event_listener = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$MultiConferenceV1EventListener");

    multi_conference_v1_event_listener_on_user_joined_method_id = env->GetMethodID(multi_conference_v1_event_listener, "onUserJoined",
                                                                                   "(Ljava/lang/String;)V");

    multi_conference_v1_event_listener_on_user_left_method_id = env->GetMethodID(multi_conference_v1_event_listener, "onUserLeft",
                                                                                 "(Ljava/lang/String;)V");

    multi_conference_v1_event_listener_on_conference_ended_method_id = env->GetMethodID(multi_conference_v1_event_listener, "onConferenceEnded", "()V");

    jclass create_multi_conference_v1_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$CreateMultiConferenceV1ResultCallback");

    create_multi_conference_v1_result_callback_method_id = env->GetMethodID(create_multi_conference_v1_result_callback_interface_class, "onResult", "(J[B)V");

    jclass retrieve_specific_chatbots_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$RetrieveSpecificChatbotsResultCallback");

    retrieve_specific_chatbots_result_callback_method_id = env->GetMethodID(retrieve_specific_chatbots_result_callback_interface_class, "onResult", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    jclass search_chatbot_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$SearchChatbotResultCallback");

    search_chatbot_result_callback_method_id = env->GetMethodID(search_chatbot_result_callback_interface_class, "onResult", "(ILjava/lang/String;Ljava/lang/String;)V");

    jclass retrieve_chatbot_info_result_callback_interface_class = env->FindClass("com/everfrost/rusty/rcs/client/RustyRcsClient$RetrieveChatbotInfoResultCallback");

    retrieve_chatbot_info_result_callback_method_id = env->GetMethodID(retrieve_chatbot_info_result_callback_interface_class, "onResult", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    runtime = new_rcs_runtime();

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI_OnLoad end\n");

    return JNI_VERSION_1_6;
}

static void create_jni_env_key()
{
    int r = pthread_key_create(&env_key, jni_env_destructor);

    assert(r == 0);
}

static JNIEnv *ensure_jni_env()
{
    int r = pthread_once(&env_key_once, create_jni_env_key);

    assert(r == 0);

    void *ptr = pthread_getspecific(env_key);

    if (ptr == nullptr) {
        JNIEnv *env = nullptr;

        int res = javaVm->GetEnv((void **)&env, JNI_VERSION_1_6);

        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "javaVm->GetEnv result %d\n", res);

        if (res == JNI_OK) {
            return env;
        }

        if (res == JNI_EDETACHED) {
            res = javaVm->AttachCurrentThread(&env, nullptr);

            __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "javaVm->AttachCurrentThread result %d\n", res);

            if (res == JNI_OK) {
                pthread_setspecific(env_key, env);
                return env;
            }
        }

        return nullptr;
    }

    return static_cast<JNIEnv *>(ptr);
}

void state_change_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on state_change_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct state_change_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void state_change_callback_impl(int state, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on state_change_callback_impl %d\n", state);
    auto callbackContext = reinterpret_cast<struct state_change_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->CallVoidMethod(callbackContext->obj, state_change_callback_method_id, state);
        }
    }
}

void message_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on message_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct message_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void message_callback_impl(int service_type, struct rcs_messaging_session *session, const char *contact_uri, const char *content_type, const char *content_body, const char *imdn_message_id, const char *cpim_date, const char *cpim_from, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on message_callback_impl\n");

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "contact_uri %s\n", contact_uri);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "content_type %s\n", content_type);

    auto callbackContext = reinterpret_cast<struct message_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {

            auto *sessionHandle = static_cast<struct rcs_messaging_session_handle *>(calloc(1, sizeof(struct rcs_messaging_session_handle)));

            sessionHandle->session = session;

            jstring contactUri = env->NewStringUTF(contact_uri);

            jstring contentType = env->NewStringUTF(content_type);

            jstring contentBody = env->NewStringUTF(content_body);

            jstring messageId = env->NewStringUTF(imdn_message_id);

            jstring date = env->NewStringUTF(cpim_date);

            jstring from = nullptr;

            if (cpim_from != nullptr) {
                from = env->NewStringUTF(cpim_from);
            }

            env->CallVoidMethod(callbackContext->obj, message_callback_method_id, service_type, reinterpret_cast<jlong>(sessionHandle), contactUri, contentType, contentBody, messageId, date, from);
        }
    }
}

void multi_conference_v1_invite_handler_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_invite_handler_context_release: %p\n", context);
    auto handlerContext = reinterpret_cast<struct multi_conference_v1_invite_handler_context *>(context);
    if (handlerContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(handlerContext->obj);
        }
        free(handlerContext);
    }
}

static void multi_conference_v1_invite_handler_function_impl(struct rcs_multi_conference_v1 *conference_v1, const char *offer_sdp, size_t offer_sdp_len, struct multi_conference_v1_invite_response_receiver *response_receiver, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_invite_handler_function_impl\n");

    auto handlerContext = reinterpret_cast<struct multi_conference_v1_invite_handler_context *>(context);
    if (handlerContext) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "offer_sdp %.*s\n", (int) offer_sdp_len, offer_sdp);

        auto callbackContext = reinterpret_cast<struct message_callback_context *>(context);
        if (callbackContext) {
            JNIEnv *env = ensure_jni_env();
            if (env) {

                auto *conferenceV1Handle = static_cast<struct rcs_multi_conference_v1_handle *>(calloc(1, sizeof(struct rcs_multi_conference_v1_handle)));

                conferenceV1Handle->conferenceV1 = conference_v1;

                jbyteArray offerSdp = env->NewByteArray(offer_sdp_len);

                env->SetByteArrayRegion(offerSdp, 0, offer_sdp_len,
                                        reinterpret_cast<const jbyte *>(offer_sdp));

                auto *receiverHandle = static_cast<struct multi_conference_v1_invite_response_receiver_handle *>(calloc(1, sizeof (struct multi_conference_v1_invite_response_receiver_handle)));

                receiverHandle->receiver = response_receiver;

                env->CallVoidMethod(callbackContext->obj, multi_conference_v1_invite_handler_method_id, reinterpret_cast<jlong>(conferenceV1Handle), offerSdp, reinterpret_cast<jlong>(receiverHandle));
            }
        }
    }
}

void auto_config_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on auto_config_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct auto_config_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void auto_config_process_callback_impl(int status_code, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on auto_config_process_callback_impl: %d\n", status_code);
    auto callbackContext = reinterpret_cast<struct auto_config_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {

            env->CallVoidMethod(callbackContext->obj, auto_config_progress_callback_method_id, status_code);
        }
    }
}

static void auto_config_result_callback_impl(int status_code, const char *ims_config, const char *rcs_config, const char *extra, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on auto_config_result_callback_impl: %d\n", status_code);
    auto callbackContext = reinterpret_cast<struct auto_config_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring imsConfig = env->NewStringUTF(ims_config);
            jstring rcsConfig = env->NewStringUTF(rcs_config);

            jstring extraString = env->NewStringUTF(extra);

            env->CallVoidMethod(callbackContext->obj, auto_config_result_callback_method_id, status_code, imsConfig, rcsConfig, extraString);
        }
    }
}

void message_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on message_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct message_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void message_result_callback_impl(uint16_t status_code, const char *reason_phrase, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on message_result_callback_impl %d %s\n", status_code, reason_phrase);
    auto callbackContext = reinterpret_cast<struct message_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            env->CallVoidMethod(callbackContext->obj, message_result_callback_method_id, status_code, reason_phrase_string);
        }
    }
}

void send_imdn_report_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on send_imdn_report_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct send_imdn_report_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void send_imdn_report_result_callback_impl(uint16_t status_code, const char *reason_phrase, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on send_imdn_report_result_callback_impl %d %s\n", status_code, reason_phrase);
    auto callbackContext = reinterpret_cast<struct send_imdn_report_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            env->CallVoidMethod(callbackContext->obj, send_imdn_report_result_callback_method_id, status_code, reason_phrase_string);
        }
    }
}

void upload_file_progress_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on upload_file_progress_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct upload_file_progress_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void upload_file_progress_callback_impl(uint32_t current, int32_t total, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on upload_file_progress_callback_impl %d %d\n", current, total);
    auto callbackContext = reinterpret_cast<struct upload_file_progress_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->CallVoidMethod(callbackContext->obj, upload_file_progress_callback_method_id, static_cast<jint>(current), total);
        }
    }
}

void upload_file_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on upload_file_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct upload_file_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void upload_file_result_callback_impl(uint16_t status_code, const char *reason_phrase, const char *xml, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on upload_file_result_callback_impl %d %s\n", status_code, reason_phrase);
    auto callbackContext = reinterpret_cast<struct upload_file_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            jstring xmlString = nullptr;
            if (xml != nullptr) {
                xmlString = env->NewStringUTF(xml);
            }

            env->CallVoidMethod(callbackContext->obj, upload_file_result_callback_method_id, status_code, reason_phrase_string, xmlString);
        }
    }
}

void download_file_progress_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on download_file_progress_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct download_file_progress_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void download_file_progress_callback_impl(uint32_t current, int32_t total, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on download_file_progress_callback_impl %d %d\n", current, total);
    auto callbackContext = reinterpret_cast<struct download_file_progress_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->CallVoidMethod(callbackContext->obj, download_file_progress_callback_method_id, static_cast<jint>(current), total);
        }
    }
}

void download_file_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on download_file_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct download_file_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void download_file_result_callback_impl(uint16_t status_code, const char *reason_phrase, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on download_file_result_callback_impl %d %s\n", status_code, reason_phrase);
    auto callbackContext = reinterpret_cast<struct download_file_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            env->CallVoidMethod(callbackContext->obj, download_file_result_callback_method_id, status_code, reason_phrase_string);
        }
    }
}

void multi_conference_v1_event_listener_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_event_listener_context_release: %p\n", context);
    auto listenerContext = reinterpret_cast<struct multi_conference_v1_event_listener_context *>(context);
    if (listenerContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(listenerContext->obj);
        }
        free(listenerContext);
    }
}

static void multi_conference_v1_event_listener_function_impl (uint16_t event_type, struct rcs_multi_conference_v1_event *event, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_event_listener_function_impl\n");

    auto listenerContext = reinterpret_cast<struct multi_conference_v1_event_listener_context *>(context);
    if (listenerContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            switch (event_type) {
                case rcs_multi_conference_v1_event_type_on_user_joined: {

                    if (event) {
                        char *user_joined = rcs_multi_conference_v1_event_get_user_joined(event);

                        if (user_joined) {

                            jstring j_user_joined = env->NewStringUTF(user_joined);

                            env->CallVoidMethod(listenerContext->obj, multi_conference_v1_event_listener_on_user_joined_method_id, j_user_joined);

                            librust_free_cstring(user_joined);
                        }
                    }

                } break;

                case rcs_multi_conference_v1_event_type_on_user_left: {

                    if (event) {
                        char *user_left = rcs_multi_conference_v1_event_get_user_left(event);

                        if (user_left) {

                            jstring j_user_left = env->NewStringUTF(user_left);

                            env->CallVoidMethod(listenerContext->obj, multi_conference_v1_event_listener_on_user_left_method_id, j_user_left);

                            librust_free_cstring(user_left);
                        }
                    }

                } break;

                default: {

                    env->CallVoidMethod(listenerContext->obj, multi_conference_v1_event_listener_on_conference_ended_method_id);

                } break;
            }
        }
    }

    if (event)
    {
        free_rcs_multi_conference_v1_event(event);
    }
}

void multi_conference_v1_create_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_create_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct multi_conference_v1_create_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void multi_conference_v1_create_result_callback_impl(struct rcs_multi_conference_v1 *conference, const char *sdp, size_t sdp_len, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on multi_conference_v1_create_result_callback_impl\n");

    auto callbackContext = reinterpret_cast<struct multi_conference_v1_create_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {

            auto *nativeHandle = reinterpret_cast<struct rcs_multi_conference_v1_handle *>(calloc(1, sizeof (struct rcs_multi_conference_v1_handle)));

            nativeHandle->conferenceV1 = conference;

            jbyteArray sdp_utf8 = env->NewByteArray(sdp_len);

            env->SetByteArrayRegion(sdp_utf8, 0, sdp_len,
                                    reinterpret_cast<const jbyte *>(sdp));

            env->CallVoidMethod(callbackContext->obj, create_multi_conference_v1_result_callback_method_id, reinterpret_cast<jlong>(nativeHandle), sdp_utf8);
        }
    }
}

void multi_conference_v1_join_result_callback_context_release(void *context)
{
    // stub
}

void retrieve_specific_chatbots_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on retrieve_specific_chatbots_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct retrieve_specific_chatbots_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void retrieve_specific_chatbots_result_callback_impl(uint16_t status_code, const char *reason_phrase, const char *specific_chatbots, const char *response_etag, uint32_t expiry, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on retrieve_specific_chatbots_result_callback_impl %d %s\n", status_code, reason_phrase);

    auto callbackContext = reinterpret_cast<struct retrieve_specific_chatbots_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            jstring specific_chatbots_string = nullptr;
            if (specific_chatbots != nullptr) {
                specific_chatbots_string = env->NewStringUTF(specific_chatbots);
            }

            jstring response_etag_string = nullptr;
            if (response_etag != nullptr) {
                response_etag_string = env->NewStringUTF(response_etag);
            }

            env->CallVoidMethod(callbackContext->obj, retrieve_specific_chatbots_result_callback_method_id, status_code, reason_phrase_string, specific_chatbots_string, response_etag_string, static_cast<jint>(expiry));
        }
    }
}

void search_chatbot_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on search_chatbot_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct search_chatbot_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void search_chatbot_result_callback_impl(uint16_t status_code,  const char *reason_phrase, const char *chatbot_search_result_list_json, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on search_chatbot_result_callback_impl %d %s\n", status_code, reason_phrase);

    auto callbackContext = reinterpret_cast<struct search_chatbot_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            jstring json = nullptr;
            if (chatbot_search_result_list_json != nullptr) {
                json = env->NewStringUTF(chatbot_search_result_list_json);
            }

            env->CallVoidMethod(callbackContext->obj, search_chatbot_result_callback_method_id, status_code, reason_phrase_string, json);
        }
    }
}

void retrieve_chatbot_info_result_callback_context_release(void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on retrieve_chatbot_info_result_callback_context_release: %p\n", context);
    auto callbackContext = reinterpret_cast<struct retrieve_chatbot_info_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            env->DeleteGlobalRef(callbackContext->obj);
        }
        free(callbackContext);
    }
}

static void retrieve_chatbot_info_result_callback_impl(uint16_t status_code,const char *reason_phrase, const char *chatbot_info, const char *response_etag, uint32_t expiry, void *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "on retrieve_chatbot_info_result_callback_impl %d %s\n", status_code, reason_phrase);

    auto callbackContext = reinterpret_cast<struct retrieve_chatbot_info_result_callback_context *>(context);
    if (callbackContext) {
        JNIEnv *env = ensure_jni_env();
        if (env) {
            jstring reason_phrase_string = env->NewStringUTF(reason_phrase);

            jstring chatbot_info_string = nullptr;
            if (chatbot_info != nullptr) {
                chatbot_info_string = env->NewStringUTF(chatbot_info);
            }

            jstring response_etag_string = nullptr;
            if (response_etag != nullptr) {
                response_etag_string = env->NewStringUTF(response_etag);
            }

            env->CallVoidMethod(callbackContext->obj, retrieve_chatbot_info_result_callback_method_id, status_code, reason_phrase_string, chatbot_info_string, response_etag_string, static_cast<jint>(expiry));
        }
    }
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_createRcsClient(JNIEnv *env, __attribute__((unused)) jclass clazz,
                                                                   jint subId, jint mcc, jint mnc,
                                                                   jstring imsi, jstring imei, jstring msisdn, jstring dir,
                                                                   jobject listener) {
    auto *stateChangeCallbackContext = static_cast<struct state_change_callback_context *>(calloc(1, sizeof(struct state_change_callback_context)));

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "created stateChangeCallbackContext %p\n", stateChangeCallbackContext);

    stateChangeCallbackContext->obj = env->NewGlobalRef(listener);

    auto *messageCallbackContext = static_cast<struct message_callback_context *>(calloc(1, sizeof(struct message_callback_context)));

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "created messageCallbackContext %p\n", messageCallbackContext);

    messageCallbackContext->obj = env->NewGlobalRef(listener);

    auto *multiConferenceV1InviteHandlerContext = static_cast<struct multi_conference_v1_invite_handler_context *>(calloc(1, sizeof (struct multi_conference_v1_invite_handler_context)));

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "created multiConferenceV1InviteHandlerContext %p\n", multiConferenceV1InviteHandlerContext);

    multiConferenceV1InviteHandlerContext->obj = env->NewGlobalRef(listener);

    const char *utf_imsi = env->GetStringUTFChars(imsi, nullptr);

    const char *utf_imei = env->GetStringUTFChars(imei, nullptr);

    const char *utf_msisdn = nullptr;

    if (msisdn != nullptr) {
        utf_msisdn = env->GetStringUTFChars(msisdn, nullptr);
    }

    const char *utf_dir = env->GetStringUTFChars(dir, nullptr);

    struct rcs_client *client = new_rcs_client(runtime, subId, mcc, mnc, utf_imsi, utf_imei, utf_msisdn, utf_dir,
                                               state_change_callback_impl, reinterpret_cast<void *>(stateChangeCallbackContext),
                                               message_callback_impl, reinterpret_cast<void *>(messageCallbackContext),
                                               multi_conference_v1_invite_handler_function_impl, reinterpret_cast<void *>(multiConferenceV1InviteHandlerContext));
//    struct rcs_client *client = new_rcs_client(state_change_callback_impl, reinterpret_cast<void *>(callbackContext));

    env->ReleaseStringUTFChars(imsi, utf_imsi);
    env->ReleaseStringUTFChars(imei, utf_imei);
    if (utf_msisdn != nullptr) {
        env->ReleaseStringUTFChars(msisdn, utf_msisdn);
    }
    env->ReleaseStringUTFChars(dir, utf_dir);

    if (client) {
        auto *nativeHandle = static_cast<struct rcs_client_handle *>(calloc(1, sizeof(struct rcs_client_handle)));
        nativeHandle->client = client;
        return reinterpret_cast<jlong>(nativeHandle);
    }

    return 0L;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_startConfig(JNIEnv *env, jclass clazz,
                                                               jlong native_handle,
                                                               jobject listener) {

    auto *callbackContext = static_cast<struct auto_config_callback_context *>(calloc(1, sizeof(struct auto_config_callback_context)));

    callbackContext->obj = env->NewGlobalRef(listener);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        rcs_client_start_config(runtime, nativeHandle->client, auto_config_process_callback_impl, auto_config_result_callback_impl, reinterpret_cast<void *>(callbackContext));
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_inputOtp(JNIEnv *env, jclass clazz,
                                                            jlong native_handle, jstring otp) {

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {

        const char *otp_string = env->GetStringUTFChars(otp, nullptr);

        rcs_client_input_otp(runtime, nativeHandle->client, otp_string);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_setup(JNIEnv *env, jclass clazz,
                                                         jlong native_handle,
                                                         jstring ims_config,
                                                         jstring rcs_config) {

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {

        const char *ims_config_string = env->GetStringUTFChars(ims_config, nullptr);
        const char *rcs_config_string = env->GetStringUTFChars(rcs_config, nullptr);

        rcs_client_setup(runtime, nativeHandle->client, ims_config_string, rcs_config_string);

        env->ReleaseStringUTFChars(ims_config, ims_config_string);
        env->ReleaseStringUTFChars(rcs_config, rcs_config_string);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_connect(__attribute__((unused)) JNIEnv *env, __attribute__((unused)) jclass clazz,
                                                           jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        rcs_client_connect(runtime, nativeHandle->client);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_disconnect(__attribute__((unused)) JNIEnv *env, __attribute__((unused)) jclass clazz,
                                                              jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        rcs_client_disconnect(runtime, nativeHandle->client);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_sendMessage(JNIEnv *env, jclass clazz,
                                                               jlong native_handle,
                                                               jstring message_type, jstring message_content,
                                                               jstring recipient, jint recipient_type,
                                                               jobject listener) {

    auto *callbackContext = static_cast<struct message_result_callback_context *>(calloc(1, sizeof(struct message_result_callback_context)));

    callbackContext->obj = env->NewGlobalRef(listener);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *message_type_string = env->GetStringUTFChars(message_type, nullptr);
        const char *message_content_string = env->GetStringUTFChars(message_content, nullptr);
        const char *recipient_string = env->GetStringUTFChars(recipient, nullptr);

        rcs_client_send_message(runtime, nativeHandle->client, message_type_string, message_content_string, recipient_string, recipient_type, message_result_callback_impl, callbackContext);

        env->ReleaseStringUTFChars(message_type, message_type_string);
        env->ReleaseStringUTFChars(message_content, message_content_string);
        env->ReleaseStringUTFChars(recipient, recipient_string);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_sendImdnReport(JNIEnv *env, jclass clazz,
                                                                  jlong native_handle,
                                                                  jstring imdn_content,
                                                                  jstring sender_uri,
                                                                  jint sender_service_type,
                                                                  jlong sender_session_native_handle,
                                                                  jobject callback) {

    auto *callbackContext = static_cast<struct send_imdn_report_result_callback_context *>(calloc(1, sizeof(struct send_imdn_report_result_callback_context)));

    callbackContext->obj = env->NewGlobalRef(callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *imdn_content_utf8 = env->GetStringUTFChars(imdn_content, nullptr);
        const char *sender_uri_utf8 = env->GetStringUTFChars(sender_uri, nullptr);

        auto sessionHandle = reinterpret_cast<struct rcs_messaging_session_handle *>(sender_session_native_handle);

        rcs_client_send_imdn_report(runtime, nativeHandle->client, imdn_content_utf8, sender_uri_utf8, sender_service_type, sessionHandle->session, send_imdn_report_result_callback_impl, callbackContext);

        env->ReleaseStringUTFChars(imdn_content, imdn_content_utf8);
        env->ReleaseStringUTFChars(sender_uri, sender_uri_utf8);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_uploadFile(JNIEnv *env, jclass clazz,
                                                              jlong native_handle,
                                                              jstring tid,
                                                              jstring file_path,
                                                              jstring file_name,
                                                              jstring file_mime,
                                                              jstring file_hash,
                                                              jstring thumbnail_path,
                                                              jstring thumbnail_name,
                                                              jstring thumbnail_mime,
                                                              jstring thumbnail_hash,
                                                              jobject progress_callback,
                                                              jobject result_callback) {

    auto *progressCallbackContext = static_cast<struct upload_file_progress_callback_context *>(calloc(1, sizeof(struct upload_file_progress_callback_context)));

    progressCallbackContext->obj = env->NewGlobalRef(progress_callback);

    auto *resultCallbackContext = static_cast<struct upload_file_result_callback_context *>(calloc(1, sizeof(struct upload_file_result_callback_context)));

    resultCallbackContext->obj = env->NewGlobalRef(result_callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *tid_utf8 = env->GetStringUTFChars(tid, nullptr);
        const char *file_path_utf8 = env->GetStringUTFChars(file_path, nullptr);
        const char *file_name_utf8 = env->GetStringUTFChars(file_name, nullptr);
        const char *file_mime_utf8 = env->GetStringUTFChars(file_mime, nullptr);
        const char *file_hash_utf8 = nullptr;
        if (file_hash != nullptr) {
            file_hash_utf8 = env->GetStringUTFChars(file_hash, nullptr);
        }

        const char *thumbnail_path_utf8 = nullptr;
        const char *thumbnail_name_utf8 = nullptr;
        const char *thumbnail_mime_utf8 = nullptr;
        const char *thumbnail_hash_utf8 = nullptr;

        if (thumbnail_path != nullptr) {
            thumbnail_path_utf8 = env->GetStringUTFChars(thumbnail_path, nullptr);
        }
        if (thumbnail_name != nullptr) {
            thumbnail_name_utf8 = env->GetStringUTFChars(thumbnail_name, nullptr);
        }
        if (thumbnail_mime != nullptr) {
            thumbnail_mime_utf8 = env->GetStringUTFChars(thumbnail_mime, nullptr);
        }
        if (thumbnail_hash != nullptr) {
            thumbnail_hash_utf8 = env->GetStringUTFChars(thumbnail_hash, nullptr);
        }

        rcs_client_upload_file(runtime, nativeHandle->client, tid_utf8,
                               file_path_utf8, file_name_utf8, file_mime_utf8, file_hash_utf8,
                               thumbnail_path_utf8, thumbnail_name_utf8, thumbnail_mime_utf8, thumbnail_hash_utf8,
                               upload_file_progress_callback_impl, progressCallbackContext,
                               upload_file_result_callback_impl, resultCallbackContext);

        env->ReleaseStringUTFChars(tid, tid_utf8);
        env->ReleaseStringUTFChars(file_path, file_path_utf8);
        env->ReleaseStringUTFChars(file_name, file_name_utf8);
        env->ReleaseStringUTFChars(file_mime, file_mime_utf8);
        if (file_hash_utf8 != nullptr) {
            env->ReleaseStringUTFChars(file_hash, file_hash_utf8);
        }

        if (thumbnail_path_utf8 != nullptr) {
            env->ReleaseStringUTFChars(thumbnail_path, thumbnail_path_utf8);
        }
        if (thumbnail_name_utf8 != nullptr) {
            env->ReleaseStringUTFChars(thumbnail_name, thumbnail_name_utf8);
        }
        if (thumbnail_mime_utf8 != nullptr) {
            env->ReleaseStringUTFChars(thumbnail_mime, thumbnail_mime_utf8);
        }
        if (thumbnail_hash_utf8 != nullptr) {
            env->ReleaseStringUTFChars(thumbnail_hash, thumbnail_hash_utf8);
        }
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_downloadFile(JNIEnv *env, jclass clazz,
                                                                jlong native_handle,
                                                                jstring data_url,
                                                                jstring destination_path,
                                                                int start,
                                                                int total,
                                                                jobject progress_callback,
                                                                jobject result_callback) {

    auto *progressCallbackContext = static_cast<struct download_file_progress_callback_context *>(calloc(1, sizeof(struct download_file_progress_callback_context)));

    progressCallbackContext->obj = env->NewGlobalRef(progress_callback);

    auto *resultCallbackContext = static_cast<struct download_file_result_callback_context *>(calloc(1, sizeof(struct download_file_result_callback_context)));

    resultCallbackContext->obj = env->NewGlobalRef(result_callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *data_url_utf8 = env->GetStringUTFChars(data_url, nullptr);
        const char *destination_path_utf8 = env->GetStringUTFChars(destination_path, nullptr);

        rcs_client_download_file(runtime, nativeHandle->client, data_url_utf8, destination_path_utf8, start, total, download_file_progress_callback_impl, progressCallbackContext, download_file_result_callback_impl, resultCallbackContext);

        env->ReleaseStringUTFChars(data_url, data_url_utf8);
        env->ReleaseStringUTFChars(destination_path, destination_path_utf8);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024MessagingSession_destroy(JNIEnv *env,
                                                                                 jclass clazz,
                                                                                 jlong native_handle) {

    auto *nativeHandle = reinterpret_cast<struct rcs_messaging_session_handle *>(native_handle);
    if (nativeHandle) {
        destroy_rcs_messaging_session(nativeHandle->session);
        free(nativeHandle);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_createMultiConferenceV1(JNIEnv *env,
                                                                           jclass clazz,
                                                                           jlong native_handle,
                                                                           jstring recipients,
                                                                           jstring offer_sdp,
                                                                           jobject event_listener,
                                                                           jobject callback) {
    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {

        const char *recipients_string = env->GetStringUTFChars(recipients, nullptr);
        const char *offer_sdp_string = env->GetStringUTFChars(offer_sdp, nullptr);

        auto listenerContext = reinterpret_cast<struct multi_conference_v1_event_listener_context *>(calloc(1, sizeof (struct multi_conference_v1_event_listener_context)));

        listenerContext->obj = env->NewGlobalRef(event_listener);

        auto callbackContext = reinterpret_cast<struct multi_conference_v1_create_result_callback_context *>(calloc(1, sizeof (struct multi_conference_v1_create_result_callback_context)));

        callbackContext->obj = env->NewGlobalRef(callback);

        rcs_client_create_multi_conference_v1(runtime, nativeHandle->client, recipients_string, offer_sdp_string,
                                              multi_conference_v1_event_listener_function_impl, listenerContext,
                                              nullptr, callbackContext);

        env->ReleaseStringUTFChars(recipients, recipients_string);
        env->ReleaseStringUTFChars(offer_sdp, offer_sdp_string);
    }
}

#pragma mark - Conference

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024MultiConferenceV1_destroy(JNIEnv *env,
                                                                                  jclass clazz,
                                                                                  jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rcs_multi_conference_v1_handle *>(native_handle);
    if (nativeHandle) {
        destroy_rcs_multi_conference(nativeHandle->conferenceV1);
        free(nativeHandle);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024MultiConferenceV1InviteResponseReceiver_sendOkResponse(
        JNIEnv *env, jclass clazz, jlong native_handle, jint status_code, jstring answer_sdp,
        jobject listener) {
    auto *nativeHandle = reinterpret_cast<struct multi_conference_v1_invite_response_receiver_handle *>(native_handle);
    if (nativeHandle) {
        auto *response = reinterpret_cast<struct multi_conference_v1_invite_response *>(calloc(1, sizeof (struct multi_conference_v1_invite_response)));

        response->status_code = status_code;

        const char *utf_answer_sdp = env->GetStringUTFChars(answer_sdp, nullptr);

        response->answer_sdp = utf_answer_sdp;

        auto *listenerContext = reinterpret_cast<struct multi_conference_v1_event_listener_context *>(calloc(1, sizeof (struct multi_conference_v1_event_listener_context)));

        response->event_listener = multi_conference_v1_event_listener_function_impl;
        response->event_listener_context = listenerContext;

        multi_conference_v1_invite_response_receiver_send_response(nativeHandle->receiver, response);

        env->ReleaseStringUTFChars(answer_sdp, utf_answer_sdp);

        free(response);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024MultiConferenceV1InviteResponseReceiver_cancel(
        JNIEnv *env, jclass clazz, jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct multi_conference_v1_invite_response_receiver_handle *>(native_handle);
    if (nativeHandle) {
        multi_conference_v1_invite_response_receiver_send_response(nativeHandle->receiver, nullptr);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024MultiConferenceV1InviteResponseReceiver_free(
        JNIEnv *env, jclass clazz, jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct multi_conference_v1_invite_response_receiver_handle *>(native_handle);
    if (nativeHandle) {
        free_multi_conference_v1_invite_response_receiver(nativeHandle->receiver);
        free(nativeHandle);
    }
}

#pragma mark - Chatbots

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_retrieveSpecificChatbots(JNIEnv *env,
                                                                            jclass clazz,
                                                                            jlong native_handle,
                                                                            jstring local_etag,
                                                                            jobject callback) {

    auto *callbackContext = static_cast<struct retrieve_specific_chatbots_result_callback_context *>(calloc(1, sizeof(struct retrieve_specific_chatbots_result_callback_context)));

    callbackContext->obj = env->NewGlobalRef(callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *local_etag_utf8 = nullptr;
        if (local_etag != nullptr) {
            local_etag_utf8 = env->GetStringUTFChars(local_etag, nullptr);
        }

        rcs_client_retrieve_specific_chatbots(runtime, nativeHandle->client, local_etag_utf8,
                                              retrieve_specific_chatbots_result_callback_impl, callbackContext);

        if (local_etag_utf8 != nullptr) {
            env->ReleaseStringUTFChars(local_etag, local_etag_utf8);
        }
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_searchChatbot(JNIEnv *env, jclass clazz,
                                                                 jlong native_handle, jstring query,
                                                                 jobject callback) {

    auto *callbackContext = static_cast<struct search_chatbot_result_callback_context *>(calloc(1, sizeof(struct search_chatbot_result_callback_context)));

    callbackContext->obj = env->NewGlobalRef(callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *query_string = env->GetStringUTFChars(query, nullptr);

        rcs_client_search_chatbot(runtime, nativeHandle->client, query_string, 0, 16,
                                  search_chatbot_result_callback_impl, callbackContext);

        env->ReleaseStringUTFChars(query, query_string);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_retrieveChatbotInfo(JNIEnv *env, jclass clazz,
                                                                       jlong native_handle,
                                                                       jstring chatbot_sip_uri,
                                                                       jstring local_etag,
                                                                       jobject callback) {

    auto *callbackContext = static_cast<struct retrieve_chatbot_info_result_callback_context *>(calloc(1, sizeof(struct retrieve_chatbot_info_result_callback_context)));

    callbackContext->obj = env->NewGlobalRef(callback);

    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        const char *chatbot_sip_uri_utf8 = env->GetStringUTFChars(chatbot_sip_uri, nullptr);
        const char *local_etag_utf8 = nullptr;
        if (local_etag != nullptr) {
            local_etag_utf8 = env->GetStringUTFChars(local_etag, nullptr);
        }

        rcs_client_retrieve_chatbot_info(runtime, nativeHandle->client, chatbot_sip_uri_utf8, local_etag_utf8,
                                         retrieve_chatbot_info_result_callback_impl, callbackContext);

        env->ReleaseStringUTFChars(chatbot_sip_uri, chatbot_sip_uri_utf8);
        if (local_etag_utf8 != nullptr) {
            env->ReleaseStringUTFChars(local_etag, local_etag_utf8);
        }
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_destroy(__attribute__((unused)) JNIEnv *env, __attribute__((unused)) jclass clazz,
                                                           jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rcs_client_handle *>(native_handle);
    if (nativeHandle) {
        destroy_rcs_client(nativeHandle->client);
        free(nativeHandle);
    }
}

static volatile jobject host_environment = nullptr;

static jmethodID debug_log_method_id = nullptr;
static jmethodID critical_log_method_id = nullptr;

static jmethodID network_request_factory_constructor_method_id = nullptr;

static jmethodID network_request_release_method_id = nullptr;

static jmethodID active_network_factory_constructor_method_id = nullptr;

static jmethodID active_network_get_type_method_id = nullptr;

static jmethodID active_network_get_dns_info_method_id = nullptr;

static jmethodID dns_info_get_server_address_method_id = nullptr;

static jmethodID create_socket_method_id = nullptr;

static jmethodID socket_bind_method_id = nullptr;

static jmethodID socket_configure_tls_method_id = nullptr;

static jmethodID socket_connect_method_id = nullptr;

static jmethodID socket_finish_connect_method_id = nullptr;

static jmethodID socket_start_handshake_method_id = nullptr;

static jmethodID socket_finish_handshake_method_id = nullptr;

static jmethodID read_socket_method_id = nullptr;

static jmethodID write_socket_method_id = nullptr;

static jmethodID shutdown_socket_method_id = nullptr;

static jmethodID close_socket_method_id = nullptr;

static jmethodID get_socket_info_method_id = nullptr;

static jmethodID get_socket_session_cipher_suite_method_id = nullptr;

static jfieldID socket_info_af_field_id = nullptr;

static jfieldID socket_info_l_addr_field_id = nullptr;

static jfieldID socket_info_l_port_field_id = nullptr;

static jfieldID cipher_suite_yy_field_id = nullptr;

static jfieldID cipher_suite_zz_field_id = nullptr;

static jmethodID getIccAuthentication_method_id = nullptr;

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_ApplicationEnvironment_registerHostEnvironment(JNIEnv *env,
                                                                                   jclass clazz,
                                                                                   jobject factory) {
    host_environment = env->NewGlobalRef(factory);

    debug_log_method_id = env->GetStaticMethodID(clazz, "debugLog", "(Ljava/lang/String;Ljava/lang/String;)V");
    critical_log_method_id = env->GetStaticMethodID(clazz, "criticalLog", "(Ljava/lang/String;Ljava/lang/String;)V");

    network_request_factory_constructor_method_id = env->GetMethodID(clazz, "createNetworkRequest",
                                                                     "(J)Lcom/everfrost/rusty/rcs/client/ApplicationEnvironment$CellularNetworkRequest;");

    jclass networkRequestClass = env->FindClass("com/everfrost/rusty/rcs/client/ApplicationEnvironment$CellularNetworkRequest");

    network_request_release_method_id = env->GetMethodID(networkRequestClass, "release", "()V");

    active_network_factory_constructor_method_id = env->GetMethodID(clazz, "getCurrentActiveNetwork", "()Landroid/net/Network;");

    active_network_get_type_method_id = env->GetMethodID(clazz, "getNetworkType", "(Landroid/net/Network;)I");

    active_network_get_dns_info_method_id = env->GetMethodID(clazz, "getDnsInfoFromNetwork",
                                                             "(Landroid/net/Network;)Lcom/everfrost/rusty/rcs/client/ApplicationEnvironment$DnsInfo;");

    jclass dnsInfoClass = env->FindClass("com/everfrost/rusty/rcs/client/ApplicationEnvironment$DnsInfo");

    dns_info_get_server_address_method_id = env->GetMethodID(dnsInfoClass, "getNextServerAddress", "()Ljava/lang/String;");

    create_socket_method_id = env->GetMethodID(clazz, "createSocket",
                                               "()Lcom/everfrost/rusty/rcs/client/ApplicationEnvironment$AsyncSocket;");

    jclass socketClass = env->FindClass("com/everfrost/rusty/rcs/client/ApplicationEnvironment$AsyncSocket");

    socket_bind_method_id = env->GetMethodID(socketClass, "bind", "(Ljava/lang/String;I)I");

    socket_configure_tls_method_id = env->GetMethodID(socketClass, "setupTls", "(Ljava/lang/String;)I");

    socket_connect_method_id = env->GetMethodID(socketClass, "connect", "(Ljava/lang/String;I)I");

    socket_finish_connect_method_id = env->GetMethodID(socketClass, "finishConnect", "(J)I");

    socket_start_handshake_method_id = env->GetMethodID(socketClass, "startHandshake", "()I");

    socket_finish_handshake_method_id = env->GetMethodID(socketClass, "finishHandshake", "(J)I");

    read_socket_method_id = env->GetMethodID(socketClass, "read", "([BJ)I");

    write_socket_method_id = env->GetMethodID(socketClass, "write", "([BJ)I");

    shutdown_socket_method_id = env->GetMethodID(socketClass, "shutDown", "(J)I");

    close_socket_method_id = env->GetMethodID(socketClass, "close", "()V");

    get_socket_info_method_id = env->GetMethodID(socketClass, "getSocketInfo",
                                                 "()Lcom/everfrost/rusty/rcs/client/ApplicationEnvironment$AsyncSocket$SocketInfo;");

    get_socket_session_cipher_suite_method_id = env->GetMethodID(socketClass, "getSessionCipherSuite", "()Lcom/everfrost/rusty/rcs/client/ApplicationEnvironment$CipherSuiteCoding;");

    jclass socketInfoClass = env->FindClass("com/everfrost/rusty/rcs/client/ApplicationEnvironment$AsyncSocket$SocketInfo");

    socket_info_af_field_id = env->GetFieldID(socketInfoClass, "af", "I");

    socket_info_l_addr_field_id = env->GetFieldID(socketInfoClass, "lAddr", "Ljava/lang/String;");

    socket_info_l_port_field_id = env->GetFieldID(socketInfoClass, "lPort", "I");

    jclass cipherSuiteCodingClass = env->FindClass("com/everfrost/rusty/rcs/client/ApplicationEnvironment$CipherSuiteCoding");

    cipher_suite_yy_field_id = env->GetFieldID(cipherSuiteCodingClass, "yy", "B");
    cipher_suite_zz_field_id = env->GetFieldID(cipherSuiteCodingClass, "zz", "B");

    getIccAuthentication_method_id = env->GetMethodID(clazz, "getIccAuthentication", "([BI)[B");
}


#pragma mark - Platform

void platform_log_impl(const char *tag, const char *message)
{
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jclass clazz = env->GetObjectClass(host_environment);

        jstring t = env->NewStringUTF(tag);
        jstring m = env->NewStringUTF(message);

        env->CallStaticVoidMethod(clazz, debug_log_method_id, t, m);
    }
}

void platform_critical_log_impl(const char *tag, const char *message)
{
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jclass clazz = env->GetObjectClass(host_environment);

        jstring t = env->NewStringUTF(tag);
        jstring m = env->NewStringUTF(message);

        env->CallStaticVoidMethod(clazz, critical_log_method_id, t, m);
    }
}

int platform_icc_open_channel(void *aid_bytes, size_t aid_size)
{
    return 0;
}

void *platform_icc_exchange_apdu(int channel, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t p3, void *in_data, size_t in_size, size_t *out_size)
{
    return nullptr;
}

void platform_icc_close_channel(int channel)
{

}


struct network_request {
    jobject obj;
    struct network_request_listener *listener;
};

struct network_request_listener {
    void *context;
    activate_cellular_network_callback *callback;
};

struct network_request *platform_activate_cellular_network(void *context, activate_cellular_network_callback callback) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        auto listener = static_cast<struct network_request_listener *>(calloc(1, sizeof(struct network_request_listener)));
        listener->context = context;
        listener->callback = callback;
        auto listener_handle = reinterpret_cast<long>(listener);
        jobject r = env->CallObjectMethod(host_environment, network_request_factory_constructor_method_id, listener_handle);
        if (r) {
            auto request = static_cast<struct network_request *>(calloc(1, sizeof(struct network_request)));
            request->listener = listener;
            request->obj = env->NewGlobalRef(r);
            return request;
        } else {
            free(listener);
        }
    }

    return nullptr;
}

void platform_drop_network_request(struct network_request *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->CallVoidMethod(c_handle->obj, network_request_release_method_id);
        env->DeleteGlobalRef(c_handle->obj);
        if (c_handle->listener) {
            free(c_handle->listener);
        }
        free(c_handle);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_ApplicationEnvironment_00024CellularNetworkRequestListener_onResult(
        __attribute__((unused)) JNIEnv *env, __attribute__((unused)) jclass clazz, jlong native_handle, jboolean activated) {
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, activated ? "network available\n" : "network lost\n");
    auto listener = reinterpret_cast<struct network_request_listener *>(native_handle);
    if (listener->callback) {
        listener->callback(listener->context, activated);
    }
}

struct network_info {
    jobject obj;
};

struct network_info *platform_get_active_network_info() {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject r = env->CallObjectMethod(host_environment, active_network_factory_constructor_method_id);
        if (r) {
            auto networkInfo = static_cast<struct network_info *>(calloc(1, sizeof (struct network_info)));
            networkInfo->obj = env->NewGlobalRef(r);
            return networkInfo;
        }
    }

    return nullptr;
}

int platform_get_network_type(struct network_info *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        return env->CallIntMethod(host_environment, active_network_get_type_method_id, c_handle->obj);
    }

    return 0;
}

struct dns_info {
    jobject obj;
};

struct dns_info *platform_get_network_dns_info(struct network_info *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject r = env->CallObjectMethod(host_environment, active_network_get_dns_info_method_id, c_handle->obj);
        if (r) {
            auto dnsInfo = static_cast<struct dns_info *>(calloc(1, sizeof (struct dns_info)));
            dnsInfo->obj = env->NewGlobalRef(r);
            return dnsInfo;
        }
    }

    return nullptr;
}

const char *platform_get_dns_server(struct dns_info *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject r = env->CallObjectMethod(c_handle->obj, dns_info_get_server_address_method_id);
        if (r) {
            auto address = (jstring) r;

            jsize address_length = env->GetStringUTFLength(address);
            const char *address_string = env->GetStringUTFChars(address, nullptr);

            __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "DnsInfo.getNextServerAddress() returns %s\n", address_string);

            char *copied = static_cast<char *>(calloc(address_length + 1, sizeof(char)));
            memcpy(copied, address_string, address_length);

            env->ReleaseStringUTFChars(address, address_string);

            return copied;
        }
    }

    return nullptr;
}

void platform_drop_dns_info(struct dns_info *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->DeleteGlobalRef(c_handle->obj);
        free(c_handle);
    }
}

void platform_drop_network_info(struct network_info *c_handle) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->DeleteGlobalRef(c_handle->obj);
        free(c_handle);
    }
}

socklen_t platform_get_inaddr_any(struct sockaddr_storage *c_struct) {
    auto *addr = reinterpret_cast<struct sockaddr_in *>(c_struct);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    return sizeof (struct sockaddr_in);
}

socklen_t platform_get_in6addr_any(struct sockaddr_storage *c_struct) {
    auto *addr = reinterpret_cast<struct sockaddr_in6 *>(c_struct);
    addr->sin6_family = AF_INET6;
    addr->sin6_addr = in6addr_any;
    return sizeof (struct sockaddr_in6);
}

char *platform_ntop(int af, struct sockaddr_storage c_struct) {
    char *addr = nullptr;
    if (af == AF_INET6) {
        addr = static_cast<char *>(calloc(INET6_ADDRSTRLEN + 1, sizeof(char)));
        inet_ntop(af, &c_struct, addr, sizeof (struct sockaddr_in6));
    } else if (af == AF_INET) {
        addr = static_cast<char *>(calloc(INET_ADDRSTRLEN + 1, sizeof(char)));
        inet_ntop(af, &c_struct, addr, sizeof (struct sockaddr_in));
    }
    return addr;
}

int platform_pton(int af, const char *network_address, struct sockaddr_storage *c_struct) {
    return inet_pton(af, network_address, c_struct);
}

struct platform_socket {
    jobject obj;
};

struct platform_socket *platform_create_socket() {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_create_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {

        jobject r = env->CallObjectMethod(host_environment, create_socket_method_id);

        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "createSocket() returns %p\n", r);

        if (r) {
            auto *handle = static_cast<platform_socket *>(calloc(1, sizeof(struct platform_socket)));

            handle->obj = env->NewGlobalRef(r);

            return handle;
        }
    }

    return nullptr;
}

int platform_socket_bind(struct platform_socket *sock, const char *l_addr, uint16_t l_port) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_bind\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {

        jstring localAddress = env->NewStringUTF(l_addr);

        jint r = env->CallIntMethod(sock->obj, socket_bind_method_id, localAddress, l_port);

        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "setupTls() returns %d\n", r);

        return r;
    }

    return EINVAL;
}

int platform_socket_configure_tls(struct platform_socket *sock, const char *host_name) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_configure_tls\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {

        jstring hostName = env->NewStringUTF(host_name);

        jint r = env->CallIntMethod(sock->obj, socket_configure_tls_method_id, hostName);

        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "setupTls() returns %d\n", r);

        return r;
    }

    return EINVAL;
}

int platform_socket_connect(struct platform_socket *sock, const char *r_addr, u_int16_t r_port) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_connect\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {

        jstring rAddr = env->NewStringUTF(r_addr);

        return env->CallIntMethod(sock->obj, socket_connect_method_id, rAddr, r_port);
    }

    return -1;
}

int platform_socket_finish_connect(struct platform_socket *sock, struct rust_async_waker *waker) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_finish_connect\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        struct rust_async_waker_handle *wakerHandle;
        if (waker) {
            wakerHandle = static_cast<rust_async_waker_handle *>(calloc(1,
                                                                        sizeof(struct rust_async_waker_handle)));

            wakerHandle->waker = waker;
        } else {
            wakerHandle = nullptr;
        }

        auto handle = reinterpret_cast<jlong>(wakerHandle);

        int r = env->CallIntMethod(sock->obj, socket_finish_connect_method_id, handle);
        if (r == 114) {
            return EALREADY;
        }
        return r;
    }

    return -1;
}

int platform_socket_start_handshake(struct platform_socket *sock) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_start_handshake\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        return env->CallIntMethod(sock->obj, socket_start_handshake_method_id);
    }

    return -1;
}

int platform_socket_finish_handshake(struct platform_socket *sock, struct rust_async_waker *waker) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_socket_finish_handshake\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        struct rust_async_waker_handle *wakerHandle;
        if (waker) {
            wakerHandle = static_cast<rust_async_waker_handle *>(calloc(1,
                                                                        sizeof(struct rust_async_waker_handle)));

            wakerHandle->waker = waker;
        } else {
            wakerHandle = nullptr;
        }

        auto handle = reinterpret_cast<jlong>(wakerHandle);

        int r = env->CallIntMethod(sock->obj, socket_finish_handshake_method_id, handle);
        if (r == 114) {
            return EALREADY;
        }
        return r;
    }

    return -1;
}

int platform_read_socket(struct platform_socket *sock, struct rust_async_waker *waker, void *buffer, size_t buffer_len, size_t *bytes_read) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_read_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        struct rust_async_waker_handle *wakerHandle;
        if (waker) {
            wakerHandle = static_cast<rust_async_waker_handle *>(calloc(1,
                                                                        sizeof(struct rust_async_waker_handle)));

            wakerHandle->waker = waker;
        } else {
            wakerHandle = nullptr;
        }

        auto handle = reinterpret_cast<jlong>(wakerHandle);

        jbyteArray jBuffer = env->NewByteArray(buffer_len);

        jint ret = env->CallIntMethod(sock->obj, read_socket_method_id, jBuffer, handle);

        if (ret > 0) {
            env->GetByteArrayRegion(jBuffer, 0, ret, reinterpret_cast<jbyte *>(buffer));
            *bytes_read = ret;
            return 0;
        }

        if (ret == 0) {
            return EAGAIN;
        } else if (ret == -11) {
            *bytes_read = 0;
            return 0;
        } else {
            return ECONNRESET;
        }
    }

    return ENOTSUP;
}

int platform_write_socket(struct platform_socket *sock, struct rust_async_waker *waker, void *buffer, size_t buffer_len, size_t *bytes_written) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_write_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        struct rust_async_waker_handle *wakerHandle;
        if (waker) {
            wakerHandle = static_cast<rust_async_waker_handle *>(calloc(1,
                                                                        sizeof(struct rust_async_waker_handle)));

            wakerHandle->waker = waker;
        } else {
            wakerHandle = nullptr;
        }

        auto handle = reinterpret_cast<jlong>(wakerHandle);

        jbyteArray bytes = env->NewByteArray(buffer_len);

        env->SetByteArrayRegion(bytes, 0, buffer_len, reinterpret_cast<const jbyte *>(buffer));

        int r = env->CallIntMethod(sock->obj, write_socket_method_id, bytes, handle);

        if (r > 0) {
            *bytes_written = r;
            return 0;
        }

        if (r == 0) {
            return EAGAIN;
        } else {
            return ECONNRESET;
        }
    }

    return ENOTSUP;
}

int platform_shutdown_socket(struct platform_socket *sock, struct rust_async_waker *waker) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_shutdown_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        struct rust_async_waker_handle *wakerHandle;
        if (waker) {
            wakerHandle = static_cast<rust_async_waker_handle *>(calloc(1,
                                                                        sizeof(struct rust_async_waker_handle)));

            wakerHandle->waker = waker;
        } else {
            wakerHandle = nullptr;
        }

        auto handle = reinterpret_cast<jlong>(wakerHandle);

        int r = env->CallIntMethod(sock->obj, shutdown_socket_method_id, handle);

        if (r == 114) {
            return EALREADY;
        }

        return r;
    }

    return ENOTSUP;
}

void platform_close_socket(struct platform_socket *sock) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_close_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {

        env->CallVoidMethod(sock->obj, close_socket_method_id);
    }
}

void platform_free_socket(struct platform_socket *sock) {

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "platform_free_socket\n");

    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->DeleteGlobalRef(sock->obj);
        free(sock);
    }
}

struct platform_socket_info {
    jobject obj;
};

struct platform_socket_info *platform_get_socket_info(struct platform_socket *sock) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject r = env->CallObjectMethod(sock->obj, get_socket_info_method_id);
        if (r) {
            auto socketInfo = static_cast<struct platform_socket_info *>(calloc(1, sizeof (struct platform_socket_info)));
            socketInfo->obj = env->NewGlobalRef(r);
            return socketInfo;
        }
    }

    return nullptr;
}

int platform_get_socket_af(struct platform_socket_info *sock_info) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        return env->GetIntField(sock_info->obj, socket_info_af_field_id);
    }

    return 0;
}

const char *platform_get_socket_l_addr(struct platform_socket_info *sock_info) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject lAddr = env->GetObjectField(sock_info->obj, socket_info_l_addr_field_id);

        if (lAddr) {
            auto lAddrString = (jstring) lAddr;

            jsize address_length = env->GetStringUTFLength(lAddrString);
            const char *address_string = env->GetStringUTFChars(lAddrString, nullptr);

            char *copied = static_cast<char *>(calloc(address_length + 1, sizeof(char)));
            memcpy(copied, address_string, address_length);

            env->ReleaseStringUTFChars(lAddrString, address_string);

            return copied;
        }
    }

    return nullptr;
}

uint16_t platform_get_socket_l_port(struct platform_socket_info *sock_info) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        return env->GetIntField(sock_info->obj, socket_info_l_port_field_id);
    }

    return 0;
}

void platform_free_socket_info(struct platform_socket_info *sock_info) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->DeleteGlobalRef(sock_info->obj);
        free(sock_info);
    }
}

struct platform_cipher_suite {
    jobject obj;
};

struct platform_cipher_suite *platform_get_socket_session_cipher_suite(struct platform_socket *sock) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        jobject r = env->CallObjectMethod(sock->obj, get_socket_session_cipher_suite_method_id);
        if (r) {
            auto socketInfo = static_cast<struct platform_cipher_suite *>(calloc(1, sizeof (struct platform_cipher_suite)));
            socketInfo->obj = env->NewGlobalRef(r);
            return socketInfo;
        }
    }

    return nullptr;
}

uint8_t platform_cipher_suite_get_yy(struct platform_cipher_suite *cipher_suite) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        jbyte yy = env->GetByteField(cipher_suite->obj, cipher_suite_yy_field_id);
        return ((int) yy) & 0xFF;
    }

    return 0;
}

uint8_t platform_cipher_suite_get_zz(struct platform_cipher_suite *cipher_suite) {

    JNIEnv *env = ensure_jni_env();
    if (env) {
        jbyte zz = env->GetByteField(cipher_suite->obj, cipher_suite_zz_field_id);
        return ((int) zz) & 0xFF;
    }

    return 0;
}

void platform_free_cipher_suite(struct platform_cipher_suite *cipher_suite) {
    JNIEnv *env = ensure_jni_env();
    if (env) {
        env->DeleteGlobalRef(cipher_suite->obj);
        free(cipher_suite);
    }
}

void *platform_perform_aka(int subscription_id, void *in_data, size_t in_size, size_t *out_size)
{
    JNIEnv *env = ensure_jni_env();
    if (env) {
        jbyteArray data = env->NewByteArray(in_size);

        env->SetByteArrayRegion(data, 0, in_size, reinterpret_cast<const jbyte *>(in_data));

        auto ret = (jbyteArray) env->CallObjectMethod(host_environment,
                                                      getIccAuthentication_method_id,
                                                      data, subscription_id);

        if (ret) {

            jsize size = env->GetArrayLength(ret);

            if (size > 0) {

                auto *ret_data = static_cast<jbyte *>(calloc(size, sizeof(jbyte)));

                env->GetByteArrayRegion(ret, 0, size, ret_data);

                *out_size = size;

                return ret_data;
            }
        }
    }

    return nullptr;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024AsyncLatchHandle_wakeUp(
        JNIEnv *env, jclass clazz, jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rust_async_waker_handle *>(native_handle);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI wake up %p\n", nativeHandle);
    if (nativeHandle) {
        rust_async_wake_up(nativeHandle->waker);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_everfrost_rusty_rcs_client_RustyRcsClient_00024AsyncLatchHandle_destroy(
        JNIEnv *env, jclass clazz, jlong native_handle) {
    auto *nativeHandle = reinterpret_cast<struct rust_async_waker_handle *>(native_handle);
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "JNI destroy %p\n", nativeHandle);
    if (nativeHandle) {
        rust_async_destroy_waker(nativeHandle->waker);
        free(nativeHandle);
    }
}
