#include <stddef.h>
#include <stdint.h>

struct rcs_runtime;
struct rcs_client;

#define rcs_multi_conference_v1_event_type_on_user_joined 0
#define rcs_multi_conference_v1_event_type_on_user_left 1
#define rcs_multi_conference_v1_event_type_on_conference_ended 2

struct rcs_messaging_session;

struct rcs_multi_conference_v1;
struct rcs_multi_conference_v1_event;

extern struct rcs_runtime *new_rcs_runtime();

typedef void (*state_change_callback) (int state, void *context);

void state_change_callback_context_release(void *context);

#define rcs_message_service_cpm_one_to_one 0
#define rcs_message_service_cpm_standalone 1
#define rcs_message_service_deferred_one_to_one 2

typedef void (*message_callback) (int service_type, struct rcs_messaging_session *session,
                                  const char *contact_uri, const char *content_type, const char *content_body,
                                  const char *imdn_message_id, const char *cpim_date, const char *cpim_from,
                                  void *context);

void message_callback_context_release(void *context);

typedef void (*multi_conference_v1_event_listener_function) (uint16_t event_type, struct rcs_multi_conference_v1_event *event, void *context);

struct multi_conference_v1_invite_response {
    uint16_t status_code;
    const char *answer_sdp;
    multi_conference_v1_event_listener_function event_listener;
    void *event_listener_context;
};

struct multi_conference_v1_invite_response_receiver;

extern void multi_conference_v1_invite_response_receiver_send_response(struct multi_conference_v1_invite_response_receiver *receiver, struct multi_conference_v1_invite_response *response);

extern void free_multi_conference_v1_invite_response_receiver(struct multi_conference_v1_invite_response_receiver *receiver);

typedef void (*multi_conference_v1_invite_handler_function) (struct rcs_multi_conference_v1 *conference, const char *offer_sdp, size_t offer_sdp_len, struct multi_conference_v1_invite_response_receiver *response_receiver, void *context);

void multi_conference_v1_invite_handler_context_release(void *context);

extern struct rcs_client *new_rcs_client(struct rcs_runtime *runtime, int32_t subscription_id, uint16_t mcc, uint16_t mnc, const char *imsi, const char *imei, const char *msisdn, const char *fs_root_dir, state_change_callback state_cb, void *state_cb_context, message_callback message_cb, void *message_cb_context, multi_conference_v1_invite_handler_function multi_conference_v1_invite_handler, void *multi_conference_v1_invite_handler_context);

typedef void (*auto_config_process_callback) (int32_t status_code, void *context);

typedef void (*auto_config_result_callback) (int32_t status_code, const char *ims_config, const char *rcs_config, const char *extra, void *context);

void auto_config_callback_context_release(void *context);

// configuration
extern void rcs_client_start_config(struct rcs_runtime *runtime, struct rcs_client *client, auto_config_process_callback p_cb, auto_config_result_callback r_cb, void *context);

extern void rcs_client_input_otp(struct rcs_runtime *runtime, struct rcs_client *client, const char *otp);

extern void rcs_client_setup(struct rcs_runtime *runtime, struct rcs_client *client, const char *ims_config, const char *rcs_config);

extern void rcs_client_connect(struct rcs_runtime *runtime, struct rcs_client *client);

extern void rcs_client_disconnect(struct rcs_runtime *runtime, struct rcs_client *client);

// messaging
typedef void (*message_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void message_result_callback_context_release(void *context);

extern void rcs_client_send_message(struct rcs_runtime *runtime, struct rcs_client *client, const char *message_type, const char *message_content, const char *recipient,
                                    bool recipient_is_chatbot,
                                    message_result_callback cb, void *context);

typedef void (*send_imdn_report_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void send_imdn_report_result_callback_context_release(void *context);

extern void rcs_client_send_imdn_report(struct rcs_runtime *runtime, struct rcs_client *client,
                                        const char *imdn_content, const char *sender_uri, int sender_service_type, struct rcs_messaging_session *session,
                                        send_imdn_report_result_callback callback, void *context);

typedef void (*upload_file_result_callback) (uint16_t status_code, const char *reason_phrase, const char *result_xml, void *context);

void upload_file_result_callback_context_release(void *context);

extern void rcs_client_upload_file(struct rcs_runtime *runtime, struct rcs_client *client, const char *tid,
                                   const char *file_path, const char *file_mime, const char *file_hash,
                                   const char *thumbnail_path, const char *thumbnail_mime, const char *thumbnail_hash,
                                   upload_file_result_callback cb, void *context);

typedef void (*download_file_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void download_file_result_callback_context_release(void *context);

extern void rcs_client_download_file(struct rcs_runtime *runtime, struct rcs_client *client,
                                     const char *file_uri, const char *download_path, size_t start, size_t total,
                                     download_file_result_callback cb, void *context);

extern void destroy_rcs_messaging_session(struct rcs_messaging_session *session);

// conference
extern char *rcs_multi_conference_v1_event_get_user_joined(struct rcs_multi_conference_v1_event *event);

extern char *rcs_multi_conference_v1_event_get_user_left(struct rcs_multi_conference_v1_event *event);

extern void free_rcs_multi_conference_v1_event(struct rcs_multi_conference_v1_event *event);

void multi_conference_v1_event_listener_context_release(void *context);

typedef void (*multi_conference_v1_create_result_callback) (struct rcs_multi_conference_v1 *conference, const char *sdp, size_t sdp_len, void *context);

void multi_conference_v1_create_result_callback_context_release(void *context);

extern void rcs_client_create_multi_conference_v1(struct rcs_runtime *runtime, struct rcs_client *client, const char *recipients, const char *offer_sdp, multi_conference_v1_event_listener_function event_listener, void *event_listener_context, multi_conference_v1_create_result_callback result_callback, void *result_callback_context);

typedef void (*multi_conference_v1_join_result_callback) (struct rcs_multi_conference_v1 *conference, const char *sdp, size_t sdp_len, void *context);

void multi_conference_v1_join_result_callback_context_release(void *context);

extern void rcs_client_join_multi_conference_v1(struct rcs_runtime *runtime, struct rcs_client *client, const char *conference_id, const char *offer_sdp, multi_conference_v1_event_listener_function event_listener, void *event_listener_context, multi_conference_v1_join_result_callback result_callback, void *result_callback_context);

extern void rcs_multi_conference_v1_keep_alive(struct rcs_runtime *runtime, struct rcs_multi_conference_v1 *conference);

extern void destroy_rcs_multi_conference(struct rcs_multi_conference_v1 *conference);

// extern void rcs_multi_conference_invite_more();

// extern void rcs_multi_conference_get_updated_info();

typedef void (*retrieve_specific_chatbots_result_callback) (uint16_t status_code, const char *reason_phrase, const char *specific_chatbots, const char *response_etag, uint32_t expiry, void *context);

void retrieve_specific_chatbots_result_callback_context_release(void *context);

extern void rcs_client_retrieve_specific_chatbots(struct rcs_runtime *runtime, struct rcs_client *client, const char *local_etag, retrieve_specific_chatbots_result_callback cb, void *context);

typedef void (*search_chatbot_result_callback) (uint16_t status_code, const char *reason_phrase, const char *chatbot_search_result_list_json, void *context);

void search_chatbot_result_callback_context_release(void *context);

extern void rcs_client_search_chatbot(struct rcs_runtime *runtime, struct rcs_client *client, const char *query, uint32_t start, uint32_t num, search_chatbot_result_callback cb, void *context);

typedef void (*retrieve_chatbot_info_result_callback) (uint16_t status_code, const char *reason_phrase, const char *chatbot_info, const char *response_etag, uint32_t expiry, void *context);

void retrieve_chatbot_info_result_callback_context_release(void *context);

extern void rcs_client_retrieve_chatbot_info(struct rcs_runtime *runtime, struct rcs_client *client, const char *chatbot_sip_uri, const char *local_etag, retrieve_chatbot_info_result_callback cb, void *context);

// destroy
extern void destroy_rcs_client(struct rcs_client *client);
