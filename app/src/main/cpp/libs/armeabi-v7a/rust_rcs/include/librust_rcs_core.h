#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

// str
extern void librust_free_cstring(char *cstr);

// log
void platform_log_impl(const char *tag, const char *message);

// icc
int platform_icc_open_channel(void *aid_bytes, size_t aid_size);
void *platform_icc_exchange_apdu(int channel, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t p3, void *in_data, size_t in_size, size_t *out_size);
void platform_icc_close_channel(int channel);

// aka
void *platform_perform_aka(int subscription_id, void *in_data, size_t in_size, size_t *out_size);

// netctrl
typedef void *activate_cellular_network_callback(void *context, bool activated);

struct network_request;
struct network_request *platform_activate_cellular_network(void *context, activate_cellular_network_callback callback);
void platform_drop_network_request(struct network_request *c_handle);

struct network_info;
struct network_info *platform_get_active_network_info();

int platform_get_network_type(struct network_info *c_handle);

struct dns_info;
struct dns_info *platform_get_network_dns_info(struct network_info *c_handle);
const char *platform_get_dns_server(struct dns_info *c_handle);
void platform_drop_dns_info(struct dns_info *c_handle);

void platform_drop_network_info(struct network_info *c_handle);

// sock
socklen_t platform_get_inaddr_any(struct sockaddr_storage *c_struct);
socklen_t platform_get_in6addr_any(struct sockaddr_storage *c_struct);
char *platform_ntop(int af, struct sockaddr_storage c_struct);
int platform_pton(int af, const char *network_address, struct sockaddr_storage *c_struct);