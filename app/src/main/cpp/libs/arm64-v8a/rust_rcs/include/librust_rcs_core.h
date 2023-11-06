/*
 * Copyright 2023 宋昊文
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

// linxu sock
socklen_t platform_get_inaddr_any(struct sockaddr_storage *c_struct);
socklen_t platform_get_in6addr_any(struct sockaddr_storage *c_struct);
char *platform_ntop(int af, struct sockaddr_storage c_struct);
int platform_pton(int af, const char *network_address, struct sockaddr_storage *c_struct);

// android sock
struct platform_socket;

struct socket_event_receiver;

struct platform_socket *platform_create_socket(struct socket_event_receiver *receiver, bool use_tls, const char *host_name);
int platform_socket_connect(struct platform_socket *sock, const char *r_addr, u_int16_t r_port);
int platform_socket_finish_connect(struct platform_socket *sock);
int platform_socket_start_handshake(struct platform_socket *sock);
int platform_socket_finish_handshake(struct platform_socket *sock);
int platform_read_socket(struct platform_socket *sock, void *buffer, size_t buffer_len, size_t *bytes_read);
int platform_write_socket(struct platform_socket *sock, void *buffer, size_t buffer_len, size_t *bytes_written);
void platform_close_socket(struct platform_socket *sock);
void platform_free_socket(struct platform_socket *sock);

struct platform_socket_info;

struct platform_socket_info *platform_get_socket_info(struct platform_socket *sock);
int platform_get_socket_af(struct platform_socket_info *sock_info);
const char *platform_get_socket_l_addr(struct platform_socket_info *sock_info);
uint16_t platform_get_socket_l_port(struct platform_socket_info *sock_info);
void platform_free_socket_info(struct platform_socket_info *sock_info);

struct platform_cipher_suite;

struct platform_cipher_suite *platform_get_socket_session_cipher_suite(struct platform_socket *sock);
uint8_t platform_cipher_suite_get_yy(struct platform_cipher_suite *cipher_suite);
uint8_t platform_cipher_suite_get_zz(struct platform_cipher_suite *cipher_suite);
void platform_free_cipher_suite(struct platform_cipher_suite *cipher_suite);

extern void socket_event_on_connect_avaliable(struct socket_event_receiver *receiver);
extern void socket_event_on_handshake_avaliable(struct socket_event_receiver *receiver);
extern void socket_event_on_read_avaliable(struct socket_event_receiver *receiver);
extern void socket_event_on_write_avaliable(struct socket_event_receiver *receiver);

extern void destroy_socket_event_receiver(struct socket_event_receiver *receiver);
