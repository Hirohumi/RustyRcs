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

// async

struct rust_async_waker;

extern void rust_async_wake_up(struct rust_async_waker *waker);
extern void rust_async_destroy_waker(struct rust_async_waker *waker);
