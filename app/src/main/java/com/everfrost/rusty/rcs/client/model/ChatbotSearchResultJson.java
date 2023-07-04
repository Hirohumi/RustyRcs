/*
 *    Copyright 2023 宋昊文
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.everfrost.rusty.rcs.client.model;

import androidx.annotation.NonNull;

public class ChatbotSearchResultJson {

    public static class BotsJson {

        public String id;

        public String name;

        public String icon;

        public boolean verified;

        public String sms;

        public String email;

        public String version;

        public String provider;

        public String website;

        public String description;

        BotsJson() {

        }

        @NonNull
        @Override
        public String toString() {
            return "BotsJson{" +
                    "id='" + id + '\'' +
                    ", name='" + name + '\'' +
                    ", icon='" + icon + '\'' +
                    ", verified=" + verified +
                    ", sms='" + sms + '\'' +
                    ", email='" + email + '\'' +
                    ", version='" + version + '\'' +
                    ", provider='" + provider + '\'' +
                    ", website='" + website + '\'' +
                    ", description='" + description + '\'' +
                    '}';
        }
    }

    private BotsJson[] bots;

    /**
     * CMCC compatibility
     */
    private BotsJson[] botsprofile;

    /**
     * CMCC recommend bots
     */
    private BotsJson[] recommendBots;

    public int itemsReturned;

    public int startIndex;

    public int totalItems;

    ChatbotSearchResultJson() {

    }

    public BotsJson[] getBots() {

        return bots != null && bots.length != 0 ? bots : botsprofile;
    }

    public BotsJson[] getRecommendBots() {

        return recommendBots;
    }
}
