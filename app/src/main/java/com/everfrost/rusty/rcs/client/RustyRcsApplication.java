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

package com.everfrost.rusty.rcs.client;

import android.app.Application;

import com.everfrost.rusty.rcs.client.utils.log.LogService;

public class RustyRcsApplication extends Application {

    private ApplicationEnvironment applicationEnvironment;

    @Override
    public void onCreate() {
        super.onCreate();

        LogService.init(this);

        applicationEnvironment = new ApplicationEnvironment(this);

        ApplicationEnvironment.registerHostEnvironment(applicationEnvironment);
    }
}
