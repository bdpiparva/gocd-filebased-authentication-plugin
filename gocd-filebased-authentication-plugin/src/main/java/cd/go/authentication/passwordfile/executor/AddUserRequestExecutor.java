/*
 * Copyright 2019 ThoughtWorks, Inc.
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

package cd.go.authentication.passwordfile.executor;

import cd.go.authentication.passwordfile.PasswordFileReader;
import cd.go.authentication.passwordfile.model.AddUserRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.sun.tools.javac.util.StringUtils;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import org.mindrot.jbcrypt.BCrypt;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

import static java.util.Collections.*;

public class AddUserRequestExecutor implements RequestExecutor {
    private static final Gson GSON = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
    private GoPluginApiRequest request;
    private final PasswordFileReader passwordFileReader;

    public AddUserRequestExecutor(GoPluginApiRequest request) {
        this.request = request;
        passwordFileReader = new PasswordFileReader();

    }

    @Override
    public GoPluginApiResponse execute() throws IOException {
        AddUserRequest addUserRequest = AddUserRequest.fromJSON(request.requestBody());
        String passwordFilePath = addUserRequest.getAuthConfig().getConfiguration().getPasswordFilePath();
        File file = new File(passwordFilePath);

        try {
            Properties properties = loadPasswordFile(file);
            String hashedPassword = BCrypt.hashpw(addUserRequest.getConfiguration().getPassword(), BCrypt.gensalt());
            properties.put(addUserRequest.getConfiguration().getUsername(), hashedPassword);
            properties.store(new FileWriter(file), "Updated by the plugin");

            return DefaultGoPluginApiResponse.success(GSON.toJson(singletonMap("message", "User successfully added to password file")));
        } catch (Exception e) {
            return DefaultGoPluginApiResponse.error(GSON.toJson(singletonMap("message", "Failed to add user: " + e.getMessage())));
        }
    }

    private Properties loadPasswordFile(File file) throws IOException {

        if (file.exists() && file.isFile()) {
            return this.passwordFileReader.read(file.getAbsolutePath());
        }

        if (file.createNewFile()) {
            return this.passwordFileReader.read(file.getAbsolutePath());
        }

        throw new RuntimeException(String.format("Failed to create password file at %s", file.getAbsoluteFile()));
    }

}
