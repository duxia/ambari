/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ambari.view.pig.utils;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.AccessControlException;
import java.util.HashMap;

public class ServiceFormattedException extends WebApplicationException {
  private final static Logger LOG =
      LoggerFactory.getLogger(ServiceFormattedException.class);

  public ServiceFormattedException(String message) {
    super(errorEntity(message, null, suggestStatus(null)));
  }

  public ServiceFormattedException(String message, Throwable exception) {
    super(errorEntity(message, exception, suggestStatus(exception)));
  }

  public ServiceFormattedException(String message, Throwable exception, int status) {
    super(errorEntity(message, exception, status));
  }

  private static int suggestStatus(Throwable exception) {
    int status = 500;
    if (exception == null) return status;
    if (exception instanceof AccessControlException) {
      status = 403;
    }
    return status;
  }

  protected static Response errorEntity(String message, Throwable e, int status) {
    HashMap<String, Object> response = new HashMap<String, Object>();
    response.put("message", message);
    String trace = null;
    if (e != null)
      trace = ExceptionUtils.getStackTrace(e);
    response.put("trace", trace);
    response.put("status", status);

    if(message != null) LOG.error(message);
    if(trace != null) LOG.debug(trace);

    return Response.status(status).entity(new JSONObject(response)).type(MediaType.APPLICATION_JSON).build();
  }
}
