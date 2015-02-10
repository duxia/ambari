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
package org.apache.ambari.server.controller.internal;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.UserRequest;
import org.apache.ambari.server.controller.UserResponse;
import org.apache.ambari.server.controller.spi.*;
import org.apache.ambari.server.controller.utilities.PropertyHelper;
import org.apache.ambari.server.controller.utilities.RSAutils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Resource provider for user resources.
 */
class UserResourceProvider extends AbstractControllerResourceProvider {

  // ----- Property ID constants ---------------------------------------------

  // Users
  protected static final String USER_USERNAME_PROPERTY_ID     = PropertyHelper.getPropertyId("Users", "user_name");
  protected static final String USER_LICENCE_TIME     = PropertyHelper.getPropertyId("Users", "licence_time");
  protected static final String USER_TOKEN     = PropertyHelper.getPropertyId("Users", "token");
  protected static final String USER_PASSWORD_PROPERTY_ID     = PropertyHelper.getPropertyId("Users", "password");
  protected static final String USER_OLD_PASSWORD_PROPERTY_ID = PropertyHelper.getPropertyId("Users", "old_password");
  protected static final String USER_LDAP_USER_PROPERTY_ID    = PropertyHelper.getPropertyId("Users", "ldap_user");
  protected static final String USER_ACTIVE_PROPERTY_ID       = PropertyHelper.getPropertyId("Users", "active");
  protected static final String USER_GROUPS_PROPERTY_ID       = PropertyHelper.getPropertyId("Users", "groups");
  protected static final String USER_ADMIN_PROPERTY_ID        = PropertyHelper.getPropertyId("Users", "admin");

  private static Set<String> pkPropertyIds =
      new HashSet<String>(Arrays.asList(new String[]{
          USER_USERNAME_PROPERTY_ID}));

  /**
   * Create a new resource provider for the given management controller.
   */
  UserResourceProvider(Set<String> propertyIds,
                       Map<Resource.Type, String> keyPropertyIds,
                       AmbariManagementController managementController) {
    super(propertyIds, keyPropertyIds, managementController);
  }

  @Override
  public RequestStatus createResources(Request request)
      throws SystemException,
      UnsupportedPropertyException,
      ResourceAlreadyExistsException,
      NoSuchParentResourceException {
    final Set<UserRequest> requests = new HashSet<UserRequest>();
    for (Map<String, Object> propertyMap : request.getProperties()) {
      requests.add(getRequest(propertyMap));
    }

    createResources(new Command<Void>() {
      @Override
      public Void invoke() throws AmbariException {
        getManagementController().createUsers(requests);
        return null;
      }
    });

    return getRequestStatus(null);
  }

  @Override
  public Set<Resource> getResources(Request request, Predicate predicate)
      throws SystemException, UnsupportedPropertyException, NoSuchResourceException, NoSuchParentResourceException {

    final Set<UserRequest> requests = new HashSet<UserRequest>();

    if (predicate == null) {
      requests.add(getRequest(null));
    } else {
      for (Map<String, Object> propertyMap : getPropertyMaps(predicate)) {
        requests.add(getRequest(propertyMap));
      }
    }

    Set<UserResponse> responses = getResources(new Command<Set<UserResponse>>() {
      @Override
      public Set<UserResponse> invoke() throws AmbariException {
        return getManagementController().getUsers(requests);
      }
    });

    if (LOG.isDebugEnabled()) {
      LOG.debug("Found user responses matching get user request"
          + ", userRequestSize=" + requests.size()
          + ", userResponseSize=" + responses.size());
    }

    Set<String>   requestedIds = getRequestPropertyIds(request, predicate);
    Set<Resource> resources    = new HashSet<Resource>();

    for (UserResponse userResponse : responses) {
      ResourceImpl resource = new ResourceImpl(Resource.Type.User);

      setResourceProperty(resource, USER_USERNAME_PROPERTY_ID,
          userResponse.getUsername(), requestedIds);
      
      setResourceProperty(resource, USER_LICENCE_TIME,
              userResponse.getLicenceTime(), requestedIds);
      
      setResourceProperty(resource, USER_LDAP_USER_PROPERTY_ID,
          userResponse.isLdapUser(), requestedIds);

      setResourceProperty(resource, USER_ACTIVE_PROPERTY_ID,
          userResponse.isActive(), requestedIds);

      setResourceProperty(resource, USER_GROUPS_PROPERTY_ID,
          userResponse.getGroups(), requestedIds);

      setResourceProperty(resource, USER_ADMIN_PROPERTY_ID,
          userResponse.isAdmin(), requestedIds);

      resources.add(resource);
    }

    return resources;
  }

  @Override
  public RequestStatus updateResources(Request request, Predicate predicate)
    throws SystemException, UnsupportedPropertyException, NoSuchResourceException, NoSuchParentResourceException {
    final Set<UserRequest> requests = new HashSet<UserRequest>();

    for (Map<String, Object> propertyMap : getPropertyMaps(request.getProperties().iterator().next(), predicate)) {
      UserRequest req = getRequest(propertyMap);

      requests.add(req);
    }

    modifyResources(new Command<Void>() {
      @Override
      public Void invoke() throws AmbariException {
        getManagementController().updateUsers(requests);
        return null;
      }
    });

    return getRequestStatus(null);
  }

  @Override
  public RequestStatus deleteResources(Predicate predicate)
      throws SystemException, UnsupportedPropertyException, NoSuchResourceException, NoSuchParentResourceException {
    final Set<UserRequest> requests = new HashSet<UserRequest>();

    for (Map<String, Object> propertyMap : getPropertyMaps(predicate)) {
      UserRequest req = getRequest(propertyMap);

      requests.add(req);
    }

    modifyResources(new Command<Void>() {
      @Override
      public Void invoke() throws AmbariException {
        getManagementController().deleteUsers(requests);
        return null;
      }
    });

    return getRequestStatus(null);
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return pkPropertyIds;
  }

  private UserRequest getRequest(Map<String, Object> properties) {
    if (properties == null) {
      return new UserRequest(null);
    }

    UserRequest request = new UserRequest ((String) properties.get(USER_USERNAME_PROPERTY_ID));

    request.setPassword((String) properties.get(USER_PASSWORD_PROPERTY_ID));
    request.setOldPassword((String) properties.get(USER_OLD_PASSWORD_PROPERTY_ID));
    //add createtime
    if(properties.get(USER_LICENCE_TIME)!= null) {
	    try {
	    	String encrypt_licenceTime=(String) properties.get(USER_LICENCE_TIME);
//	    	LOG.info("resive the encrypt_licenceTime is : "+encrypt_licenceTime);
	    	String publicKeyFile = "/usr/lib/ambari-server/public.key";
	    	String decrypt_licenceTime=RSAutils.decrypt(RSAutils.getPublicKey(publicKeyFile), encrypt_licenceTime);
//	    	LOG.info("resive the decrypt_licenceTime is : "+decrypt_licenceTime);
	    	Date date_licenceTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(decrypt_licenceTime);
//	    	LOG.info(date_licenceTime.toString());
			request.setLicenceTime(date_licenceTime);
		} catch (ParseException e) {
			e.printStackTrace();
			LOG.error("USER_LICENCE_TIME : ParseException");
		} catch (IOException e) {
			e.printStackTrace();
			LOG.error("USER_LICENCE_TIME : IOException");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			LOG.error("USER_LICENCE_TIME : GeneralSecurityException");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			LOG.error("USER_LICENCE_TIME : ClassNotFoundException");
		}
    }
    request.setToken((String) properties.get(USER_TOKEN));
    
    if (null != properties.get(USER_ACTIVE_PROPERTY_ID)) {
      request.setActive(Boolean.valueOf(properties.get(USER_ACTIVE_PROPERTY_ID).toString()));
    }

    if (null != properties.get(USER_ADMIN_PROPERTY_ID)) {
      request.setAdmin(Boolean.valueOf(properties.get(USER_ADMIN_PROPERTY_ID).toString()));
    }

    return request;
  }
}
