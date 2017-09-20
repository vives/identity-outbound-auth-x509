/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.x509Certificate;

import org.apache.axiom.om.util.Base64;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.apache.commons.lang.StringUtils;

import javax.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Working with certificate and claims store
 */
public class X509CertificateUtil extends AbstractAdmin {

    /**
     * Get certificate from claims.
     *
     * @param username name of the user
     * @return x509 certificate
     * @throws AuthenticationFailedException authentication failed exception
     */
    private static X509Certificate getCertificate(String username) throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        UserStoreManager userStoreManager;
        RealmService realmService = X509CertificateRealmServiceComponent.getRealmService();
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantID = realmService.getTenantManager().getTenantId(tenantDomain);
            userStoreManager = realmService.getTenantUserRealm(tenantID).getUserStoreManager();
            String claimURI = getClaimUri();
            Map<String, String> userClaimValues = userStoreManager.getUserClaimValues(username, new
                    String[] { claimURI }, null);
            String userCertificate = userClaimValues.get(claimURI);
            if (StringUtils.isNotEmpty(userCertificate)) {
                x509Certificate = X509Certificate.getInstance(Base64.decode(userCertificate));
            } else {
                return null;
            }
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while decoding the certificate ", e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("Error while user manager for tenant id ", e);
        }
        return x509Certificate;
    }

    /**
     * Add certificate into claims.
     *
     * @param username         name of the user
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException authentication failed exception
     */
    public synchronized boolean addCertificate(String username, byte[] certificateBytes)
            throws AuthenticationFailedException {
        Map<String, String> claims = new HashMap<>();
        try {
            X509Certificate x509Certificate = X509Certificate.getInstance(certificateBytes);
            claims.put(getClaimUri(), Base64.encode(x509Certificate.getEncoded()));
            org.wso2.carbon.user.core.UserStoreManager userStoreManager = getUserRealm().getUserStoreManager();
            userStoreManager.setUserClaimValues(username, claims, X509CertificateConstants.DEFAULT);
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate of user: " + username, e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while setting certificate of user: " + username, e);
        }
        return true;
    }

    /**
     * Validate the certificate against with given certificate.
     *
     * @param userName         name of the user
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException
     */
    public synchronized boolean validateCerts(String userName, byte[] certificateBytes)
            throws AuthenticationFailedException {
        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);
        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        }
        return x509Certificate.equals(getCertificate(userName));
    }

    /**
     * Check availability of certificate.
     *
     * @param userName name of the user
     * @return boolean status of availability
     */
    public synchronized boolean isCertificateExist(String userName) throws AuthenticationFailedException {
        return getCertificate(userName) != null;
    }

    /**
     * Get parameter values from local file.
     */
    private static Map<String, String> getX509Parameters() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(X509CertificateConstants.AUTHENTICATOR_NAME);
        if(authConfig != null) {
            return authConfig.getParameterMap();
        }
        return null;
    }

    /**
     * Get user claimURI value.
     *
     * @return claimURI
     */
    private static String getClaimUri(){
        String claimURI = X509CertificateConstants.CLAIM_DIALECT_URI;
        Map<String, String> parametersMap = getX509Parameters();
        if(parametersMap != null) {
            Object claimURIObj = parametersMap.get(X509CertificateConstants.CLAIM_URI);
            if (claimURIObj != null) {
                claimURI = String.valueOf(claimURIObj);
            }
        }
        return claimURI;
    }
}