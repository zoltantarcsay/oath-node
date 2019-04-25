/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2019 ForgeRock AS.
 * Portions copyright 2019 Zoltan Tarcsay
 * Portions copyright 2019 Josh Cross
 * Portions copyright 2019 Chris Clifton
 */

package com.forgerock.backstage.ssoextensions.auth.oath;


import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jwe.EncryptedJwt;
import org.forgerock.json.jose.jwe.EncryptionMethod;
import org.forgerock.json.jose.jwe.JweAlgorithm;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.rest.devices.DeviceJsonUtils;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.forgerock.openam.core.rest.devices.oath.UserOathDeviceProfileManager;
import org.forgerock.openam.secrets.Secrets;
import org.forgerock.openam.shared.secrets.Labels;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.DataEncryptionKey;
import org.forgerock.secrets.keys.KeyFormatRaw;

import javax.inject.Inject;
import java.io.IOException;
import java.util.List;

import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.secrets.Purpose.purpose;

public class OathHelper {
    public static final String LIST_CLAIM_NAME = "list";
    private final UserOathDeviceProfileManager userOathDeviceProfileManager;
    private final CoreWrapper coreWrapper;
    private final Realm realm;
    private final JwtBuilderFactory jwtBuilderFactory;
    private final Secrets secrets;
    private final DeviceJsonUtils<OathDeviceSettings> deviceJsonUtils;

    private static final Purpose<DataEncryptionKey> AUTH_TREE_ENCRYPTION =
            purpose(Labels.STATELESS_TOKEN_ENCRYPTION, DataEncryptionKey.class);


    @Inject
    public OathHelper(@Assisted Realm realm,
                      UserOathDeviceProfileManager userOathDeviceProfileManager,
                      CoreWrapper coreWrapper,
                      JwtBuilderFactory jwtBuilderFactory,
                      Secrets secrets,
                      DeviceJsonUtils<OathDeviceSettings> deviceJsonUtils) {
        this.realm = realm;
        this.userOathDeviceProfileManager = userOathDeviceProfileManager;
        this.coreWrapper = coreWrapper;
        this.jwtBuilderFactory = jwtBuilderFactory;
        this.secrets = secrets;
        this.deviceJsonUtils = deviceJsonUtils;
    }

    public String encryptOathDeviceSettings(OathDeviceSettings settings) throws IOException {
        return encrypt(deviceJsonUtils.toJsonValue(settings));
    }

    public String encryptList(List list) {
        return encrypt(json(object(field(LIST_CLAIM_NAME, list))));
    }

    /**
     * Encrypt a payload for inclusion in a shared state.
     *
     * @param payload the payload to be encrypted
     * @return the encrypted payload
     */
    public String encrypt(JsonValue payload) {
        SecretsProvider provider = secrets.getRealmSecrets(realm);
        DataEncryptionKey key;
        try {
            key = provider.getActiveSecret(AUTH_TREE_ENCRYPTION).getOrThrowUninterruptibly();
            return jwtBuilderFactory.jwe(key.export(KeyFormatRaw.INSTANCE))
                    .headers()
                    .alg(JweAlgorithm.DIRECT)
                    .enc(EncryptionMethod.A128CBC_HS256)
                    .done()
                    .claims(new JwtClaimsSet(payload.asMap()))
                    .asJwt()
                    .build();
        } catch (NoSuchSecretException e) {
            throw new IllegalStateException("No encryption found for AuthTrees", e);
        }
    }

    public OathDeviceSettings decryptOathDeviceSettings(String payload) throws IOException {
        return deviceJsonUtils.toDeviceSettingValue(decrypt(payload));
    }

    public List decryptList(String payload) {
        return decrypt(payload).get(LIST_CLAIM_NAME).asList();
    }

    /**
     * Decrypt an encrypted payload from a shared state.
     *
     * @param payload the payload to be decrypted
     * @return the decrypted payload
     */
    public JsonValue decrypt(String payload) {
        SecretsProvider provider = secrets.getRealmSecrets(realm);
        DataEncryptionKey key;
        try {
            key = provider.getActiveSecret(AUTH_TREE_ENCRYPTION).getOrThrowUninterruptibly();
            EncryptedJwt jwt = jwtBuilderFactory.reconstruct(payload, EncryptedJwt.class);
            jwt.decrypt(key.export(KeyFormatRaw.INSTANCE));
            return jwt.getClaimsSet().toJsonValue();
        } catch (NoSuchSecretException e) {
            throw new IllegalStateException("No encryption found for AuthTrees", e);
        }
    }

    public OathDeviceSettings getOathDeviceSettings(TreeContext context) throws DevicePersistenceException {
        List<OathDeviceSettings> deviceProfiles = userOathDeviceProfileManager.getDeviceProfiles(getUsername(context), getRealm(context));
        return CollectionUtils.getFirstItem(deviceProfiles, null);
    }

    public void saveOathDeviceSettings(TreeContext context, OathDeviceSettings deviceSettings) throws DevicePersistenceException {
        userOathDeviceProfileManager.saveDeviceProfile(getUsername(context), getRealm(context), deviceSettings);
    }

    public OathDeviceSettings createDeviceProfile(int minSharedSecretLength) {
        return userOathDeviceProfileManager.createDeviceProfile(minSharedSecretLength);
    }

    public AMIdentity getIdentity(TreeContext context) {
        return coreWrapper.getIdentity(getUsername(context), getRealm(context));
    }

    private String getUsername(TreeContext context) {
        return context.sharedState.get(USERNAME).asString();
    }

    private String getRealm(TreeContext context) {
        return context.sharedState.get(REALM).asString();
    }

}
