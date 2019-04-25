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

package com.forgerock.backstage.ssoextensions.auth.oath.registration;

import com.forgerock.backstage.ssoextensions.auth.oath.OathAlgorithm;
import com.forgerock.backstage.ssoextensions.auth.oath.OathHelper;
import com.google.common.collect.ImmutableList;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.callback.ConfirmationCallback;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OathRegistrationNodeTest {

    private final OathRegistrationNode.Config config = mock(OathRegistrationNode.Config.class);

    private final OathHelper helper = mock(OathHelper.class);
    private final RecoveryCodeGenerator recoveryCodeGenerator = mock(RecoveryCodeGenerator.class);
    private final OathRegistrationNode oathRegistrationNode = new OathRegistrationNode(config, helper, recoveryCodeGenerator);
    private final JsonValue emptySharedState = new JsonValue(new HashMap<>());
    private final ConfirmationCallback confirmationCallback = mock(ConfirmationCallback.class);
    private final ExternalRequestContext request = new ExternalRequestContext.Builder().parameters(emptyMap()).build();

    @Before
    public void init() {
        when(config.algorithm()).thenReturn(OathAlgorithm.HOTP);
        when(config.minSharedSecretLength()).thenReturn(1);
        when(config.issuerName()).thenReturn("test");
        when(config.generateRecoveryCodes()).thenReturn(true);
        when(config.passwordLength()).thenReturn(6);
    }

    @Test
    public void process_whenConfirmation_thenOutcome() throws NodeProcessException {
        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));
        Action action = oathRegistrationNode.process(context);
        assertThat(action.outcome).isEqualTo("outcome");
    }

    @Test
    public void process_whenInitialStage_thenGenerateDeviceProfileAndCallbacks() throws NodeProcessException, IOException {

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of());
        List<String> recoveryCodes = ImmutableList.of("123456");
        OathDeviceSettings settings = new OathDeviceSettings();
        settings.setSharedSecret("abcd");
        settings.setDeviceName("device");

        when(config.generateRecoveryCodes()).thenReturn(false);
        when(helper.createDeviceProfile(anyInt())).thenReturn(settings);
        when(helper.encryptOathDeviceSettings(any())).thenReturn("device_settings");
        when(helper.encryptList(recoveryCodes)).thenReturn("encrypted_recovery_codes");
        when(helper.getIdentity(any())).thenReturn(mock(AMIdentity.class));

        Action action = oathRegistrationNode.process(context);

        assertThat(action.callbacks).hasSize(2);
        assertThat(action.callbacks.get(0)).isInstanceOf(ScriptTextOutputCallback.class);
        assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
        assertThat(action.sharedState.get("oathDeviceProfile").asString()).isEqualTo("device_settings");
        assertThat(action.sharedState.isDefined("recoveryCodes")).isFalse();
        assertThat(action.sharedState.isDefined("deviceName")).isFalse();
    }

    @Test
    public void process_whenRecoveryCodesRequested_thenGenerateRecoveryCodes() throws NodeProcessException, CodeException, IOException {

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of());
        List<String> recoveryCodes = ImmutableList.of("123456");
        OathDeviceSettings settings = new OathDeviceSettings();
        settings.setSharedSecret("abcd");
        settings.setDeviceName("device");

        when(config.generateRecoveryCodes()).thenReturn(true);
        when(recoveryCodeGenerator.generateCodes(anyInt(), any(), anyBoolean())).thenReturn(recoveryCodes);
        when(helper.createDeviceProfile(anyInt())).thenReturn(settings);
        when(helper.encryptOathDeviceSettings(any())).thenReturn("device_settings");
        when(helper.encryptList(recoveryCodes)).thenReturn("encrypted_recovery_codes");
        when(helper.getIdentity(any())).thenReturn(mock(AMIdentity.class));

        Action action = oathRegistrationNode.process(context);

        assertThat(action.callbacks).hasSize(2);
        assertThat(action.callbacks.get(0)).isInstanceOf(ScriptTextOutputCallback.class);
        assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
        assertThat(action.sharedState.get("oathDeviceProfile").asString()).isEqualTo("device_settings");
        assertThat(action.sharedState.get("recoveryCodes").asString()).isEqualTo("encrypted_recovery_codes");

    }

}
