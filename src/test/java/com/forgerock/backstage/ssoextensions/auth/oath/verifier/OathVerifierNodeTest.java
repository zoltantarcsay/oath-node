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

package com.forgerock.backstage.ssoextensions.auth.oath.verifier;

import com.forgerock.backstage.ssoextensions.auth.oath.OathAlgorithm;
import com.forgerock.backstage.ssoextensions.auth.oath.OathHelper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import java.io.IOException;
import java.util.HashMap;

import static com.forgerock.backstage.ssoextensions.auth.oath.OathConstants.OATH_DEVICE_PROFILE_KEY;
import static com.forgerock.backstage.ssoextensions.auth.oath.verifier.OathVerifierNode.RECOVERY_PRESSED;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OathVerifierNodeTest {

    private final OathVerifierNode.Config config = new OathVerifierNode.Config() {
        @Override
        public OathAlgorithm algorithm() {
            return OathAlgorithm.HOTP;
        }

        @Override
        public int minSharedSecretLength() {
            return 1;
        }
    };
    private final OathHelper helper = mock(OathHelper.class);
    private final OathVerifierNode verifierNode = new OathVerifierNode(config, helper);
    private final ConfirmationCallback confirmationCallback = mock(ConfirmationCallback.class);
    private final NameCallback nameCallback = mock(NameCallback.class);
    private final JsonValue emptySharedState = new JsonValue(new HashMap<>());
    private final ExternalRequestContext request = new ExternalRequestContext.Builder().parameters(emptyMap()).build();
    private final OathDeviceSettings deviceSettings = new OathDeviceSettings();

    @Before
    public void init() {
        deviceSettings.setSharedSecret("abcd");
    }

    @Test
    public void process_whenNoDeviceSettings_thenNotRegistered() throws NodeProcessException {

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of());
        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("NOT_REGISTERED");
    }

    @Test
    public void process_whenRecoveryPressed_thenRecoveryCode() throws NodeProcessException, DevicePersistenceException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(RECOVERY_PRESSED);
        when(helper.getOathDeviceSettings(any())).thenReturn(new OathDeviceSettings());

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("RECOVERY_CODE");
    }

    @Test
    public void process_whenInitialSetup_thenReturnCallbacks() throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(new OathDeviceSettings());

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));

        Action action = verifierNode.process(context);
        assertThat(action.callbacks).hasSize(2);
        assertThat(action.callbacks.get(0)).isInstanceOf(NameCallback.class);
        assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
    }

    @Test
    public void process_whenValidOtpProvidedFromContext_thenSuccess() throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(deviceSettings);
        when(nameCallback.getName()).thenReturn("564491");

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("SUCCESS");
    }

    @Test
    public void process_whenValidOtpProvidedFromSharedState_thenSuccess() throws NodeProcessException, IOException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(nameCallback.getName()).thenReturn("564491");
        when(helper.decryptOathDeviceSettings(anyString())).thenReturn(deviceSettings);
        JsonValue sharedState = new JsonValue(ImmutableMap.of(OATH_DEVICE_PROFILE_KEY, ""));
        TreeContext context = new TreeContext(sharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("SUCCESS");
    }

    @Test
    public void process_whenInvalidOtpProvided_thenFail() throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(deviceSettings);
        when(nameCallback.getName()).thenReturn("invalid_otp");

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("FAILURE");
    }


}
