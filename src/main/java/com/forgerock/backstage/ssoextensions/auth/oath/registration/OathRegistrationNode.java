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
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import org.apache.commons.codec.DecoderException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.modules.fr.oath.AuthenticatorAppRegistrationURIBuilder;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.forgerock.openam.utils.Alphabet;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.forgerock.openam.utils.qr.GenerationUtils;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static com.forgerock.backstage.ssoextensions.auth.oath.OathConstants.OATH_DEVICE_PROFILE_KEY;
import static org.forgerock.openam.auth.nodes.RecoveryCodeDisplayNode.RECOVERY_CODE_DEVICE_NAME;
import static org.forgerock.openam.auth.nodes.RecoveryCodeDisplayNode.RECOVERY_CODE_KEY;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = OathRegistrationNode.Config.class)
public class OathRegistrationNode extends SingleOutcomeNode {

    private final Config config;
    private final OathHelper helper;
    private final RecoveryCodeGenerator recoveryCodeGenerator;

    private static final int NUM_CODES = 10;
    private static final String BUTTON_LABEL = "Next";
    private static final String CALLBACK_ELEMENT_ID = "callback_0";

    /**
     * Configuration for the node.
     */
    public interface Config extends OathRegistrationNodeConfig {
    }


    @Inject
    public OathRegistrationNode(@Assisted Config config,
                                OathHelper helper,
                                RecoveryCodeGenerator recoveryCodeGenerator) {
        this.config = config;
        this.helper = helper;
        this.recoveryCodeGenerator = recoveryCodeGenerator;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        if (context.getCallback(ConfirmationCallback.class).isPresent()) {
            return goToNext().build();
        }

        return createDeviceProfileAndFinishWithCallbacks(context);
    }

    private Action createDeviceProfileAndFinishWithCallbacks(TreeContext context) throws NodeProcessException {
        List<String> recoveryCodes = config.generateRecoveryCodes() ? generateRecoveryCodes() : Collections.emptyList();
        OathDeviceSettings settings = createDeviceSettings(recoveryCodes);

        JsonValue sharedState;
        try {
            sharedState = context.sharedState.copy().put(OATH_DEVICE_PROFILE_KEY, helper.encryptOathDeviceSettings(settings));

        } catch (IOException e) {
            throw new NodeProcessException(e);
        }

        if (config.generateRecoveryCodes()) {
            sharedState
                    .put(RECOVERY_CODE_KEY, helper.encryptList(recoveryCodes))
                    .put(RECOVERY_CODE_DEVICE_NAME, settings.getDeviceName());
        }

        String script = GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration(
                CALLBACK_ELEMENT_ID,
                getRegistrationUri(settings, helper.getIdentity(context))
        );

        List<Callback> callbacks = ImmutableList.of(
                new ScriptTextOutputCallback(script),
                new ConfirmationCallback(ConfirmationCallback.YES, new String[]{BUTTON_LABEL}, 0)
        );

        return Action.send(callbacks)
                .replaceSharedState(sharedState)
                .build();
    }

    private List<String> generateRecoveryCodes() throws NodeProcessException {
        try {
            return recoveryCodeGenerator.generateCodes(NUM_CODES, Alphabet.ALPHANUMERIC, false);
        } catch (CodeException e) {
            throw new NodeProcessException(e);
        }
    }

    private OathDeviceSettings createDeviceSettings(List<String> recoveryCodes) {
        OathDeviceSettings settings = helper.createDeviceProfile(config.minSharedSecretLength());
        settings.setChecksumDigit(config.checksum());
        settings.setRecoveryCodes(recoveryCodes);
        return settings;
    }


    private String getRegistrationUri(OathDeviceSettings settings, AMIdentity id) throws NodeProcessException {
        if (settings == null) {
            throw new NodeProcessException("Invalid settings");
        }

        final AuthenticatorAppRegistrationURIBuilder builder = new AuthenticatorAppRegistrationURIBuilder(
                id,
                settings.getSharedSecret(),
                config.passwordLength(),
                config.issuerName()
        );

        OathAlgorithm algorithm = this.config.algorithm();

        try {
            if (OathAlgorithm.HOTP.equals(algorithm)) {
                int counter = settings.getCounter();
                return builder.getAuthenticatorAppRegistrationUriForHOTP(counter);
            } else if (OathAlgorithm.TOTP.equals(algorithm)) {
                return builder.getAuthenticatorAppRegistrationUriForTOTP(config.totpTimeStepInterval());
            } else {
                throw new NodeProcessException("No OTP algorithm selected");
            }
        } catch (DecoderException e) {
            throw new NodeProcessException("Could not decode secret key from hex to plain text", e);
        }
    }


}
