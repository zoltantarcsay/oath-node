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
import com.google.inject.assistedinject.Assisted;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.forgerock.openam.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static com.forgerock.backstage.ssoextensions.auth.oath.OathConstants.OATH_DEVICE_PROFILE_KEY;
import static com.forgerock.backstage.ssoextensions.auth.oath.verifier.OathVerifierNodeOutcomeProvider.OATHOutcome.*;
import static org.forgerock.openam.auth.nodes.RecoveryCodeDisplayNode.RECOVERY_CODE_DEVICE_NAME;
import static org.forgerock.openam.auth.nodes.RecoveryCodeDisplayNode.RECOVERY_CODE_KEY;


@Node.Metadata(outcomeProvider = OathVerifierNodeOutcomeProvider.class,
        configClass = OathVerifierNode.Config.class)
public class OathVerifierNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(OathVerifierNode.class);
    private final Config config;
    private final OathHelper helper;

    private static int SUBMIT = 0;
    static int RECOVERY_PRESSED = 1;

    /**
     * Configuration for the node.
     */
    public interface Config extends OathVerifierNodeConfig {
    }

    @Inject
    public OathVerifierNode(@Assisted Config config, OathHelper helper) {
        this.config = config;
        this.helper = helper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        OathDeviceSettings deviceSettings;

        try {
            deviceSettings = getDeviceProfileFromSharedState(context).orElse(this.helper.getOathDeviceSettings(context));
        } catch (DevicePersistenceException e) {
            throw new NodeProcessException(e);
        }

        if (null == deviceSettings) {
            return Action.goTo(NOT_REGISTERED.name()).build();
        }

        Optional<ConfirmationCallback> confirmationCallback = context.getCallback(ConfirmationCallback.class);
        if (confirmationCallback.isPresent() && confirmationCallback.get().getSelectedIndex() == RECOVERY_PRESSED) {
            return Action.goTo(RECOVERY_CODE.name()).build();
        }

        Optional<NameCallback> nameCallback = context.getCallback(NameCallback.class);
        if (!nameCallback.isPresent()) {
            return Action.send(getCallbacks()).build();
        }

        try {
            verifyCode(nameCallback.get().getName(), deviceSettings);
            helper.saveOathDeviceSettings(context, deviceSettings);

            Action.ActionBuilder actionBuilder = Action.goTo(SUCCESS.name());
            addRecoveryCodesToTransientState(context, actionBuilder);

            return actionBuilder.build();
        } catch (OathVerificationException | DevicePersistenceException e) {
            logger.debug(e.getMessage(), e);
            return Action.goTo(FAILURE.name()).build();
        }
    }

    private void addRecoveryCodesToTransientState(TreeContext context, Action.ActionBuilder actionBuilder) {
        String encryptedRecoveryCodes = context.sharedState.get(RECOVERY_CODE_KEY).asString();
        if (StringUtils.isEmpty(encryptedRecoveryCodes)) {
            return;
        }

        JsonValue transientState = context.transientState.copy();
        JsonValue sharedState = context.sharedState.copy();

        transientState
                .put(RECOVERY_CODE_KEY, helper.decryptList(encryptedRecoveryCodes))
                .put(RECOVERY_CODE_DEVICE_NAME, context.sharedState.get(RECOVERY_CODE_DEVICE_NAME));

        sharedState.remove(RECOVERY_CODE_KEY);
        sharedState.remove(RECOVERY_CODE_DEVICE_NAME);

        actionBuilder.replaceTransientState(transientState).replaceSharedState(sharedState);
    }

    /**
     * Verifies the input OTP.
     *
     * @param otp      The OTP to verify.
     * @param settings With which the OTP was configured.
     * @throws OathVerificationException on any error
     */
    private void verifyCode(String otp, OathDeviceSettings settings) throws OathVerificationException {
        if (settings == null) {
            throw new OathVerificationException("Invalid stored settings");
        }

        if (config.minSharedSecretLength() <= 0) {
            throw new OathVerificationException("Min Secret Key Length is not a valid value");
        }

        // check password length MUST be 6 or higher according to RFC
        if (config.passwordLength() < 6) {
            throw new OathVerificationException("Password length is smaller than 6");
        }

        AbstractOathVerifier verifier;

        if (OathAlgorithm.HOTP.equals(config.algorithm())) {
            verifier = new HotpVerifier(config, settings);
        } else if (OathAlgorithm.TOTP.equals(config.algorithm())) {
            verifier = new TotpVerifier(config, settings);
        } else {
            throw new OathVerificationException("Invalid OTP algorithm");
        }

        verifier.verify(otp);
    }

    private List<Callback> getCallbacks() {
        return ImmutableList.of(
                new NameCallback("Enter verification code"),
                new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[]{"Submit", "Use recovery code"}, SUBMIT)
        );
    }

    private Optional<OathDeviceSettings> getDeviceProfileFromSharedState(TreeContext context) {
        JsonValue oathDeviceProfileJsonNode = context.sharedState.get(OATH_DEVICE_PROFILE_KEY);

        if (oathDeviceProfileJsonNode.isNull()) {
            logger.debug("No device profile found in shared state");
            return Optional.empty();
        }

        logger.debug("Storing device profile found in shared state");

        OathDeviceSettings oathDeviceProfile;
        try {
            oathDeviceProfile = helper.decryptOathDeviceSettings(oathDeviceProfileJsonNode.asString());
        } catch (IOException e) {
            logger.error("Cannot deserialize device profile from shared state", e);
            return Optional.empty();
        }

        return Optional.of(oathDeviceProfile);
    }
}
