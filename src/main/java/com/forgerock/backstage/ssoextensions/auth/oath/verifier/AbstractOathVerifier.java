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

import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;

import java.security.MessageDigest;

abstract class AbstractOathVerifier {
    final OathVerifierNode.Config config;
    final OathDeviceSettings settings;

    AbstractOathVerifier(OathVerifierNode.Config config, OathDeviceSettings settings) {
        this.config = config;
        this.settings = settings;
    }

    abstract void verify(String otp) throws OathVerificationException;

    String getSharedSecret() throws OathVerificationException {
        String sharedSecret = settings.getSharedSecret();
        if (config.minSharedSecretLength() <= 0) {
            throw new OathVerificationException("Min Secret Key Length is not a valid value");
        }

        if (sharedSecret == null || sharedSecret.isEmpty()) {
            throw new OathVerificationException("Secret key is not a valid value");
        }

        if (sharedSecret.length() < config.minSharedSecretLength()) {
            throw new OathVerificationException("Secret key of length " + sharedSecret.length()
                    + " is less than the minimum secret key length");
        }

        // get rid of white space in string (messes with the data converter)
        sharedSecret = sharedSecret.replaceAll("\\s+", "");
        // convert sharedSecret to lowercase
        sharedSecret = sharedSecret.toLowerCase();
        // make sure sharedSecret is even length
        if ((sharedSecret.length() % 2) != 0) {
            sharedSecret = "0" + sharedSecret;
        }


        return sharedSecret;
    }

    boolean isEqual(String str1, String str2) {
        return MessageDigest.isEqual(str1.getBytes(), str2.getBytes());
    }
}
