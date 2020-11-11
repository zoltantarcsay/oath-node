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

import com.sun.identity.authentication.modules.hotp.HOTPAlgorithm;
import com.sun.identity.authentication.modules.hotp.OTPGenerator;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;

import javax.xml.bind.DatatypeConverter;

public final class HotpVerifier extends AbstractOathVerifier {
    private final OTPGenerator hotpGenerator = new HOTPAlgorithm();

    HotpVerifier(OathVerifierNode.Config config, OathDeviceSettings settings) {
        super(config, settings);
    }

    @Override
    void verify(String otp) throws OathVerificationException {
        int counter = settings.getCounter();
        byte[] sharedSecretBytes = DatatypeConverter.parseHexBinary(getSharedSecret());

        //test the counter in the lookahead window
        for (int i = 0; i <= config.hotpWindowSize(); i++) {
            String otpGen;
            try {
                otpGen = hotpGenerator.generateOTP(sharedSecretBytes, counter + i, config.passwordLength(), config.checksum(),
                        config.truncationOffset());
            } catch (Exception e) {
                throw new OathVerificationException(e.getMessage(), e);
            }
            if (isEqual(otpGen, otp)) {
                settings.setCounter(counter + i);
                return;
            }
        }
        throw new OathVerificationException();
    }
}
