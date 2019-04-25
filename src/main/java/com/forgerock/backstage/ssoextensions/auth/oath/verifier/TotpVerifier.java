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

import org.forgerock.openam.authentication.modules.fr.oath.TOTPAlgorithm;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.forgerock.util.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static org.forgerock.openam.utils.Time.currentTimeMillis;

public final class TotpVerifier extends AbstractOathVerifier {
    private final Logger logger = LoggerFactory.getLogger(TotpVerifier.class);
    private final long time;

    public TotpVerifier(OathVerifierNode.Config config, OathDeviceSettings settings) {
        this(config, settings, currentTimeMillis() / 1000L);
    }

    @VisibleForTesting
    TotpVerifier(OathVerifierNode.Config config, OathDeviceSettings settings, long time) {
        super(config, settings);

        this.time = time;
    }

    @Override
    public void verify(String otp) throws OathVerificationException {
        //get Last login time
        long lastLoginTimeStep = settings.getLastLogin() / config.totpTimeStepInterval();

        //Check TOTP values for validity
        if (lastLoginTimeStep < 0) {
            throw new OathVerificationException("invalid login time value");
        }

        //must be greater than 0 or we get divide by 0, and cant be negative
        if (config.totpTimeStepInterval() <= 0) {
            throw new OathVerificationException("invalid TOTP time step interval");
        }

        if (config.totpTimeStepInWindow() < 0) {
            throw new OathVerificationException("invalid TOTP steps in window value");
        }

        //get Time Step
        long localTime = (time / config.totpTimeStepInterval()) + (settings.getClockDriftSeconds() / config.totpTimeStepInterval());

        if (lastLoginTimeStep == localTime) {
            throw new OathVerificationException("Login failed attempting to use the same OTP in same Time Step: " + localTime);
        }

        boolean sameWindow = false;

        //check if we are in the time window to prevent 2 logins within the window using the same OTP

        if (lastLoginTimeStep >= (localTime - config.totpTimeStepInWindow()) &&
                lastLoginTimeStep <= (localTime + config.totpTimeStepInWindow())) {
            logger.debug("Logging in in the same TOTP window");
            sameWindow = true;
        }

        String passLenStr = Integer.toString(config.passwordLength());
        String otpGen = TOTPAlgorithm.generateTOTP(getSharedSecret(), Long.toHexString(localTime), passLenStr);

        if (isEqual(otpGen, otp)) {
            checkDrift(localTime);
            updateDeviceSettings(localTime, settings);
            return;
        }

        for (int i = 1; i <= config.totpTimeStepInWindow(); i++) {
            long time1 = localTime + i;
            long time2 = localTime - i;

            //check time step after current time
            otpGen = TOTPAlgorithm.generateTOTP(getSharedSecret(), Long.toHexString(time1), passLenStr);

            if (isEqual(otpGen, otp)) {
                checkDrift(time1);
                updateDeviceSettings(time1, settings);
                return;
            }

            //check time step before current time
            otpGen = TOTPAlgorithm.generateTOTP(getSharedSecret(), Long.toHexString(time2), passLenStr);

            if (isEqual(otpGen, otp) && sameWindow) {
                logger.error("Logging in in the same window with a OTP that is "
                        + "older than the current times OTP");
                throw new OathVerificationException();
            } else if (isEqual(otpGen, otp) && !sameWindow) {
                checkDrift(time2);
                updateDeviceSettings(time2, settings);
                return;
            }
        }

        throw new OathVerificationException();
    }

    private long getDrift(long localTime) {
        return localTime - (time / config.totpTimeStepInterval());
    }

    private void checkDrift(long localTime)  throws OathVerificationException  {
        if (Math.abs(getDrift(localTime)) > config.totpMaxClockDrift()) {
            throw new OathVerificationException("OTP is out of sync");
        }
    }

    private void updateDeviceSettings(long localTime, OathDeviceSettings settings) {
        settings.setLastLogin(localTime * config.totpTimeStepInterval(), TimeUnit.SECONDS);
        settings.setClockDriftSeconds((int) getDrift(localTime) * config.totpTimeStepInterval());
    }
}
