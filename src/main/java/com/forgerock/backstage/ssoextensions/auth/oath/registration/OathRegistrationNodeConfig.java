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
import com.forgerock.backstage.ssoextensions.auth.oath.verifier.OathAlgorithmAttribute;
import org.forgerock.openam.annotations.sm.Attribute;

public interface OathRegistrationNodeConfig {
    @Attribute(order = 100)
    default int passwordLength() {
        return 6;
    }

    @Attribute(order = 200)
    default int minSharedSecretLength() {
        return 20;
    }

    @Attribute(order = 300)
    @OathAlgorithmAttribute
    default OathAlgorithm algorithm() {
        return OathAlgorithm.TOTP;
    }

    @Attribute(order = 400)
    default int totpTimeStepInterval() {
        return 30;
    }

    @Attribute(order = 500)
    default String issuerName() {
        return "ForgeRock";
    }

    @Attribute(order = 600)
    default boolean checksum() {
        return false;
    }

    @Attribute(order = 700)
    default boolean generateRecoveryCodes() {
        return false;
    }
}
