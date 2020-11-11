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
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class HotpVerifierTest {

    private final OathDeviceSettings settings = new OathDeviceSettings();
    private final OathVerifierNode.Config config = new OathVerifierNode.Config() {
        @Override
        public int minSharedSecretLength() {
            return 1;
        }
    };
    private final HotpVerifier hotpVerifier = new HotpVerifier(config, settings);

    @Before
    public void init() {
        settings.setSharedSecret("abcd");
    }

    @Test
    public void verify_whenFirst_thenValid() throws OathVerificationException {
        hotpVerifier.verify("564491");
    }

    @Test
    public void verify_whenSecond_thenValid() throws OathVerificationException {
        hotpVerifier.verify("853971");
    }

    @Test
    public void verify_whenInvalidToken_thenFail() {
        assertThatThrownBy(() -> hotpVerifier.verify("foo"))
                .isInstanceOf(OathVerificationException.class);
    }

    @Test
    public void verify_incrementCounter() throws OathVerificationException {
        int counter = settings.getCounter();
        hotpVerifier.verify("853971");
        assertThat(settings.getCounter()).isEqualTo(counter + 1);
    }
}
