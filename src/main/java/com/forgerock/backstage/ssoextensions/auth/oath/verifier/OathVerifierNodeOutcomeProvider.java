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

import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.util.i18n.PreferredLocales;

import java.util.List;


public class OathVerifierNodeOutcomeProvider implements OutcomeProvider {
    public enum OATHOutcome {
        NOT_REGISTERED("Not Registered"),
        RECOVERY_CODE("Recovery Code"),
        SUCCESS("Success"),
        FAILURE("Failure");

        private final String displayValue;

        private OATHOutcome(String displayValue) {
            this.displayValue = displayValue;
        }

        private Outcome getOutcome() {
            return new Outcome(name(), displayValue);
        }
    }


    @Override
    public List<Outcome> getOutcomes(PreferredLocales preferredLocales, JsonValue jsonValue) {
        return ImmutableList.of(
                OATHOutcome.NOT_REGISTERED.getOutcome(),
                OATHOutcome.RECOVERY_CODE.getOutcome(),
                OATHOutcome.SUCCESS.getOutcome(),
                OATHOutcome.FAILURE.getOutcome()
        );
    }
}