package org.vash.vate.org.bouncycastle.cms;

import org.vash.vate.org.bouncycastle.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
