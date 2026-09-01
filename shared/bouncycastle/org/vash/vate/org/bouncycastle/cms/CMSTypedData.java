package org.vash.vate.org.bouncycastle.cms;

import org.vash.vate.org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
