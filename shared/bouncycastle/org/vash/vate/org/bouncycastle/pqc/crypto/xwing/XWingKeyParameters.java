package org.vash.vate.org.bouncycastle.pqc.crypto.xwing;

import org.vash.vate.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XWingKeyParameters
    extends AsymmetricKeyParameter
{
    XWingKeyParameters(
        boolean isPrivate)
    {
        super(isPrivate);
    }
}
