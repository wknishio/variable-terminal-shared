package org.vash.vate.org.bouncycastle.cms.bc;

import org.vash.vate.org.bouncycastle.asn1.cms.KEKIdentifier;
import org.vash.vate.org.bouncycastle.cms.KEKRecipientInfoGenerator;
import org.vash.vate.org.bouncycastle.operator.bc.BcSymmetricKeyWrapper;

public class BcKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        super(kekIdentifier, kekWrapper);
    }

    public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper);
    }
}
