package org.vash.vate.org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface EdDSAPublicKey
    extends EdDSAKey, PublicKey
{
    byte[] getPointEncoding();
}
