package org.vash.vate.org.bouncycastle.jcajce.interfaces;

import org.vash.vate.org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import java.security.Key;

public interface MLKEMKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a MLKEMParameterSpec
     */
    MLKEMParameterSpec getParameterSpec();
}
