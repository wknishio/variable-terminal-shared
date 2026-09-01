package org.vash.vate.org.bouncycastle.jcajce.interfaces;

import java.security.Key;

import org.vash.vate.org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

public interface SLHDSAKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SLHDSAParameterSpec
     */
    SLHDSAParameterSpec getParameterSpec();
}
