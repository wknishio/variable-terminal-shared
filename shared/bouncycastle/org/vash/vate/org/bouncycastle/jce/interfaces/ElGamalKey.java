package org.vash.vate.org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHKey;

import org.vash.vate.org.bouncycastle.jce.spec.ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
