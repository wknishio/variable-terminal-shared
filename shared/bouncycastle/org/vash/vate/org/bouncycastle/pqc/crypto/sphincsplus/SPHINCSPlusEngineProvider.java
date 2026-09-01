package org.vash.vate.org.bouncycastle.pqc.crypto.sphincsplus;

interface SPHINCSPlusEngineProvider
{
    int getN();

    SPHINCSPlusEngine get();
}
