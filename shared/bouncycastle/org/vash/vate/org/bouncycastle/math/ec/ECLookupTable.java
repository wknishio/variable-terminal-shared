package org.vash.vate.org.bouncycastle.math.ec;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
    ECPoint lookupVar(int index);
}
