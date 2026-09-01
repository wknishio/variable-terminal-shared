package org.vash.vate.org.bouncycastle.math.ec.endo;

import org.vash.vate.org.bouncycastle.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
