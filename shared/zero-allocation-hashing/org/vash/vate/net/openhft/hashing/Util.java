/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package org.vash.vate.net.openhft.hashing;

public final class Util {

    /* Known java.vm.name list:
     *
     *   HotSpot:
     *   - Java HotSpot(TM) xx-Bit Server VM
     *   - OpenJDK xx-Bit Server VM
     *
     *   J9:
     *   - Eclipse OpenJ9 VM
     *   - IBM J9 VM
     */

    static void checkArrayOffs(final int arrayLength, final int off, final int len) {
        if (len < 0 || off < 0 || off + len > arrayLength || off + len < 0)
            throw new IndexOutOfBoundsException();
    }

//    static long getDirectBufferAddress(final ByteBuffer buff) {
//        return ((DirectBuffer)buff).address();
//    }
}
