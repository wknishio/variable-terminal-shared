/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package org.vash.vate.net.openhft.hashing;

import org.vash.vate.io.airlift.compress.SafeUtils;

import static org.vash.vate.net.openhft.hashing.Primitives.*;

import java.nio.ByteOrder;

public class UnsafeAccess extends Access<byte[]> {
    static final UnsafeAccess INSTANCE = new UnsafeAccess();

    static final long BOOLEAN_BASE = 0;
    static final long BYTE_BASE = 0;
    static final long CHAR_BASE = 0;
    static final long SHORT_BASE = 0;
    static final long INT_BASE = 0;
    static final long LONG_BASE = 0;

    static final byte TRUE_BYTE_VALUE = 0;
    static final byte FALSE_BYTE_VALUE = 0;

    private UnsafeAccess() {}

    
    public long getLong(byte[] input, long offset) {
        return SafeUtils.readLong(input, (int) offset);
    }

    
    public long getUnsignedInt(byte[] input, long offset) {
        return unsignedInt(getInt(input, offset));
    }

    
    public int getInt(byte[] input, long offset) {
        return SafeUtils.readInt(input, (int) offset);
    }

    
    public int getUnsignedShort(byte[] input, long offset) {
        return unsignedShort(getShort(input, offset));
    }

    
    public int getShort(byte[] input, long offset) {
        return SafeUtils.readShort(input, (int) offset);
    }

    
    public int getUnsignedByte(byte[] input, long offset) {
        return unsignedByte(getByte(input, offset));
    }

    
    public int getByte(byte[] input, long offset) {
        return SafeUtils.readByte(input, (int) offset);
    }

    public ByteOrder byteOrder(byte[] input)
    {
      return ByteOrder.LITTLE_ENDIAN;
    }

}
