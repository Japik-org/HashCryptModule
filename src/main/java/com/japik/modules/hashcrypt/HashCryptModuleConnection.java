package com.japik.modules.hashcrypt;

import com.google.common.hash.HashFunction;
import com.japik.module.AModuleConnection;
import com.japik.module.ModuleConnectionParams;
import com.japik.modules.crypt.connection.ICryptModuleConnection;
import org.jetbrains.annotations.NotNull;

import java.rmi.RemoteException;
import java.util.Random;

public final class HashCryptModuleConnection
        extends AModuleConnection<HashCryptModule, ICryptModuleConnection>
        implements ICryptModuleConnection {

    private final Random random = new Random();
    private final HashFunction hashFunction;
    private final byte[] localSalt;

    public HashCryptModuleConnection(@NotNull HashCryptModule module, ModuleConnectionParams params,
                                     HashFunction hashFunction, byte[] localSalt) {
        super(module, params);
        this.hashFunction = hashFunction;
        this.localSalt = localSalt;
    }

    @Override
    public byte[] crypt(byte[] data, byte[] salt) throws RemoteException {
        return hashFunction.hashBytes(
                combine(
                        data,
                        combine(localSalt, salt)
                )
        ).asBytes();
    }

    @Override
    public byte[] decrypt(byte[] crypt, byte[] salt) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] randomSalt(int len) {
        byte[] saltOut = new byte[len];
        random.nextBytes(saltOut);
        return saltOut;
    }

    @Override
    public byte[] combine(byte[] arr1, byte[] arr2) {
        final int len = Math.max(arr1.length, arr2.length);
        byte[] out = new byte[len];
        System.arraycopy(arr1, 0, out, 0, arr1.length);
        for (int i = 0; i < arr2.length; i++) {
            out[i] += arr2[i];
        }
        return out;
    }
}
