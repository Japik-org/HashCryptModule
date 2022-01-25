package com.pro100kryto.server.modules.hashcrypt;

import com.google.common.hash.HashFunction;
import com.pro100kryto.server.module.AModuleConnection;
import com.pro100kryto.server.module.ModuleConnectionParams;
import com.pro100kryto.server.modules.crypt.connection.ICryptModuleConnection;
import org.jetbrains.annotations.NotNull;

import java.rmi.RemoteException;
import java.util.Random;

public final class HashCryptModuleConnection extends AModuleConnection<HashCryptModule, ICryptModuleConnection> implements ICryptModuleConnection {

    private final Random random = new Random();
    private final HashFunction hashFunction;
    private final int saltLen;
    private final byte[] localSalt;

    public HashCryptModuleConnection(@NotNull HashCryptModule module, ModuleConnectionParams params,
                                     HashFunction hashFunction, int saltLen, byte[] localSalt) {
        super(module, params);
        this.hashFunction = hashFunction;
        this.saltLen = saltLen;
        this.localSalt = localSalt;
    }

    @Override
    public int getCryptLen() {
        return hashFunction.bits()/8;
    }

    @Override
    public byte[] crypt(byte[] cryptOut, byte[] data, byte[] salt) throws RemoteException {
        hashFunction.hashBytes(
                combineSalt(
                        data,
                        combineSalt(localSalt, salt)
                )
        ).writeBytesTo(cryptOut, 0, cryptOut.length);
        return cryptOut;
    }

    @Override
    public byte[] decrypt(byte[] dataOut, byte[] crypt, byte[] salt) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getSaltLen() {
        return saltLen;
    }

    @Override
    public byte[] randomSalt(byte[] saltOut) {
        random.nextBytes(saltOut);
        return saltOut;
    }

    @Override
    public byte[] combineSalt(byte[] saltOut, byte[] salt1, byte[] salt2) {
        System.arraycopy(salt1, 0, saltOut, 0, Math.min(salt1.length, saltOut.length));
        for (int i = 0; i < Math.max(salt2.length, saltOut.length); i++) {
            saltOut[i%saltOut.length] += salt2[i%salt2.length];
        }
        return saltOut;
    }
}
