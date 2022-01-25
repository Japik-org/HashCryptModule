package com.pro100kryto.server.modules.hashcrypt;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.pro100kryto.server.module.AModule;
import com.pro100kryto.server.module.BaseModuleSettings;
import com.pro100kryto.server.module.ModuleConnectionParams;
import com.pro100kryto.server.module.ModuleParams;
import com.pro100kryto.server.modules.crypt.connection.ICryptModuleConnection;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class HashCryptModule extends AModule<ICryptModuleConnection> {
    public HashCryptModule(ModuleParams moduleParams) {
        super(moduleParams);
    }

    @Override
    protected @NotNull ICryptModuleConnection createModuleConnection(ModuleConnectionParams params) {
        final HashFunction hashFunction;
        String ha = settings.getOrDefault("hashing-algorithm", "sha512").toLowerCase();
        switch (ha){
            case "sha512":
                hashFunction = Hashing.sha512();
                break;
            case "sha384":
                hashFunction = Hashing.sha384();
                break;
            case "sha256":
                hashFunction = Hashing.sha256();
                break;
            case "sha1":
                hashFunction = Hashing.sha1();
                break;
            case "md5":
                hashFunction = Hashing.md5();
                break;
            case "crc32":
                hashFunction = Hashing.crc32();
                break;
            case "crc32c":
                hashFunction = Hashing.crc32c();
                break;
            case "adler32":
                hashFunction = Hashing.adler32();
                break;

            default:
                throw new IllegalArgumentException("Unknown hashing algorithm '" + ha + "'");
        }

        final int saltLen = settings.getIntOrDefault("salt-length", 64);
        final byte[] localSalt;

        if (settings.containsKey("salt-local")) {
            localSalt = settings.get("salt-local").getBytes(StandardCharsets.UTF_8);
        } else {
            localSalt = new byte[saltLen];
            new Random().nextBytes(localSalt);
            logger.info("random local salt is " + Arrays.toString(localSalt));
        }

        return new HashCryptModuleConnection(this, params, hashFunction,
                saltLen,
                localSalt
        );
    }

    @Override
    protected void setupSettingsBeforeInit() throws Throwable {
        settings.put(BaseModuleSettings.KEY_CONNECTION_MULTIPLE_ENABLED, false);
        settings.put(BaseModuleSettings.KEY_CONNECTION_CREATE_AFTER_INIT_ENABLED, true);

        super.setupSettingsBeforeInit();
    }
}
