package com.japik.modules.hashcrypt;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.japik.livecycle.controller.LiveCycleController;
import com.japik.livecycle.controller.LiveCycleImplId;
import com.japik.module.AModule;
import com.japik.module.BaseModuleSettings;
import com.japik.module.ModuleConnectionParams;
import com.japik.module.ModuleParams;
import com.japik.modules.crypt.connection.ICryptModuleConnection;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.Charset;
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

        final byte[] localSalt;

        final String type = settings.getOrDefault("salt-local-type", "disabled");

        if (type.equals("random")) {
            localSalt = new byte[settings.getIntOrDefault("salt-local-length", 64)];
            new Random().nextBytes(localSalt);
            logger.info("random local salt is " + Arrays.toString(localSalt));

        } else if (type.equals("charset")) {
            localSalt = settings.get("salt-local").getBytes(Charset.forName(settings.getOrDefault("salt-local-charset", "UTF-8")));

        } else {
            localSalt = new byte[0];
            logger.warn("local salt is disabled!");
        }

        return new HashCryptModuleConnection(this,
                params,
                hashFunction,
                localSalt
        );
    }

    @Override
    protected void initLiveCycleController(LiveCycleController liveCycleController) {
        super.initLiveCycleController(liveCycleController);

        liveCycleController.getInitImplQueue().put(new LiveCycleImplId(
                "put settings",
                LiveCycleController.PRIORITY_HIGHEST
        ), () -> {
            settings.put(BaseModuleSettings.KEY_CONNECTION_MULTIPLE_ENABLED, false);
            settings.put(BaseModuleSettings.KEY_CONNECTION_CREATE_AFTER_INIT_ENABLED, true);
        });
    }
}
