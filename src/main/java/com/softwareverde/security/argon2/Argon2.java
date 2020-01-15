package com.softwareverde.security.argon2;

import com.softwareverde.util.HexUtil;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;

public class Argon2 {
    protected static final int DEFAULT_ARGON2_TYPE = Argon2Parameters.ARGON2_id;
    protected static final int DEFAULT_ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;
    protected static final int DEFAULT_ITERATION_COUNT = 12;
    protected static final int DEFAULT_MEMORY_FOOTPRINT_POWER_OF_2 = 16; // 2**16 kB = 64MB
    protected static final int DEFAULT_THREAD_COUNT = 2;
    protected static final int DEFAULT_SALT_LENGTH_BYTES = 16;
    protected static final int DEFAULT_OUTPUT_BYTE_COUNT = 32;

    private final Argon2Parameters.Builder _parametersBuilder;
    private final int _argon2Type;
    private final int _argon2Version;
    private final int _iterations;
    private final int _allowedMemoryPowerOf2;
    private final int _threadCount;
    private final byte[] _salt;
    private final int _outputByteCount;

    protected static byte[] _newSalt() {
        final byte[] salt = new byte[DEFAULT_SALT_LENGTH_BYTES];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public Argon2() {
        this(Argon2._newSalt());
    }

    public Argon2(final int iterations, final int allowedMemoryPowerOf2, final int threadCount) {
        this(DEFAULT_ARGON2_TYPE, DEFAULT_ARGON2_VERSION, iterations, allowedMemoryPowerOf2, threadCount, Argon2._newSalt());
    }

    public Argon2(final int argon2Type, final int argon2Version, final int iterations, final int allowedMemoryPowerOf2, final int threadCount) {
        this(DEFAULT_ARGON2_TYPE, DEFAULT_ARGON2_VERSION, DEFAULT_ITERATION_COUNT, DEFAULT_MEMORY_FOOTPRINT_POWER_OF_2, DEFAULT_THREAD_COUNT, Argon2._newSalt());
    }

    public Argon2(final byte[] salt) {
        this(DEFAULT_ITERATION_COUNT, DEFAULT_MEMORY_FOOTPRINT_POWER_OF_2, DEFAULT_THREAD_COUNT, salt);
    }

    public Argon2(final int iterations, final int allowedMemoryKb, final int threadCount, final byte[] salt) {
        this(DEFAULT_ARGON2_TYPE, DEFAULT_ARGON2_VERSION, iterations, allowedMemoryKb, threadCount, salt);
    }

    public Argon2(final int argon2Type, final int argon2Version, final int iterations, final int allowedMemoryPowerOf2, final int threadCount, final byte[] salt) {
        this(argon2Type, argon2Version, iterations, allowedMemoryPowerOf2, threadCount, salt, DEFAULT_OUTPUT_BYTE_COUNT);
    }

    public Argon2(final int argon2Type, final int argon2Version, final int iterations, final int allowedMemoryPowerOf2, final int threadCount, final byte[] salt, final int outputByteCount) {
        _parametersBuilder = new Argon2Parameters.Builder(argon2Type)
                .withVersion(argon2Version)
                .withIterations(iterations)
                .withMemoryPowOfTwo(allowedMemoryPowerOf2)
                .withParallelism(threadCount)
                .withSalt(salt);

        _argon2Type = argon2Type;
        _argon2Version = argon2Version;
        _iterations = iterations;
        _allowedMemoryPowerOf2 = allowedMemoryPowerOf2;
        _threadCount = threadCount;
        _salt = salt;
        _outputByteCount = outputByteCount;
    }

    public Argon2(final String parameterString) {
        final String[] parameters = parameterString.split("\\$");
        final int minParameterCount = 8;
        final int maxParameterCount = 9;
        if (parameters.length < minParameterCount || parameters.length > maxParameterCount) {
            throw new IllegalArgumentException("Invalid parameter string: expected " + minParameterCount + " to " + maxParameterCount + " parameters, found " + parameters.length);
        }

        final String hashIndicator = parameters[0];
        if (! "Argon2".equals(hashIndicator)) {
            throw new IllegalArgumentException("Invalid hash type: " + parameters[0]);
        }
        _argon2Type = Integer.parseInt(parameters[1]);
        _argon2Version = Integer.parseInt(parameters[2]);
        _iterations = Integer.parseInt(parameters[3]);
        _allowedMemoryPowerOf2 = Integer.parseInt(parameters[4]);
        _threadCount = Integer.parseInt(parameters[5]);
        _salt = HexUtil.hexStringToByteArray(parameters[6]);
        _outputByteCount = Integer.parseInt(parameters[7]);

        _parametersBuilder = new Argon2Parameters.Builder(_argon2Type)
                .withVersion(_argon2Version)
                .withIterations(_iterations)
                .withMemoryPowOfTwo(_allowedMemoryPowerOf2)
                .withParallelism(_threadCount)
                .withSalt(_salt);
    }

    public int getArgon2Type() {
        return _argon2Type;
    }

    public int getArgon2Version() {
        return _argon2Version;
    }

    public int getIterations() {
        return _iterations;
    }

    public int getAllowedMemoryPowerOf2() {
        return _allowedMemoryPowerOf2;
    }

    public int getThreadCount() {
        return _threadCount;
    }

    public byte[] getSalt() {
        return _salt;
    }

    public int getOutputByteCount() {
        return _outputByteCount;
    }

    public byte[] generate(final byte[] inputData) {
        final Argon2BytesGenerator argon2BytesGenerator = new Argon2BytesGenerator();
        argon2BytesGenerator.init(_parametersBuilder.build());

        final byte[] result = new byte[_outputByteCount];
        argon2BytesGenerator.generateBytes(inputData, result);
        return result;
    }

    public byte[] generate(final char[] password) {
        final Argon2BytesGenerator argon2BytesGenerator = new Argon2BytesGenerator();
        argon2BytesGenerator.init(_parametersBuilder.build());

        final byte[] result = new byte[_outputByteCount];
        argon2BytesGenerator.generateBytes(password, result);
        return result;
    }

    public String getParameterString() {
        return _getParameterString();
    }

    private String _getParameterString() {
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Argon2$");
        stringBuilder.append(_argon2Type);
        stringBuilder.append("$");
        stringBuilder.append(_argon2Version);
        stringBuilder.append("$");
        stringBuilder.append(_iterations);
        stringBuilder.append("$");
        stringBuilder.append(_allowedMemoryPowerOf2);
        stringBuilder.append("$");
        stringBuilder.append(_threadCount);
        stringBuilder.append("$");
        stringBuilder.append(HexUtil.toHexString(_salt));
        stringBuilder.append("$");
        stringBuilder.append(_outputByteCount);
        return stringBuilder.toString();
    }

    public String generateParameterizedHash(final byte[] inputData) {
        final byte[] result = this.generate(inputData);
        return _toParameterizedHash(result);
    }

    public String generateParameterizedHash(final char[] password) {
        final byte[] result = this.generate(password);
        return _toParameterizedHash(result);
    }

    private String _toParameterizedHash(final byte[] result) {
        final StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append(_getParameterString());
        stringBuilder.append("$");
        stringBuilder.append(HexUtil.toHexString(result));

        return stringBuilder.toString();
    }
}
