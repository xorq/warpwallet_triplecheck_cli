



import java.io.*;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import static java.lang.System.getProperty;
import static java.util.regex.Pattern.CASE_INSENSITIVE;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

import static java.lang.Integer.MAX_VALUE;
import static java.lang.System.arraycopy;

import java.util.Arrays;
//import junit.framework.TestCase;

//import com.lambdaworks.crypto.SCrypt;
//import org.junit.Test;

//import static org.junit.Assert.*;

class dataconv {
	static String toHexString(byte[] bytes) {
	    char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j*2] = hexArray[v/16];
	        hexChars[j*2 + 1] = hexArray[v%16];
	    }
	    return new String(hexChars);
	}
}

class PBKDF {
    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param   alg     HMAC algorithm to use.
     * @param   P       Password.
     * @param   S       Salt.
     * @param   c       Iteration count.
     * @param   dkLen   Intended length, in octets, of the derived key.
     *
     * @return  The derived key.
     *
     * @throws  GeneralSecurityException
     */
    static byte[] pbkdf2(String alg, byte[] P, byte[] S, int c, int dkLen) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(alg);
        mac.init(new SecretKeySpec(P, alg));
        byte[] DK = new byte[dkLen];
        pbkdf2(mac, S, c, DK, dkLen);
        return DK;
    }

    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param   mac     Pre-initialized {@link Mac} instance to use.
     * @param   S       Salt.
     * @param   c       Iteration count.
     * @param   DK      Byte array that derived key will be placed in.
     * @param   dkLen   Intended length, in octets, of the derived key.
     *
     * @throws  GeneralSecurityException
     */
    static void pbkdf2(Mac mac, byte[] S, int c, byte[] DK, int dkLen) throws GeneralSecurityException {
        int hLen = mac.getMacLength();

        if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
            throw new GeneralSecurityException("Requested key length too long");
        }

        byte[] U      = new byte[hLen];
        byte[] T      = new byte[hLen];
        byte[] block1 = new byte[S.length + 4];

        int l = (int) Math.ceil((double) dkLen / hLen);
        int r = dkLen - (l - 1) * hLen;

        arraycopy(S, 0, block1, 0, S.length);

        for (int i = 1; i <= l; i++) {
            block1[S.length + 0] = (byte) (i >> 24 & 0xff);
            block1[S.length + 1] = (byte) (i >> 16 & 0xff);
            block1[S.length + 2] = (byte) (i >> 8  & 0xff);
            block1[S.length + 3] = (byte) (i >> 0  & 0xff);

            mac.update(block1);
            mac.doFinal(U, 0);
            arraycopy(U, 0, T, 0, hLen);

            for (int j = 1; j < c; j++) {
                mac.update(U);
                mac.doFinal(U, 0);

                for (int k = 0; k < hLen; k++) {
                    T[k] ^= U[k];
                }
            }

            arraycopy(T, 0, DK, (i - 1) * hLen, (i == l ? r : hLen));
        }
    }
}




class CryptoTestUtil {
    public static byte[] decode(String str) {
        byte[] bytes = new byte[str.length() / 2];
        int index = 0;

        for (int i = 0; i < str.length(); i += 2) {
            int high = hexValue(str.charAt(i));
            int low = hexValue(str.charAt(i + 1));
            bytes[index++] = (byte) ((high << 4) + low);
        }

        return bytes;
    }

    public static int hexValue(char c) {
        return c >= 'a' ? c - 87 : c - 48;
    }
}



/**
 * A native library loader that will extract and load a shared library contained in a jar.
 * This loader will attempt to detect the {@link Platform platform} (CPU architecture and OS)
 * it is running on and load the appropriate shared library.
 *
 * Given a library path and name this loader looks for a native library with path
 * [libraryPath]/[arch]/[os]/lib[name].[ext]
 *
 * @author Will Glozer
 */
class JarLibraryLoader implements LibraryLoader {
    private final CodeSource codeSource;
    private final String libraryPath;

    /**
     * Initialize a new instance that looks for shared libraries located in the same jar
     * as this class and with a path starting with {@code lib}.
     */
    public JarLibraryLoader() {
        this(JarLibraryLoader.class.getProtectionDomain().getCodeSource(), "lib");
    }

    /**
     * Initialize a new instance that looks for shared libraries located in the specified
     * directory of the supplied code source.
     *
     * @param codeSource    Code source containing shared libraries.
     * @param libraryPath   Path prefix of shared libraries.
     */
    public JarLibraryLoader(CodeSource codeSource, String libraryPath) {
        this.codeSource  = codeSource;
        this.libraryPath = libraryPath;
    }

    /**
     * Load a shared library, and optionally verify the jar signatures.
     *
     * @param name      Name of the library to load.
     * @param verify    Verify the jar file if signed.
     *
     * @return true if the library was successfully loaded.
     */
    public boolean load(String name, boolean verify) {
        boolean loaded = false;

        try {
            Platform platform = Platform.detect();
            JarFile jar = new JarFile(codeSource.getLocation().getPath(), verify);
            try {
                for (String path : libCandidates(platform, name)) {
                    JarEntry entry = jar.getJarEntry(path);
                    if (entry == null) continue;

                    File lib = extract(name, jar.getInputStream(entry));
                    System.load(lib.getAbsolutePath());
                    lib.delete();

                    loaded = true;
                    break;
                }
            } finally {
                jar.close();
            }
        } catch (Throwable e) {
            loaded = false;
        }

        return loaded;
    }

    /**
     * Extract a jar entry to a temp file.
     *
     * @param name  Name prefix for temp file.
     * @param is    Jar entry input stream.
     *
     * @return A temporary file.
     *
     * @throws IOException when an IO error occurs.
     */
    private static File extract(String name, InputStream is) throws IOException {
        byte[] buf = new byte[4096];
        int len;

        File lib = File.createTempFile(name, "lib");
        FileOutputStream os = new FileOutputStream(lib);

        try {
            while ((len = is.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
        } catch (IOException e) {
            lib.delete();
            throw e;
        } finally {
            os.close();
            is.close();
        }

        return lib;
    }

    /**
     * Generate a list of candidate libraries for the supplied library name and suitable
     * for the current platform.
     *
     * @param platform  Current platform.
     * @param name      Library name.
     *
     * @return List of potential library names.
     */
    private List<String> libCandidates(Platform platform, String name) {
        List<String> candidates = new ArrayList<String>();
        StringBuilder sb = new StringBuilder();

        sb.append(libraryPath).append("/");
        sb.append(platform.arch).append("/");
        sb.append(platform.os).append("/");
        sb.append("lib").append(name);

        switch (platform.os) {
            case darwin:
                candidates.add(sb + ".dylib");
                candidates.add(sb + ".jnilib");
                break;
            case linux:
            case freebsd:
                candidates.add(sb + ".so");
                break;
        }

        return candidates;
    }
}
/**
 * A {@code LibraryLoader} attempts to load the appropriate native library
 * for the current platform.
 *
 * @author Will Glozer
 */
interface LibraryLoader {
    /**
     * Load a native library, and optionally verify any signatures.
     *
     * @param name      Name of the library to load.
     * @param verify    Verify signatures if signed.
     *
     * @return true if the library was successfully loaded.
     */
    boolean load(String name, boolean verify);
}

// Copyright (C) 2011 - Will Glozer.  All rights reserved.


/**
 * {@code LibraryLoaders} will create the appropriate {@link LibraryLoader} for
 * the VM it is running on.
 *
 * The system property {@code com.lambdaworks.jni.loader} may be used to override
 * loader auto-detection, or to disable loading native libraries entirely via use
 * of the nil loader.
 *
 * @author Will Glozer
 */
class LibraryLoaders {
    /**
     * Create a new {@link LibraryLoader} for the current VM.
     *
     * @return the loader.
     */
    public static LibraryLoader loader() {
        String type = System.getProperty("com.lambdaworks.jni.loader");

        if (type != null) {
            if (type.equals("sys")) return new SysLibraryLoader();
            if (type.equals("nil")) return new NilLibraryLoader();
            if (type.equals("jar")) return new JarLibraryLoader();
            throw new IllegalStateException("Illegal value for com.lambdaworks.jni.loader: " + type);
        }

        String vmSpec = System.getProperty("java.vm.specification.name");
        return vmSpec.startsWith("Java") ? new JarLibraryLoader() : new SysLibraryLoader();
    }
}



// Copyright (C) 2013 - Will Glozer.  All rights reserved.

/**
 * A native library loader that refuses to load libraries.
 *
 * @author Will Glozer
 */
class NilLibraryLoader implements LibraryLoader {
    /**
     * Don't load a shared library.
     *
     * @param name      Name of the library to load.
     * @param verify    Ignored, no verification is done.
     *
     * @return false.
     */
    public boolean load(String name, boolean verify) {
        return false;
    }
}


// Copyright (C) 2011 - Will Glozer.  All rights reserved.



/**
 * A platform is a unique combination of CPU architecture and operating system. This class
 * attempts to determine the platform it is executing on by examining and normalizing the
 * <code>os.arch</code> and <code>os.name</code> system properties.
 *
 * @author Will Glozer
 */
class Platform {
    public enum Arch {
        x86   ("x86|i386"),
        x86_64("x86_64|amd64");

        Pattern pattern;

        Arch(String pattern) {
            this.pattern = Pattern.compile("\\A" + pattern + "\\Z", CASE_INSENSITIVE);
        }
    }

    public enum OS {
        darwin ("darwin|mac os x"),
        freebsd("freebsd"),
        linux  ("linux");

        Pattern pattern;

        OS(String pattern) {
            this.pattern = Pattern.compile("\\A" + pattern + "\\Z", CASE_INSENSITIVE);
        }
    }

    public final Arch arch;
    public final OS os;

    private Platform(Arch arch, OS os) {
        this.arch = arch;
        this.os = os;
    }

    /**
     * Attempt to detect the current platform.
     *
     * @return The current platform.
     *
     * @throws UnsupportedPlatformException if the platform cannot be detected.
     */
    public static Platform detect() throws UnsupportedPlatformException {
        String osArch = getProperty("os.arch");
        String osName = getProperty("os.name");

        for (Arch arch : Arch.values()) {
            if (arch.pattern.matcher(osArch).matches()) {
                for (OS os : OS.values()) {
                    if (os.pattern.matcher(osName).matches()) {
                        return new Platform(arch, os);
                    }
                }
            }
        }

        String msg = String.format("Unsupported platform %s %s", osArch, osName);
        throw new UnsupportedPlatformException(msg);
    }
}






// Copyright (C) 2011 - Will Glozer.  All rights reserved.


/**
 * A native library loader that simply invokes {@link System#loadLibrary}. The shared
 * library path and filename are platform specific.
 *
 * @author Will Glozer
 */
class SysLibraryLoader implements LibraryLoader {
    /**
     * Load a shared library.
     *
     * @param name      Name of the library to load.
     * @param verify    Ignored, no verification is done.
     *
     * @return true if the library was successfully loaded.
     */
    public boolean load(String name, boolean verify) {
        boolean loaded;

        try {
            System.loadLibrary(name);
            loaded = true;
        } catch (Throwable e) {
            loaded = false;
        }

        return loaded;
    }
}




// Copyright (C) 2011 - Will Glozer.  All rights reserved.

/**
 * Exception thrown when the current platform cannot be detected.
 *
 * @author Will Glozer
 */
class UnsupportedPlatformException extends RuntimeException {
    public UnsupportedPlatformException(String s) {
        super(s);
    }
}


















/**
 * An implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt</a>
 * key derivation function. This class will attempt to load a native library
 * containing the optimized C implementation from
 * <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a> and
 * fall back to the pure Java version if that fails.
 *
 * @author  Will Glozer
 */
class SCrypt {
    private static final boolean native_library_loaded;

    static {
        LibraryLoader loader = LibraryLoaders.loader();
        native_library_loaded = loader.load("scrypt", true);
    }

    /**
     * Implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a>.
     * Calls the native implementation {@link #scryptN} when the native library was successfully
     * loaded, otherwise calls {@link #scryptJ}.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException when HMAC_SHA256 is not available.
     */
    public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException {
        return native_library_loaded ? scryptN(passwd, salt, N, r, p, dkLen) : scryptJ(passwd, salt, N, r, p, dkLen);
    }

    /**
     * Native C implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a> using
     * the code from <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    public static native byte[] scryptN(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen);

    /**
     * Pure Java implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException when HMAC_SHA256 is not available.
     */
    public static byte[] scryptJ(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException {
        if (N < 2 || (N & (N - 1)) != 0) throw new IllegalArgumentException("N must be a power of 2 greater than 1");

        if (N > MAX_VALUE / 128 / r) throw new IllegalArgumentException("Parameter N is too large");
        if (r > MAX_VALUE / 128 / p) throw new IllegalArgumentException("Parameter r is too large");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(passwd, "HmacSHA256"));

        byte[] DK = new byte[dkLen];

        byte[] B  = new byte[128 * r * p];
        byte[] XY = new byte[256 * r];
        byte[] V  = new byte[128 * r * N];
        int i;

        PBKDF.pbkdf2(mac, salt, 1, B, p * 128 * r);

        for (i = 0; i < p; i++) {
            smix(B, i * 128 * r, r, N, V, XY);
        }

        PBKDF.pbkdf2(mac, B, 1, DK, dkLen);

        return DK;
    }

    public static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY) {
        int Xi = 0;
        int Yi = 128 * r;
        int i;

        arraycopy(B, Bi, XY, Xi, 128 * r);

        for (i = 0; i < N; i++) {
            arraycopy(XY, Xi, V, i * (128 * r), 128 * r);
            blockmix_salsa8(XY, Xi, Yi, r);
        }

        for (i = 0; i < N; i++) {
            int j = integerify(XY, Xi, r) & (N - 1);
            blockxor(V, j * (128 * r), XY, Xi, 128 * r);
            blockmix_salsa8(XY, Xi, Yi, r);
        }

        arraycopy(XY, Xi, B, Bi, 128 * r);
    }

    public static void blockmix_salsa8(byte[] BY, int Bi, int Yi, int r) {
        byte[] X = new byte[64];
        int i;

        arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

        for (i = 0; i < 2 * r; i++) {
            blockxor(BY, i * 64, X, 0, 64);
            salsa20_8(X);
            arraycopy(X, 0, BY, Yi + (i * 64), 64);
        }

        for (i = 0; i < r; i++) {
            arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
        }

        for (i = 0; i < r; i++) {
            arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
        }
    }

    public static int R(int a, int b) {
        return (a << b) | (a >>> (32 - b));
    }

    public static void salsa20_8(byte[] B) {
        int[] B32 = new int[16];
        int[] x   = new int[16];
        int i;

        for (i = 0; i < 16; i++) {
            B32[i]  = (B[i * 4 + 0] & 0xff) << 0;
            B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
            B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
            B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
        }

        arraycopy(B32, 0, x, 0, 16);

        for (i = 8; i > 0; i -= 2) {
            x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
            x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
            x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
            x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
            x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
            x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
            x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
            x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
            x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
            x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
            x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
            x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
            x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
            x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
            x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
            x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
        }

        for (i = 0; i < 16; ++i) B32[i] = x[i] + B32[i];

        for (i = 0; i < 16; i++) {
            B[i * 4 + 0] = (byte) (B32[i] >> 0  & 0xff);
            B[i * 4 + 1] = (byte) (B32[i] >> 8  & 0xff);
            B[i * 4 + 2] = (byte) (B32[i] >> 16 & 0xff);
            B[i * 4 + 3] = (byte) (B32[i] >> 24 & 0xff);
        }
    }

    public static void blockxor(byte[] S, int Si, byte[] D, int Di, int len) {
        for (int i = 0; i < len; i++) {
            D[Di + i] ^= S[Si + i];
        }
    }

    public static int integerify(byte[] B, int Bi, int r) {
        int n;

        Bi += (2 * r - 1) * 64;

        n  = (B[Bi + 0] & 0xff) << 0;
        n |= (B[Bi + 1] & 0xff) << 8;
        n |= (B[Bi + 2] & 0xff) << 16;
        n |= (B[Bi + 3] & 0xff) << 24;

        return n;
    }
}





public class scrypto{
	
   public static void main(String args[]) throws Exception {
		byte[] P = (args[0]).getBytes("UTF-8");
		byte[] S = (args[1]).getBytes("UTF-8");
		int    N = Integer.parseInt(args[2]);
		N = (int)Math.pow(2,N);
		int    r = Integer.parseInt(args[3]);
		int    p = Integer.parseInt(args[4]);
		int    buflen = Integer.parseInt(args[5]);
		System.out.println(dataconv.toHexString(SCrypt.scrypt(P, S, N, r, p, buflen)));
    }
}		

