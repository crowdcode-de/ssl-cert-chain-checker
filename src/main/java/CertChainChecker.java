import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Created by marcus on 20.06.2017.
 */
public class CertChainChecker {

    public static void main(String[] argv) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (argv == null || argv.length != 4) {
            System.out.println("params: <keyStoreType> <password> <keyAlias> <pathToCert>");
            System.out.println("example: JKS foobar example /tmp/mystore.jks");
            System.exit(0);
        }

        String keyStoreType = argv[0];
        String password = argv[1];
        String keyAlias = argv[2];
        String filePath = argv[3];
        FileInputStream inputStream = new FileInputStream((new File(filePath)).getAbsolutePath());
        KeyStore store = KeyStore.getInstance(keyStoreType);
        store.load(inputStream, password.toCharArray());
        Certificate[] certs = store.getCertificateChain(keyAlias);
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(1, certs[0].getPublicKey());
    }
}
