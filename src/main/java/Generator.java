import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class Generator {
    public static long validityInMilliseconds = 36000000; // 10h

    public static void main(String[] args) {
        //Generator.generateKeys();
        Generator.generateToken();
    }

    public static  void generateKeys() {
        KeyPair kp = RsaProvider.generateKeyPair(2048);
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();
        Path path = Paths.get("your_certificate.pem");
        try {
            Files.write(path, Base64.getEncoder().encode(publicKey.getEncoded()));
            path = Paths.get("your_private_key.pem");
            Files.write(path, Base64.getEncoder().encode(privateKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static  void generateToken() {
        String prefix = "ROLE_";
        try {
            String realmPublicKey = Files.readAllLines(Paths.get("your_certificate.pem")).get(0);
            PublicKey publicKey = decodePublicKey(pemToDer(realmPublicKey));

            String realmPrivateKey = Files.readAllLines(Paths.get("your_private_key.pem")).get(0);
            PrivateKey privateKey = decodePrivateKey(pemToDer(realmPrivateKey));
            List list = new ArrayList<String>();
            list.add(prefix+"A");
            list.add(prefix+"U");
            User user = new User(1,"test@mail.ru", "ru");
            System.out.println("Bearer "+createToken("test",list,user,privateKey));

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }


    }

    public static String createToken(String username, List<String> roles, User user, PrivateKey privateKey) {

        Claims claims = Jwts.claims().setSubject(username);
        claims.put("auth", roles.stream().map(s -> new SimpleGrantedAuthority(s)).filter(Objects::nonNull).collect(Collectors.toList()));
        claims.put("user", user);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.RS256, privateKey)//
                .compact();
    }
    /**
     * Decode a PEM string to DER format
     *
     * @param pem
     * @return
     * @throws java.io.IOException
     */
    public static byte[] pemToDer(String pem) throws IOException {
        return Base64.getDecoder().decode(pem);
    }


    public static PublicKey decodePublicKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);

        KeyFactory kf = KeyFactory.getInstance("RSA"
                //        , "BC" //use provider BouncyCastle if available.
        );
        return kf.generatePublic(spec);
    }

    public static PrivateKey decodePrivateKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(der);

        KeyFactory kf = KeyFactory.getInstance("RSA"
                //        , "BC" //use provider BouncyCastle if available.
        );
        return kf.generatePrivate(pkcs8EncodedKeySpec);
    }

}
