import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;

public class ExtractKeyId {

	public static void main(String[] args) throws Exception {
		List<String> keyIds = new ArrayList<String>();
		ArmoredInputStream ais = (ArmoredInputStream)
				PGPUtil.getDecoderStream(new FileInputStream(new File(args[0])));
		
		// Extract keyIds based on the header.
		String header = ais.getArmorHeaderLine();
		if (header.contains("PUBLIC KEY")) {
			keyIds = extractPublicKeyIds(ais);
		} else if (header.contains("PRIVATE KEY")) {
			keyIds = extractPrivateKeyIds(ais);
		} else if (header.contains("PGP MESSAGE")) {
			keyIds = extractMessageKeyIds(ais);
		} else {
			System.err.println("unrecognized header: " + header);
		}

		System.out.println("\n" + header +"\nExtracted the following keyIds...");
		for (String keyId : keyIds) {
			System.out.println(keyId);
		}
	}

	private static List<String> extractMessageKeyIds(ArmoredInputStream ais) {
		ArrayList<String> keys = new ArrayList<String>();
		try {
			PGPObjectFactory factory = new PGPObjectFactory(ais,null);
			@SuppressWarnings("unchecked")
			Iterator<PGPEncryptedDataList> factoryIterator = factory.iterator();
			while (factoryIterator.hasNext()) {
				PGPEncryptedDataList edl = factoryIterator.next();
				
				@SuppressWarnings("unchecked")
				Iterator<PGPEncryptedData> edlIterator = edl.iterator();
				while (edlIterator.hasNext()) {
					PGPEncryptedData ped = edlIterator.next();
					String className = ped.getClass().getName();
					if (className.equals("org.bouncycastle.openpgp.PGPPublicKeyEncryptedData")) {
						System.out.println("Extracting keyId from " + ped.getClass().getName());
						keys.add(Long.toHexString(((PGPPublicKeyEncryptedData)ped).getKeyID()));
					} else {
						System.out.println("Skipping " + ped.getClass().getName());
					}
				}
			}
		} catch (Exception e) {
			// Do nothing
		}
		return keys;
	}
	
	private static List<String> extractPublicKeyIds(ArmoredInputStream ais) {
		ArrayList<String> keys = new ArrayList<String>();
		try {
			JcaPGPPublicKeyRingCollection pubRings = new JcaPGPPublicKeyRingCollection(ais);
			Iterator<PGPPublicKeyRing> it = pubRings.getKeyRings();
			while (it.hasNext()) {
				PGPPublicKeyRing pubRing = it.next();
				PGPPublicKey publicKey = pubRing.getPublicKey();
				System.out.println("Extracting keyId from " + publicKey.getClass().getName());
				keys.add(Long.toHexString(publicKey.getKeyID()));
			}
		} catch (Exception e) {
			// Do nothing
		}
		return keys;
	}

	private static List<String> extractPrivateKeyIds(ArmoredInputStream ais) {
		ArrayList<String> keys = new ArrayList<String>();
		try {
			JcaPGPSecretKeyRingCollection privRings = new JcaPGPSecretKeyRingCollection(ais);
			Iterator<PGPSecretKeyRing> it = privRings.getKeyRings();
			while (it.hasNext()) {
				PGPSecretKeyRing privRing = it.next();
				PGPSecretKey privKey = privRing.getSecretKey();
				System.out.println("Extracting keyId from " + privKey.getClass().getName());
				keys.add(Long.toHexString(privKey.getKeyID()));
			}
		} catch (Exception e) {
			// Do nothing
		}
		return keys;
	}
}
