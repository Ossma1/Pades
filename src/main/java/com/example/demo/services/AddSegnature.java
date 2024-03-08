package com.example.demo.services;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import com.itextpdf.commons.utils.FileUtil;
import com.itextpdf.forms.fields.properties.SignedAppearanceText;
import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfPadesSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.SignerProperties;


import java.io.FileOutputStream;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import com.itextpdf.forms.PdfAcroForm;


import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.signatures.*;


@Service
public class AddSegnature {
    public AddSegnature() {}
	private static final String CERT_PATH = System.getProperty("user.dir")+"/Files/mon_keystore.p12";

    public static final String SRC = System.getProperty("user.dir")+"/Files/hello.pdf";
    public static final String DEST = System.getProperty("user.dir")+"/Files/cv.pdf";
    public static final String IMAGE_PATH = System.getProperty("user.dir")+"/Files/Signature.svg";

    private static final String SIGNATURE_NAME = "Signature1";

    private static final char[] PASSWORD = "oussama".toCharArray();
    public String AddSignatureUsingAppearanceInstanceExample() throws Exception {
    	 try {
    	File file = new File(DEST);
        file.getParentFile().mkdirs();
        Security.addProvider(new BouncyCastleProvider());
        signSignature(SRC, DEST);
        return "La signature a été ajoutée avec succès,le fichier construit 'cv.pdf' existe dans le dossier File";
    	 } catch (Exception e) {
    	        e.printStackTrace();
    	        return "Erreur lors de l'ajout de la signature : "+e.getMessage();
    	    }
    }
    /**
     * Basic example of the signature appearance customizing during the document signing.
     *
     * @param src  source file
     * @param dest destination file
     *
     * @throws Exception in case some exception occurred.
     */
    public void signSignature(String src, String dest) throws Exception {
        PdfPadesSigner padesSigner = new PdfPadesSigner(new PdfReader(FileUtil.getInputStreamForFile(src)),
                FileUtil.getFileOutputStream(dest));
        // We can pass the appearance through the signer properties.
        SignerProperties signerProperties = createSignerProperties();

        padesSigner.signWithBaselineBProfile(signerProperties, getCertificateChain(CERT_PATH,PASSWORD), getPrivateKey(CERT_PATH,PASSWORD));
    }

    /**
     * Creates properties to be used in signing operations. Also creates the appearance that will be passed to the
     * PDF signer through the signer properties.
     *
     * @return {@link SignerProperties} properties to be used for main signing operation.
     *
     * @throws IOException in case an I/O error occurs when reading the file.
     */
    protected SignerProperties createSignerProperties() throws IOException {
        SignerProperties signerProperties = new SignerProperties().setFieldName("Signature1");

        // Create the appearance instance and set the signature content to be shown and different appearance properties.
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(signerProperties.getFieldName())
                .setContent(new SignedAppearanceText().setReasonLine("Customized reason: Reason").setLocationLine("Customized location: Location"), ImageDataFactory.create(IMAGE_PATH))
              ;

        // Note that if SignedAppearanceText is set as a content, description text will be generated automatically, but
        // any `visual` values can be changed by using the appropriate setters. This won't affect the signature dictionary.

        // Set created signature appearance and other signer properties.
        signerProperties
                .setSignatureAppearance(appearance)
                .setPageNumber(1)
                .setPageRect(new Rectangle(50, 650, 200, 100))
                .setReason("Reason")
                .setLocation("Location");
        return signerProperties;
    }

    /**
     * Creates signing chain for the sample. This chain shouldn't be used for the real signing.
     * @param certificatePath
     * @param password
     * @return the chain of certificates to be used for the signing operation.
     */
    private static Certificate[] getCertificateChain(String certificatePath, char[] password) throws Exception {
        Certificate[] certChain = null;

        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream(certificatePath), password);

        Enumeration<String> aliases = p12.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (p12.isKeyEntry(alias)) {
                certChain = p12.getCertificateChain(alias);
                break;
            }
        }
        return certChain;
    }

    /**
     * Creates private key for the sample. This key shouldn't be used for the real signing.
     * @param certificatePath
     * @param password
     * @return {@link PrivateKey} instance to be used for the main signing operation.
     */
    private static PrivateKeySignature getPrivateKey(String certificatePath, char[] password) throws Exception {
        PrivateKey pk = null;

        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream(certificatePath), password);

        Enumeration<String> aliases = p12.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (p12.isKeyEntry(alias)) {
                pk = (PrivateKey) p12.getKey(alias, password);
                break;
            }
        }
        Security.addProvider(new BouncyCastleProvider());
        return new PrivateKeySignature(pk, DigestAlgorithms.SHA512, BouncyCastleProvider.PROVIDER_NAME);
    }
    public Map<String, Boolean> verifiedSignature() throws GeneralSecurityException, IOException {
    	  Map<String, Boolean> Results= new HashMap<>();

    	    
    	Security.addProvider(new BouncyCastleProvider());
			        String signedPdfPath = DEST;
			
			        PdfDocument pdfDocument = new PdfDocument(new com.itextpdf.kernel.pdf.PdfReader(signedPdfPath));
			        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
			        List<String> names = signatureUtil.getSignatureNames();

			        for (String name : names) {
			            System.out.println("===== " + name + " =====");
			            
			            Results.put(name, verifySignature(signatureUtil, name));

			        }
			        pdfDocument.close();
			      return Results;
			        
			}
			    private  boolean verifySignature(SignatureUtil signUtil, String name) throws GeneralSecurityException {
			        PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
			
			        System.out.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
			        System.out.println("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
			        System.out.println("Integrity and Authenticity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());
			        return pkcs7.verifySignatureIntegrityAndAuthenticity();
			    }      
    
}
