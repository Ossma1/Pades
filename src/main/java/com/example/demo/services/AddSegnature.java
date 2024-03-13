package com.example.demo.services;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import com.itextpdf.commons.utils.FileUtil;
import com.itextpdf.forms.fields.properties.SignedAppearanceText;
import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.io.source.ByteArrayOutputStream;
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
	//private static final String CERT_PATH = System.getProperty("user.dir")+"/Files/mon_keystore.p12";

    //public static final String SRC = System.getProperty("user.dir")+"/Files/hello.pdf";
    public static final String DEST = System.getProperty("user.dir")+"/Files/cv.pdf";
    public static final String IMAGE_PATH = System.getProperty("user.dir")+"/Files/Signature.svg";


    private static final char[] PASSWORD = "oussama".toCharArray();
    
    public byte[] AddSignatureUsingAppearanceInstanceExample(byte[] pdfContent, byte[] certificateBytes) throws Exception {
//    	File file = new File(DEST);
//      file.getParentFile().mkdirs();
        Security.addProvider(new BouncyCastleProvider());
        return signSignature(pdfContent, certificateBytes);
    	 
    }
  
    public byte[] signSignature(byte[] pdfContent, byte[] certificateBytes) throws Exception {
    	try (ByteArrayInputStream pdfInputStream = new ByteArrayInputStream(pdfContent);
    	         ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
    	        PdfPadesSigner padesSigner = new PdfPadesSigner(new PdfReader(pdfInputStream),
    	        		outputStream);
    	        SignerProperties signerProperties = createSignerProperties();

    	        padesSigner.signWithBaselineBProfile(signerProperties, getCertificateChain(certificateBytes,PASSWORD), getPrivateKey(certificateBytes,PASSWORD));
    	    	  return outputStream.toByteArray();
    
    	}
    }

   
    protected SignerProperties createSignerProperties() throws IOException {
        SignerProperties signerProperties = new SignerProperties().setFieldName("Signature1");

        SignatureFieldAppearance appearance = new SignatureFieldAppearance(signerProperties.getFieldName())
                .setContent(new SignedAppearanceText().setReasonLine("Customized reason: Reason").setLocationLine("Customized location: Location"), ImageDataFactory.create(IMAGE_PATH))
              ;
        signerProperties
                .setSignatureAppearance(appearance)
                .setPageNumber(1)
                .setPageRect(new Rectangle(50, 650, 200, 100))
                .setReason("Reason")
                .setLocation("Location");
        return signerProperties;
    }


    private static Certificate[] getCertificateChain(byte[] certificateBytes, char[] password) throws Exception {
        Certificate[] certChain = null;

        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new  ByteArrayInputStream(certificateBytes), password);

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

    private static PrivateKeySignature getPrivateKey(byte[] certificateBytes, char[] password) throws Exception {
        PrivateKey pk = null;

        KeyStore p12 = KeyStore.getInstance("pkcs12");
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes)) {
            p12.load(inputStream, password);

            Enumeration<String> aliases = p12.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (p12.isKeyEntry(alias)) {
                    pk = (PrivateKey) p12.getKey(alias, password);
                    break;
                }
            }
        }

        Security.addProvider(new BouncyCastleProvider());
        return new PrivateKeySignature(pk, DigestAlgorithms.SHA512, BouncyCastleProvider.PROVIDER_NAME);
    }
    
    public byte[] PdfSignedToPadesService(byte[] pdfContent, byte[] certificateBytes) throws Exception {
    	  CMSSignedData cmsSignedData = new CMSSignedData(pdfContent);
          SignerInformation signerInfo = (SignerInformation) cmsSignedData.getSignerInfos().getSigners().iterator().next();
          Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();
          Collection<X509CertificateHolder> certHolders = certificates.getMatches(signerInfo.getSID());
          if (certHolders.size() != 1) {
              throw new IllegalStateException("Impossible de récupérer le certificat associé à la signature.");
          }
          X509CertificateHolder certHolder = certHolders.iterator().next();
          X509Certificate certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
          boolean verifie = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(certificate));
          System.out.print(verifie);
          if (verifie) {
              return signSignature(pdfContent, certificateBytes);
 
          }
          return pdfContent;
      
      
    	
    }
    public Map<String, Boolean> verifiedSignature(byte[] pdfSigneContent) throws GeneralSecurityException, IOException {
    	  Map<String, Boolean> Results= new HashMap<>();

    	    
    	Security.addProvider(new BouncyCastleProvider());
			
			        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(pdfSigneContent)) {

			        PdfDocument pdfDocument = new PdfDocument(new com.itextpdf.kernel.pdf.PdfReader(inputStream));
			        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
			        List<String> names = signatureUtil.getSignatureNames();

			        for (String name : names) {
			            System.out.println("===== " + name + " =====");
			            
			            Results.put(name, verifySignature(signatureUtil, name));

			        }
			        pdfDocument.close();
			      }
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
