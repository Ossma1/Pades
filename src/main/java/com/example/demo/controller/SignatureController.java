package com.example.demo.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.example.demo.modele.PdfResultRequest;
import com.example.demo.modele.PdfSigningRequest;
import com.example.demo.services.AddSegnature;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
@RestController
@RequestMapping("/signature")
public class SignatureController {

	 @Autowired
	 private AddSegnature serviceAddSignature;

	@PostMapping("/createPAdESSignature")
    public ResponseEntity<byte[]> createPAdESSignature(@RequestBody PdfSigningRequest request) throws Exception {
    	try {
            byte[] signedPdf = serviceAddSignature.AddSignatureUsingAppearanceInstanceExample(request.getPdfContent(), request.getCertificateBytes());    
            return ResponseEntity.ok()
                    .body(signedPdf);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    	}
   
    
    @GetMapping("/verifiedAddSignature")
    public byte[] verifiedAddSignature() throws IOException  {
    	byte[] p12Bytes  = Files.readAllBytes(Paths.get(System.getProperty("user.dir")+"/Files/mon_keystore.p12"));

		byte[] pdfBytes = Files.readAllBytes(Paths.get(System.getProperty("user.dir")+"/Files/hello.pdf"));
		RestTemplate restTemplate = new RestTemplate();
		String url = "http://localhost:8081/signature/createPAdESSignature";

		PdfSigningRequest request = new PdfSigningRequest(pdfBytes, p12Bytes);

		// Envoi de la requête POST
		ResponseEntity<byte[]> response = restTemplate.postForEntity(url, request, byte[].class);

		// Traitement de la réponse
		    byte[] signedPdfBytes = response.getBody();
		    try (ByteArrayInputStream inputStream = new ByteArrayInputStream(signedPdfBytes)) {
		        PdfDocument pdfDocument = new PdfDocument(new PdfReader(inputStream),new PdfWriter(System.getProperty("user.dir") + "/Files/hello1.pdf"));
		        pdfDocument.close();
		    } catch (IOException e) {
		        e.printStackTrace();
		    }
		    return signedPdfBytes;
		   
		
    }
   
}
