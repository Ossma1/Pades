package com.example.demo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.boot.SpringApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import com.example.demo.modele.PdfSigningRequest;

public class testAddSign {

	public testAddSign() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) throws IOException {
		byte[] p12Bytes  = Files.readAllBytes(Paths.get(System.getProperty("user.dir")+"/Files/mon_keystore.p12"));

		byte[] pdfBytes = Files.readAllBytes(Paths.get(System.getProperty("user.dir")+"/Files/hello.pdf"));
		RestTemplate restTemplate = new RestTemplate();
		String url = "http://localhost:8081/signature/createPAdESSignature";

		PdfSigningRequest request = new PdfSigningRequest(pdfBytes, p12Bytes);

		// Envoi de la requête POST
		ResponseEntity<byte[]> response = restTemplate.postForEntity(url, request, byte[].class);

		// Traitement de la réponse
		if (response.getStatusCode() == HttpStatus.OK) {
		    byte[] signedPdfBytes = response.getBody();
		    // Faire quelque chose avec le PDF signé
		} else {
		    // Gérer les erreurs de la requête
		}
	}

}
