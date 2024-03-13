package com.example.demo.modele;

public class PdfResultRequest {

	  private byte[] pdfContent;

	    public PdfResultRequest() {
	    }

	    public PdfResultRequest(byte[] pdfContent) {
	        this.pdfContent = pdfContent;
	    }

	    public byte[] getPdfContent() {
	        return pdfContent;
	    }

	    public void setPdfContent(byte[] pdfContent) {
	        this.pdfContent = pdfContent;
	    }

}
