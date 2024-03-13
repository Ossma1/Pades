package com.example.demo.modele;

public class PdfSigningRequest {
    private byte[] pdfContent;
    private byte[] certificateBytes;

    public PdfSigningRequest(byte[] pdfBytes, byte[] p12Bytes) {
    	this.pdfContent=pdfBytes;
    	this.certificateBytes=p12Bytes;
    }

	public byte[] getPdfContent() {
        return pdfContent;
    }

    public void setPdfContent(byte[] pdfContent) {
        this.pdfContent = pdfContent;
    }

    public byte[] getCertificateBytes() {
        return certificateBytes;
    }

    public void setCertificateBytes(byte[] certificateBytes) {
        this.certificateBytes = certificateBytes;
    }
}