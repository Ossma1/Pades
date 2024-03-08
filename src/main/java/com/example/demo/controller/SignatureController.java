package com.example.demo.controller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.services.AddSegnature;

@RestController
@RequestMapping("/signature")
public class SignatureController {

	 @Autowired
	 private AddSegnature serviceAddSignature;

    @GetMapping("/createPAdESSignature")
    public String createPAdESSignature() throws Exception {
    	return serviceAddSignature.AddSignatureUsingAppearanceInstanceExample();    
    	}
    @GetMapping("/verifiedSignature")
    public Map<String, Boolean> verifiedSignature() throws GeneralSecurityException, IOException {
    	return serviceAddSignature.verifiedSignature();
    }
}
