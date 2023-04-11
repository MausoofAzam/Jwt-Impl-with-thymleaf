package com.snort.fileservice;

import java.util.Base64;

public class FileUploaderServiceImpl {
	public static String convertImageString(byte[] image) {
		String base64EncodedImage = Base64.getEncoder().encodeToString(image);
		return base64EncodedImage;
	}
}
