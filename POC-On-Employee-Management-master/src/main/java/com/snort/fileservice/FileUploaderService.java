package com.snort.fileservice;

import java.io.IOException;

import org.springframework.web.multipart.MultipartFile;

public interface FileUploaderService {


	String uploadFile(MultipartFile multipartFile) throws IOException;
	byte[] downloadingFile(String fileName) throws IOException;
}
