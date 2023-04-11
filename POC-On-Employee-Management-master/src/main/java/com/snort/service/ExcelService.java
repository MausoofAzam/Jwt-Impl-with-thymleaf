package com.snort.service;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.snort.entity.Answersheet;
import com.snort.excelhelper.MyExcelHelper;
import com.snort.repository.ExcelRepositiory;

@Service
public class ExcelService {


	@Autowired
	private ExcelRepositiory repository;

	public void save(MultipartFile file) {
		try {
			List<Answersheet> answersheet = MyExcelHelper.convertExcelToListOfAnswersheets(file.getInputStream());
			this.repository.saveAll(answersheet);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public List<Answersheet> getAllAnswersheets() {

		return (List<Answersheet>) this.repository.findAll();
	}
}
