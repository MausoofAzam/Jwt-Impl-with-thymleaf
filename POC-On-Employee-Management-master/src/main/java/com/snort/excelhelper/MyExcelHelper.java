package com.snort.excelhelper;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.multipart.MultipartFile;

import com.snort.entity.Answersheet;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MyExcelHelper {
	//check that if file is excel type or not.	
		public static boolean checkExcelFormat(MultipartFile file) {
			log.info("file checkExcelFormat is done");
			String contentType = file.getContentType();

			if (contentType.equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")) {
				return true;
			} else {
				return false;
			}
		}

		// converts excel to list of Answersheets.
		public static List<Answersheet> convertExcelToListOfAnswersheets(InputStream is) {
			log.info("convertExcelToListOfAnswersheets method is called..!");
			List<Answersheet> list = new ArrayList<>();
			try {
				XSSFWorkbook workbook = new XSSFWorkbook(is);
				XSSFSheet sheet = workbook.getSheet("data");
				int rowNumber = 0;
				Iterator<Row> iterator = sheet.iterator(); // check here

				while (iterator.hasNext()) {
					Row row = iterator.next();

					if (rowNumber == 0) {
						rowNumber++;
						continue;
					}

					Iterator<Cell> cells = row.iterator();
					int cid = 0;
					Answersheet a = new Answersheet();
					while (cells.hasNext()) {

						Cell cell = cells.next();
						switch (cid) {
						case 0:

							a.setQuestionId((int) cell.getNumericCellValue());
							break;
						case 1:
							a.setQuestion(cell.getStringCellValue());
							break;
						case 2:
							a.setOption1(cell.getStringCellValue());
							break;
						case 3:
							a.setOption2(cell.getStringCellValue());
							break;
						case 4:
							a.setOption3(cell.getStringCellValue());
							break;
						case 5:
							a.setOption4(cell.getStringCellValue());
							break;
						case 6:
							a.setAnswer(cell.getStringCellValue());
							break;
						default:
							break;
						}
						cid++;
					}
					list.add(a);
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
			return list;
		}
}
