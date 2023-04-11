package com.snort.controller;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import com.snort.entity.Answersheet;
import com.snort.entity.Form;
import com.snort.excelhelper.MyExcelHelper;
import com.snort.service.ExcelService;

import lombok.extern.slf4j.Slf4j;
@Slf4j
@Controller
//@RestController
@CrossOrigin("*")
public class ExcelController {

	@Autowired
	private ExcelService excelService;
	private int size=0;
	
	@GetMapping("/register")
	public String showForm(Model model) {
		Form form = new Form();
		model.addAttribute("form", form);
		log.info("ExcelController :public String showForm(Model model) method ");
		List<String> practice = Arrays.asList("JAVA", ".NET", "TESTING");
		model.addAttribute("practice", practice);
		
		List<String> level =Arrays.asList("Beginner","Intermediate","Advanced");
		model.addAttribute("level",level);
		
		return "register_form";
	}
	@PostMapping("/register")
	public ModelAndView submitForm(@ModelAttribute("form") Form form, @RequestParam("file") MultipartFile file) {
		ModelAndView view = new  ModelAndView();
		if (MyExcelHelper.checkExcelFormat(file)) {
			// true
			System.out.println("File upload....");
			this.excelService.save(file);
		}
		List<Answersheet> answer = this.excelService.getAllAnswersheets();
		System.out.println("Total answers ::  "+answer.size());
		view.addObject("answer",answer);
		view.setViewName("register_success");
		return view;
	}

	@PostMapping("/sheet/upload")
	public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
		if (MyExcelHelper.checkExcelFormat(file)) {
			// true
			this.excelService.save(file);
			return ResponseEntity.ok(Map.of("message", "File is uploaded and data is saved to db"));

		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Please upload excel file ");
	}
	@GetMapping("/excel")
	public List<Answersheet> getAllSheet() {
		return this.excelService.getAllAnswersheets();
	}
}
