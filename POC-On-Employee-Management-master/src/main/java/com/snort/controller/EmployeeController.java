package com.snort.controller;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import com.snort.entity.Employee;
import com.snort.service.EmployeeService;

@Controller
public class EmployeeController {

	@Autowired
	private EmployeeService employeeService;

	// display list of Employees
	@GetMapping("/")
	public String viewHomePage(Model model) {
		model.addAttribute("employeeList", employeeService.getAllEmployees());
		return "index";
	}

	@GetMapping("/showNewEmployeeForm")
	public String showNewEmployeeForm(Model model) {
		// create model attribute to bind form data
		Employee employee = new Employee();
		model.addAttribute("employee", employee);
		return "new_employee";
	}

	@PostMapping("/saveEmployee")
	public String saveEmployee(@ModelAttribute("employee") Employee employee) {
		// save employee to database
		System.out.println("Emp data : " + employee);
		employeeService.saveEmployee(employee);
		return "redirect:/";
	}

	@GetMapping("/showFormForUpdate/{id}")
	public String showFormForUpdate(@PathVariable(value = "id") long id, Model model) {

		// get employee from the service
		Employee employee = employeeService.getEmployeeById(id);

		// set employee as a model attribute to pre-populate the form
		model.addAttribute("employee", employee);
		return "update_employee";
	}

	@GetMapping("/deleteEmployee/{id}")
	public String deleteEmployee(@PathVariable(value = "id") long id) {
		// calling delete employee method
		this.employeeService.deleteEmployeeById(id);

		return "redirect:/";

	}

	@GetMapping("/search")
	public ModelAndView searchBy(HttpServletRequest request) {
		
		ModelAndView view = new ModelAndView("index.html");

		String optionName = request.getParameter("optionName").trim();
		String optionValue = request.getParameter("optionValue").trim();

		System.out.println("optionName : " + optionName);
		System.out.println("optionValue : " + optionValue);

		List<Employee> employeeList = new ArrayList<>();
		switch (optionName) {
		case "Firstname": {
//			calling database method findbyFirstname and store result into employee list
			employeeList = employeeService.findByFirstname(optionValue);
		}
			break;
		case "Email": {
			employeeList = employeeService.findByEmail(optionValue);
		}
			break;
		case "Phone": {
			employeeList = employeeService.findByPhone(optionValue);
		}
			break;
		default:

			break;
		}
		System.out.println("Total Employee["+employeeList.size()+"] found : "+employeeList);
		view.addObject("employeeList",employeeList);
		return view;
	}
}