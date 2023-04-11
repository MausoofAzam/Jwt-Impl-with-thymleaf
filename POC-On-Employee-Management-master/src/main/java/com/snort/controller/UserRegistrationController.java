package com.snort.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.snort.service.UserService;
import com.snort.web.dto.UserRegistrationDto;

@Controller
@RequestMapping("/registration")
public class UserRegistrationController {

	private UserService userService;

	public UserRegistrationController(UserService userService) {
		super();
		this.userService = userService;
	}
	
	@ModelAttribute("user")
    public UserRegistrationDto userRegistrationDto() {
        return new UserRegistrationDto();
    }
	
	@GetMapping
	public String showRegistrationForm() {
		return "registration";
	}
	
	@PostMapping 
	public String registerUserAccount(@ModelAttribute("user") UserRegistrationDto registrationDto, Model model) {
		String error = "";
		try {
			userService.save(registrationDto);
			return "redirect:/registration?success";
		} catch (Exception e) {
			error = "Email already exists!";
			System.out.println(error);
			model.addAttribute("error",error);
			return "redirect:/registration?error";
		}
		
	}
}
