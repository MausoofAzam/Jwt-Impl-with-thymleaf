package com.snort.controller;

import com.snort.entity.JwtAuthRequest;
import com.snort.entity.User;
import com.snort.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
@Slf4j
@Controller
public class MainController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;
//	@Autowired
//	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtils jwtUtil;


	/*@GetMapping("/login")
	public String login() {
		return "login";
	}*/

	@GetMapping(value = { "/", "/login" })
	public ModelAndView login(@RequestParam(value = "error", required = false) String error,
							  @RequestParam(value = "logout", required = false) String logout) {

		ModelAndView model = new ModelAndView();
		if (error != null) {
			model.addObject("error", "Invalid email and password.");
		}
		if (logout != null) {
			model.addObject("msg", "You have been logged out.");
		}
		model.setViewName("login");
		return model;
	}

	@PostMapping(value = "/authenticate")
	public String createAuthenticationToken(@ModelAttribute("user") User user, BindingResult bindingResult,
											HttpServletResponse response) throws Exception {

		if (bindingResult.hasErrors()) {
			return "login";
		}

		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));
		} catch (UsernameNotFoundException e) {
			return "redirect:/login?error";
		}
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(user.getEmail());
		String jwt = jwtUtil.generateToken(userDetails);

		Cookie cookie = new Cookie("jwt", jwt);
		cookie.setMaxAge(60 * 60 * 24);
		cookie.setHttpOnly(true);
		response.addCookie(cookie);
		log.info("@PostMapping in createAuthenticationToken method Called in Main Controller");

		return "redirect:/welcome";
	}
	@GetMapping(value = "welcome")
	public ModelAndView welcome(HttpServletRequest request) throws Exception {
		log.info("@GetMapping(value index) method Called in Main Controller");

		Cookie[] cookies = request.getCookies();
		String jwt = null;
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals("jwt")) {
				jwt = cookie.getValue();
				break;
			}
		}
		if (jwt == null) {
			return new ModelAndView("redirect:/login");
		}

		String email = jwtUtil.extractUsername(jwt);
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);

		if (jwtUtil.validateToken(jwt, userDetails)) {
			ModelAndView model = new ModelAndView();
			model.addObject("email", email);
			model.setViewName("index");
			return model;
		} else {
			return new ModelAndView("redirect:/login");
		}
	}
}
