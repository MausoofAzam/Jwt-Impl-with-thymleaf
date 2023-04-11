package com.snort.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.snort.entity.User;
import com.snort.web.dto.UserRegistrationDto;

public interface UserService extends UserDetailsService {

	User save(UserRegistrationDto  userRegistrationDto);
	
}
