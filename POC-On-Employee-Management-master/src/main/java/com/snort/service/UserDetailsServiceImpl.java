package com.snort.service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.snort.entity.Role;
import com.snort.entity.User;
import com.snort.repository.RolesRepository;
import com.snort.repository.UserRepository;
import com.snort.web.dto.UserRegistrationDto;
@Slf4j
@Service

public class UserDetailsServiceImpl implements UserService {

//	private static Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RolesRepository rolesRepository;

	@Override
	public User save(UserRegistrationDto registrationDto) throws RuntimeException {
		Set<String> strRoles = null;
		Set<Role> roles = new HashSet<>();
		User user = new User(registrationDto.getFirstName(), registrationDto.getLastName(), registrationDto.getEmail(),
				bCryptPasswordEncoder.encode(registrationDto.getPassword()));

		if (userRepository.existsByEmail(registrationDto.getEmail())) {
			throw new RuntimeException("Email already exists!");
		}

		if (strRoles == null) {
			Role userRole = rolesRepository.findByName("ROLE_USER")
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			log.info("singnup as ROLE_USER : ", userRole);
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = rolesRepository.findByName("ROLE_ADMIN")
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					log.info("case singnup as adminRole : ", adminRole);
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = rolesRepository.findByName("ROLE_SUPERADMIN")
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					log.info("case singnup as superadmin role : ", modRole.toString());
					roles.add(modRole);

					break;
				default:
					Role userRole = rolesRepository.findByName("ROLE_USER")
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					log.info("case singnup as user Role : ", userRole);
					roles.add(userRole);
				}
			});
		}
		user.setRoles(roles);
		return userRepository.save(user);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(username);
		log.info(" in UserDetailsServiceImpl : loadUserByUsername() : ", user);

		if (user == null) {
			throw new UsernameNotFoundException("Invalid username or password.");
		}
		return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(),

		mapRolesToAuthorities(user.getRoles()));
	}

	private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
		log.info(" in UserDetailsServiceImpl : loadUserByUsername() : ", roles);

		return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
	}

}
