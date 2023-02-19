package com.example.security.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.security.config.JwtService;
import com.example.security.user.Role;
import com.example.security.user.User;
import com.example.security.user.UserRepository;

@Service
public class AuthenticationService {
	
	private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);

	private final UserRepository userRepository;
	
	private final PasswordEncoder passwordEncoder;
	
	private final JwtService jwtService;
	
	private final AuthenticationManager authenticationManager;
	
	public AuthenticationService(UserRepository userRepository,
			PasswordEncoder passwordEncoder,
			JwtService jwtService,
			AuthenticationManager authenticationManager) {
		
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authenticationManager = authenticationManager;
	}

	public AuthenticationResponse register(RegisterRequest registerRequest) {

		var user = new User();
		
		user.setFirstName(registerRequest.getFirstName());
		user.setLastName(registerRequest.getLastName());
		user.setEmail(registerRequest.getEmail());
		user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		user.setRole(Role.USER);
		
		userRepository.save(user);
		
		var jwtToken = jwtService.generateToken(user);
		
		var authenticationResponse = new AuthenticationResponse();
		authenticationResponse.setToken(jwtToken);
		
		return authenticationResponse;
	}
	
	public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
		
		LOG.info("authenticate user {}.", authenticationRequest.getEmail());
		
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword()));
		
		var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
		var jwtToken = jwtService.generateToken(user);
		
		var authenticationResponse = new AuthenticationResponse();
		authenticationResponse.setToken(jwtToken);
		
		return authenticationResponse;
	}
}
