package com.jwt.auth.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.Authorization;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Api(value = "Swagger2DemoRestController", description = "REST APIs related to JWT Test Services")
@RestController
@RequestMapping("/api/test")
public class TestRestAPIs {

	@ApiOperation(value = "Get User Or Admin Access API", response = String.class, tags = "Test",
			authorizations = { @Authorization(value="jwtToken") })
	@GetMapping("/user")
	@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
	public String userAccess() {
		return ">>> User Contents!";
	}

	@ApiOperation(value = "Get PM Or Admin Access API", response = String.class, tags = "Test",
			authorizations = { @Authorization(value="jwtToken") })
	@GetMapping("/pm")
	@PreAuthorize("hasRole('PM') or hasRole('ADMIN')")
	public String projectManagementAccess() {
		return ">>> Board Management Project";
	}

	@ApiOperation(value = "Get Admin Access API", response = String.class, tags = "Test",
			authorizations = { @Authorization(value="jwtToken") })
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return ">>> Admin Contents";
	}
}