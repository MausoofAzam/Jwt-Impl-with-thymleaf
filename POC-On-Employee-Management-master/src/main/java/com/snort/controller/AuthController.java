//package com.snort.controller;
//
//import com.snort.config.JwtAuthResponse;
//import com.snort.entity.JwtAuthRequest;
//import com.snort.service.UserDetailsServiceImpl;
//import com.snort.utils.JwtUtils;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
////@RequestMapping("/api/v1/auth")
//public class AuthController {
//    @Autowired
//    private JwtUtils jwtUtil;
//
//    @Autowired
//    private AuthenticationManager authenticationManager;
//    @Autowired
//    private UserDetailsServiceImpl userDetailsService;
//
//    @RequestMapping({"/hello"})
//    public String hello(){
//
//        return "Hello World";
//    }
//
//    /*@PostMapping("/authenticate")
//    public String generateToken(@RequestBody AuthRequest authRequest) throws Exception {
//        try {
//            authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword())
//            );
//        } catch (Exception e) {
//            throw new Exception("invalid username/password");
//        }
//        return jwtUtil.generateToken(authRequest.getEmail());
//    }*/
/*@PostMapping("/authenticate")
    public ResponseEntity<JwtAuthResponse> createToken(@RequestBody JwtAuthRequest request){
        this.authenticate(request.getEmail(),request.getPassword());
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(request.getEmail());
        String token=this.jwtUtil.generateToken((userDetails));
        JwtAuthResponse response =new JwtAuthResponse();
        response.setToken(token);
       return new ResponseEntity<>(response,HttpStatus.OK);
    }
    private void authenticate(String username,String password){
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
            this.authenticationManager.authenticate(authenticationToken);

    }*/
//}
