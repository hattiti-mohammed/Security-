package org.sid.securityservice.Sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.securityservice.Sec.Entities.AppRoles;
import org.sid.securityservice.Sec.Entities.AppUser;
import org.sid.securityservice.Sec.Service.Accountservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Controller {
    @Autowired
    private Accountservice accountservice;

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public List<AppUser> appUsers(){

        return accountservice.listUsers();
    }
    @PostMapping(path = "/user")
    @PostAuthorize("hasAuthority('USER')")

    public AppUser adduser(@RequestBody AppUser appUser){
        return accountservice.adduser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRoles addroles(@RequestBody AppRoles appRoles){
        return accountservice.addrole(appRoles);
    }

    @PostMapping(path = "/addRoleToUSer")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUSer( @RequestBody UserForm userForm){
        accountservice.addroletouser(userForm.getUsername(),userForm.getRolename());
    }

    @GetMapping("/user/{username}")
    public AppUser appUser (@PathVariable(name = "username") String username){
       return accountservice.loadUserByUsername(username);
    }

    @GetMapping("/refreshtoken")
    public void refrechToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String auhToken=request.getHeader("authorization");
        if(auhToken!=null && auhToken.startsWith("Bearer ")){
            try {
                String jwt=auhToken.substring(7);
                Algorithm algorithm=Algorithm.HMAC256("mysecret1234");
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT=jwtVerifier.verify(jwt);
                String username=decodedJWT.getSubject();
                AppUser appUser=accountservice.loadUserByUsername(username);
                String jwtaccessToken=JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+3*60*120))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRolename()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String>idToken=new HashMap<>();
                idToken.put("acces-token",jwtaccessToken);
                idToken.put("refresh-token",jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);


            }
            catch (Exception e){
              throw e;
                
            }

        }
        else {
            throw new RuntimeException("refresh token required!");
        }
    }


}
@Data
 class UserForm{
    private String username;
    private String rolename;
}
