package org.sid.securityservice;

import org.sid.securityservice.Sec.Entities.AppRoles;
import org.sid.securityservice.Sec.Entities.AppUser;
import org.sid.securityservice.Sec.Service.Accountservice;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true , securedEnabled = true)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }


    @Bean
    CommandLineRunner commandLineRunner(Accountservice accountservice){
        return args -> {
            accountservice.addrole(new AppRoles(null,"USER"));
            accountservice.addrole(new AppRoles(null,"ADMIN"));
            accountservice.addrole(new AppRoles(null,"CUSTOMER_MANAGER"));
            accountservice.addrole(new AppRoles(null,"PRODUCT_MANAGER"));
            accountservice.addrole(new AppRoles(null,"BILLS_MANAGER"));

            accountservice.adduser(new AppUser(null,"user1","1111",new ArrayList<>()));
            accountservice.adduser(new AppUser(null,"user2","2222h",new ArrayList<>()));
            accountservice.adduser(new AppUser(null,"user3","3333h",new ArrayList<>()));
            accountservice.adduser(new AppUser(null,"user4","4444h",new ArrayList<>()));
            accountservice.adduser(new AppUser(null,"user5","5555h",new ArrayList<>()));

            accountservice.addroletouser("user1","USER");
            accountservice.addroletouser("user2","ADMIN");
            accountservice.addroletouser("user3","CUSTOMER_MANAGER");
            accountservice.addroletouser("user4","PRODUCT_MANAGER");
            accountservice.addroletouser("user5","BILLS_MANAGER");
        };
    }

}
