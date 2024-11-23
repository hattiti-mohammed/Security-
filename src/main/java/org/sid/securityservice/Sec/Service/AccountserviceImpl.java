package org.sid.securityservice.Sec.Service;
import org.sid.securityservice.Sec.Entities.AppRoles;
import org.sid.securityservice.Sec.Entities.AppUser;
import org.sid.securityservice.Sec.Reposetories.AppRoleReposetorie;
import org.sid.securityservice.Sec.Reposetories.AppUserReposetorie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@Transactional

public class AccountserviceImpl implements Accountservice {
    @Autowired
    private AppRoleReposetorie appRoleReposetorie;
    @Autowired
    private AppUserReposetorie appUserReposetorie;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public AppUser adduser(AppUser appUser) {
        String pw=appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));

        return appUserReposetorie.save(appUser);
    }

    @Override
    public AppRoles addrole(AppRoles appRoles) {
        return appRoleReposetorie.save(appRoles);
    }

    @Override
    public void addroletouser(String username, String rolename) {
     AppUser appUser=appUserReposetorie.findByUsername(username);
     AppRoles appRoles=appRoleReposetorie.findByRolename(rolename);
     appUser.getAppRoles().add(appRoles);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserReposetorie.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserReposetorie.findAll();
    }
}
