package org.sid.securityservice.Sec.Service;

import org.sid.securityservice.Sec.Entities.AppRoles;
import org.sid.securityservice.Sec.Entities.AppUser;

import java.util.List;

public interface Accountservice {
    AppUser adduser(AppUser appUser);
    AppRoles addrole(AppRoles appRoles);
    void addroletouser(String username , String rolename);
    AppUser loadUserByUsername(String username);
    List<AppUser>listUsers();
}
