package org.sid.securityservice.Sec.Reposetories;

import org.sid.securityservice.Sec.Entities.AppRoles;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleReposetorie extends JpaRepository<AppRoles,Long> {
    AppRoles findByRolename(String rolename);
}
