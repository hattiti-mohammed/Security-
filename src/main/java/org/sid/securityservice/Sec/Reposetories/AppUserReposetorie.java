package org.sid.securityservice.Sec.Reposetories;

import org.sid.securityservice.Sec.Entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserReposetorie extends JpaRepository<AppUser,Long> {
    AppUser findByUsername (String username);
}
