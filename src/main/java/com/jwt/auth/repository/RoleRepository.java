package com.jwt.auth.repository;

import java.util.Optional;

import com.jwt.auth.model.Role;
import com.jwt.auth.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);
}