package com.snort.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.snort.entity.Role;

@Repository
public interface RolesRepository extends JpaRepository<Role, Integer> {
	Optional<Role> findByName(String name);
}
