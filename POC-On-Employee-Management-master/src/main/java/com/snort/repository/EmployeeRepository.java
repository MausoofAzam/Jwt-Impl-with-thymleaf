package com.snort.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.snort.entity.Employee;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {

	List<Employee> findByFirstname(String firstname);

	List<Employee> findByEmail(String Email);

	List<Employee> findByPhone(String phone);
}
