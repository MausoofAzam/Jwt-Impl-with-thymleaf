package com.snort.service;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.snort.entity.Employee;
import com.snort.repository.EmployeeRepository;

@Service
public class EmployeeServiceImpl implements EmployeeService {

	private static Logger log = LoggerFactory.getLogger(EmployeeServiceImpl.class);

	@Autowired
	private EmployeeRepository employeeRepository;

	@Override
	public List<Employee> getAllEmployees() {

		log.info("EmployeeService : findAll() Executed");
		return employeeRepository.findAll();
	}

	@Override
	public void saveEmployee(Employee employee) {
		log.info("EmployeeService: save() executed");
		this.employeeRepository.save(employee);
	}

	@Override
	public Employee getEmployeeById(Long id) {
		log.info("EmployeeService : getEmployeeById() has executed");
		Optional<Employee> optional = employeeRepository.findById(id);
		Employee employee = null;

		if (optional.isPresent()) {
			employee = optional.get();
		} else {
			throw new RuntimeException("Employee not found for id::" + id);
		}
		return employee;
	}

	@Override
	public void deleteEmployeeById(long id) {
		log.info("EmployeeService : deleteEmployeeById() has executed..!");
		this.employeeRepository.deleteById(id);
	}

	@Override
	public List<Employee> findByFirstname(String firstname) {
		return employeeRepository.findByFirstname(firstname);
	}

	@Override
	public List<Employee> findByEmail(String Email) {
		// TODO Auto-generated method stub
		return employeeRepository.findByEmail(Email);
	}

	@Override
	public List<Employee> findByPhone(String phone) {
		// TODO Auto-generated method stub
		return employeeRepository.findByPhone(phone);
	}

}
