package com.snort;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.snort.entity.Employee;
import com.snort.repository.EmployeeRepository;

@SpringBootApplication
public class EmployeeInformationApplication implements CommandLineRunner {

	@Autowired
	EmployeeRepository employeeRepository;

	private static Logger log = LoggerFactory.getLogger(EmployeeInformationApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(EmployeeInformationApplication.class, args);

		log.info("EmployeeInformationApplication program has started..!");
	}

	@Override
	public void run(String... args) throws Exception {

//		List<Employee> list = new ArrayList<>();
//		list = employeeRepository.findByFirstname("Amitabh");
//		System.out.println("findByFirstname:" + list);
//
//		List<Employee> list1 = new ArrayList<>();
//		list1 = employeeRepository.findByEmail("Amitabh@gmail.com");
//		System.out.println("findByEmail:" + list1);
//
//		List<Employee> list2 = new ArrayList<>();
//		list2 = employeeRepository.findByPhone("67564657");
//		System.out.println("findByPhone:" + list2);

	}

}
