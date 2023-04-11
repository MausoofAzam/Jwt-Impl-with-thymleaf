package com.snort.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.snort.entity.Answersheet;

@Repository
public interface ExcelRepositiory extends CrudRepository<Answersheet, Integer>{

}
