package com.snort.request;

public class EmployeeSearchRequest {
	private String optionName;
	private String optionValue;

	
	public EmployeeSearchRequest() {
		// TODO Auto-generated constructor stub
	}


	public EmployeeSearchRequest(String optionName, String optionValue) {
		super();
		this.optionName = optionName;
		this.optionValue = optionValue;
	}


	public String getOptionName() {
		return optionName;
	}


	public void setOptionName(String optionName) {
		this.optionName = optionName;
	}


	public String getOptionValue() {
		return optionValue;
	}


	public void setOptionValue(String optionValue) {
		this.optionValue = optionValue;
	}


	@Override
	public String toString() {
		return "EmployeeSearchRequest [optionName=" + optionName + ", optionValue=" + optionValue + "]";
	}
	
	
}
