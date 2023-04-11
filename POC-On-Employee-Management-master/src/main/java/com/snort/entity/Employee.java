package com.snort.entity;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name = "Employees")
public class Employee {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	@Column(name = "first_name")
	private String firstname;
	@Column(name = "last_name")
	private String lastname;
	private String age;
	@Column(name = "Email")
	private String email;
	@Column(name = "emp_address")
	private String address;
	@Column(name = "emp_phone")
	private String phone;
	
	//img details
	@Lob
	@Column(length = 2000)
	private byte[] image;
	private String imageName;
	private String imageType;
	private Long imageSize;

//	public Employee() {
//		// TODO Auto-generated constructor stub
//	}

	

//	public Employee(Long id, String firstname, String lastname, String age, String email, String address, String phone,
//			byte[] image, String imageName, String imageType, Long imageSize) {
//		super();
//		this.id = id;
//		this.firstname = firstname;
//		this.lastname = lastname;
//		this.age = age;
//		this.email = email;
//		this.address = address;
//		this.phone = phone;
//		this.image = image;
//		this.imageName = imageName;
//		this.imageType = imageType;
//		this.imageSize = imageSize;
//	}
//
//
//
//	public Long getId() {
//		return id;
//	}
//
//	public void setId(Long id) {
//		this.id = id;
//	}
//
//	public String getFirstname() {
//		return firstname;
//	}
//
//	public void setFirstname(String firstname) {
//		this.firstname = firstname;
//	}
//
//	public String getLastname() {
//		return lastname;
//	}
//
//	public void setLastname(String lastname) {
//		this.lastname = lastname;
//	}
//
//	public String getAge() {
//		return age;
//	}
//
//	public void setAge(String age) {
//		this.age = age;
//	}
//
//	public String getEmail() {
//		return email;
//	}
//
//	public void setEmail(String email) {
//		this.email = email;
//	}
//
//	public String getAddress() {
//		return address;
//	}
//
//	public void setAddress(String address) {
//		this.address = address;
//	}
//
//	public String getPhone() {
//		return phone;
//	}
//
//	public void setPhone(String phone) {
//		this.phone = phone;
//	}
//
//	public byte[] getImage() {
//		return image;
//	}
//
//
//
//	public void setImage(byte[] image) {
//		this.image = image;
//	}
//
//
//
//	public String getImageName() {
//		return imageName;
//	}
//
//
//
//	public void setImageName(String imageName) {
//		this.imageName = imageName;
//	}
//
//
//
//	public String getImageType() {
//		return imageType;
//	}
//
//
//
//	public void setImageType(String imageType) {
//		this.imageType = imageType;
//	}
//
//
//
//	public Long getImageSize() {
//		return imageSize;
//	}
//
//
//
//	public void setImageSize(Long imageSize) {
//		this.imageSize = imageSize;
//	}
//
//
//
//	@Override
//	public String toString() {
//		return "Employee [id=" + id + ", firstname=" + firstname + ", lastname=" + lastname + ", age=" + age
//				+ ", email=" + email + ", address=" + address + ", phone=" + phone + ", image=" + Arrays.toString(image)
//				+ ", imageName=" + imageName + ", imageType=" + imageType + ", imageSize=" + imageSize + "]";
//	}

	
}
