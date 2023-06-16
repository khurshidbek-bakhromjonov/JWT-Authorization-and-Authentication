package com.security.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
//import lombok.Getter;
//import lombok.Setter;

import java.io.Serializable;

//@Getter
//@Setter
@Entity
@Table(name = "authorities")
public class Authority implements Serializable {

    @Id
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
