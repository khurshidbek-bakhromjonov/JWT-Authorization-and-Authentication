package com.security.web.rest.vm;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginVM {

    private String username;
    private String password;
    private boolean rememberMe;
}
