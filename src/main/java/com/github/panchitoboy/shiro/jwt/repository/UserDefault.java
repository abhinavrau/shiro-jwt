package com.github.panchitoboy.shiro.jwt.repository;

import org.apache.shiro.authc.HostAuthenticationToken;

import java.util.HashSet;
import java.util.Set;

public interface UserDefault extends HostAuthenticationToken {

    default Set<String> getRoles() {
        Set<String> roles = new HashSet<>();
        roles.add("default");
        return roles;
    }
}
