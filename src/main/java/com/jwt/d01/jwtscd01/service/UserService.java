package com.jwt.d01.jwtscd01.service;

import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

import com.jwt.d01.jwtscd01.models.User;

@Service
public class UserService {

    private List<User> store = new ArrayList<>();

    public UserService() {
        store.add(new User("U001", "Alice", "alice@example.com"));
        store.add(new User("U002", "Bob", "bob@example.com"));
        store.add(new User("U003", "Charlie", "charlie@example.com"));
        store.add(new User("U004", "Diana", "diana@example.com"));
        store.add(new User("U005", "Tanmoy", "tanmoy@example.com"));
    }

    public List<User> getAllUsers() {
        return this.store;
    }
}