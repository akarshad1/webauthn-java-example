package com.webauthn.app.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Getter
public class AppCache {
    private final Map<String, Object> cache = new HashMap<>();
}
