package com.webauthn.app.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FinishAuthRequest {

    private String credential;
    private String username;
    private String credname;

}
