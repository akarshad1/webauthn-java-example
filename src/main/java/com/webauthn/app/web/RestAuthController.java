package com.webauthn.app.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn.app.authenticator.Authenticator;
import com.webauthn.app.dto.AppCache;
import com.webauthn.app.dto.FinishAuthRequest;
import com.webauthn.app.dto.RegistrationRequest;
import com.webauthn.app.service.RegistrationService;
import com.webauthn.app.user.AppUser;
import com.webauthn.app.utility.Utility;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.io.IOException;

@RestController
@RequestMapping("/api")

public class RestAuthController {

    private final RelyingParty relyingParty;
    private final RegistrationService registrationService;
    private final AppCache appCache;

    RestAuthController(RegistrationService registrationService, RelyingParty relyingPary, AppCache appCache) {
        this.relyingParty = relyingPary;
        this.registrationService = registrationService;
        this.appCache = appCache;
    }

    @GetMapping("/details")
    public String details() {
        JSONObject jsonResult = new JSONObject();
        jsonResult.put("success", true);
        return jsonResult.toString();
    }


    @PostMapping("/start-registration")
    public String startRegistration(@RequestBody RegistrationRequest registrationRequest) {
        AppUser existingUser = registrationService.findByUsername(registrationRequest.getUsername());
        if (existingUser == null) {
            UserIdentity userIdentity = UserIdentity.builder()
                    .name(registrationRequest.getUsername())
                    .displayName(registrationRequest.getDisplay())
                    .id(Utility.generateRandom(32))
                    .build();
            AppUser saveUser = new AppUser(userIdentity);
            saveUser = registrationService.saveUser(saveUser);
            System.out.println("New saved user id = " + saveUser.getId());
            String response = newRestAuthRegistration(saveUser);
            return response;
        } else {
            System.out.println("Username " + registrationRequest.getUsername() + " already exists. Choose a new name.");
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + registrationRequest.getUsername() + " already exists. Choose a new name.");
        }
    }
    public String newRestAuthRegistration(AppUser user) {
        AppUser existingUser = registrationService.findByHandle(user.getHandle());
        if (existingUser != null) {
            UserIdentity userIdentity = user.toUserIdentity();
            StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .build();
            PublicKeyCredentialCreationOptions registration = relyingParty.startRegistration(registrationOptions);
            appCache.getCache().put(userIdentity.getDisplayName(), registration);
            try {
                String sendingResponse = registration.toCredentialsCreateJson();
                System.out.println(sendingResponse);
                return sendingResponse;
            } catch (JsonProcessingException e) {
                e.printStackTrace();
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
            }
        } else {
            System.out.println("User " + user.getUsername() + " does not exist. Please register.");
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + user.getUsername() + " does not exist. Please register.");
        }
    }

    @PostMapping("/finish-registration")
    @ResponseBody
    public String finishRegistration(@RequestBody FinishAuthRequest finishAuthRequest) {

        ObjectMapper mapper = new ObjectMapper();

        try {
            System.out.println(mapper.writeValueAsString(finishAuthRequest));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        try {
            AppUser user = registrationService.findByUsername(finishAuthRequest.getUsername());
            PublicKeyCredentialCreationOptions requestOptions = (PublicKeyCredentialCreationOptions) appCache.getCache().get(user.getUsername());
            if (requestOptions != null) {
                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                        PublicKeyCredential.parseRegistrationResponseJson(finishAuthRequest.getCredential());
                FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                        .request(requestOptions)
                        .response(pkc)
                        .build();
                RegistrationResult result = relyingParty.finishRegistration(options);
                Authenticator savedAuth = new Authenticator(result, pkc.getResponse(), user, finishAuthRequest.getCredname());
                registrationService.saveUserAuth(savedAuth);
            } else {
                System.out.println("Cached request expired. Try to register again!");
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Cached request expired. Try to register again!");
            }
        } catch (RegistrationFailedException e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration failed.", e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to save credential, please try again!", e);
        }

        JSONObject jsonResult = new JSONObject();
        jsonResult.put("success", true);
        return jsonResult.toString();
    }
}
