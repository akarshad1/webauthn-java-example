package com.webauthn.app.service;

import java.util.Optional;
import java.util.Set;

import com.webauthn.app.authenticator.Authenticator;
import com.webauthn.app.authenticator.AuthenticatorRepository;
import com.webauthn.app.repo.RegistrationRepo;
import com.webauthn.app.user.AppUser;
import com.webauthn.app.user.UserRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RegistrationService {
    @Autowired
    private UserRepository userRepo;
    @Autowired
    private AuthenticatorRepository authRepository;

    @Autowired
    private RegistrationRepo registrationRepo;
    @Transactional
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return registrationRepo.getCredentialIdsForUsername(username);
    }

    @Transactional
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        AppUser user = userRepo.findByUsername(username);
        return Optional.of(ByteArray.fromBase64(user.getHandle()));
    }

    @Transactional
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        AppUser user = userRepo.findByHandle(userHandle.getBase64());
        return Optional.of(user.getUsername());
    }

    @Transactional
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return registrationRepo.lookup(credentialId, userHandle);
    }

    @Transactional
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return registrationRepo.lookupAll(credentialId);
    }

    @Transactional
    public AppUser findByUsername(String username) {
        return userRepo.findByUsername(username);
    }
    @Transactional
    public AppUser saveUser(AppUser user) {
        return userRepo.save(user);
    }

    @Transactional
    public AppUser findByHandle(String handle){
        return userRepo.findByHandle(handle);
    }

    @Transactional
    public void saveUserAuth(Authenticator authenticator) {
        authRepository.save(authenticator);
    }

}