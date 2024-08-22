package com.webauthn.app.authenticator;

import com.webauthn.app.user.AppUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthenticatorRepository extends CrudRepository<Authenticator, Long> {
    Optional<Authenticator> findByCredentialId(String credentialId);

    List<Authenticator> findAllByUser(AppUser user);

    List<Authenticator> findAllByCredentialId(String credentialId);
}
