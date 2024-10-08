package com.webauthn.app.authenticator;

import com.webauthn.app.user.AppUser;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Optional;

@Entity
@Getter
@NoArgsConstructor
public class Authenticator {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column
    private String name;

    @Column(nullable = false)
    private String credentialId;

    @Column(nullable = false)
    private String publicKey;

    @Column(nullable = false)
    private Long count;

    @Column(nullable = true)
    private String aaguid;

    @ManyToOne
    private AppUser user;

    public Authenticator(RegistrationResult result, AuthenticatorAttestationResponse response, AppUser user, String name) {
        Optional<AttestedCredentialData> attestationData = response.getAttestation().getAuthenticatorData().getAttestedCredentialData();
        this.credentialId = result.getKeyId().getId().getBase64();
        this.publicKey = result.getPublicKeyCose().getBase64();
        this.aaguid = attestationData.get().getAaguid().getBase64();
        this.count = result.getSignatureCount();
        this.name = name;
        this.user = user;
    }
}
