package com.izzat.loginregister.appuser;

import com.izzat.loginregister.registration.token.ConfirmationToken;
import com.izzat.loginregister.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG =  "user with email %s not found";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    private static final Logger LOGGER = LoggerFactory.getLogger(AppUserService.class);

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser) {
        Optional<AppUser> user = appUserRepository.findByEmail(appUser.getEmail());
        boolean userExists = user.isPresent();

        if (userExists) {
            AppUser user1 = user.get();
            if (Objects.equals(user1.getFirstName(), appUser.getFirstName()) &&
                Objects.equals(user1.getLastName(), appUser.getLastName()) &&
                        !user1.hasConfirmedToken()) {
                user1.setPassword(appUser.getPassword());
                saveAppUser(user1);
                return generateConfirmationToken(user1);

            } else {
                throw new IllegalStateException("email already taken");
            }

        }

        saveAppUser(appUser);

        return generateConfirmationToken(appUser);
    }

    private String generateConfirmationToken(AppUser appUser) {
        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );

        appUser.addConfirmationToken(confirmationToken);
        confirmationTokenService.saveConfirmationToken(
                confirmationToken);
        return token;
    }

    private void saveAppUser(AppUser appUser) {
        String encodedPassword = bCryptPasswordEncoder
                .encode(appUser.getPassword());

        appUser.setPassword(encodedPassword);

        appUserRepository.save(appUser);
    }

    public void enableAppUser(String email) {
        appUserRepository.enableAppUser(email);
    }
}
