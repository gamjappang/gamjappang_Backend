package demago.gamjappang.controller;

import demago.gamjappang.config.auth.PrincipalDetails;
import demago.gamjappang.model.User;
import demago.gamjappang.rapository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private UserRepository userRepository;

    @Autowired
    public UserController(UserRepository userRepository){
        this.userRepository = userRepository;
    }

//    @GetMapping("/user/me")
//    @PreAuthorize("isAuthenticated()")
//    public User getUserAuthentication(){
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//    }
}
